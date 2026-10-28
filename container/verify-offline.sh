#!/usr/bin/env bash
# Run against a disposable, network-isolated Linux node. No registry access occurs.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/offline-helpers.sh"
engine=${ENGINE:-docker}
image=${1:?core image}
bundles=${2:?bundle directory}
version=${3:?release version}
arch=${4:?bundle architecture}
ctl=${5:?native dioramactl}
kubectl=${6:?Linux kubectl executable}
mode=${7:-container}
host="$bundles/diorama-$version-linux-$arch-host-offline.tar.gz"
name="diorama-offline-test-$$"
volume="$name-data"
work=$(mktemp -d)
k() { "$engine" exec -i "$name" /tmp/kubectl --kubeconfig /var/lib/diorama/pki/admin.kubeconfig "$@"; }
cleanup() {
  result=$?
  if [ "$result" -ne 0 ]; then
    "$engine" logs --tail=100 "$name" || true
    k get pods -A || true
    for addon in d2k portainer-agent; do
      ns=d2k; [ "$addon" != portainer-agent ] || ns=portainer
      k -n "$ns" logs "diorama-install-$addon-0" || true
    done
  fi
  "$engine" rm -f "$name" >/dev/null 2>&1 || true
  "$engine" volume rm "$volume" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$result"
}
trap cleanup EXIT
until_ok() {
  for _ in $(seq 1 120); do
    if "$@"; then return 0; fi
    if [ "$("$engine" inspect --format '{{.State.Running}}' "$name")" != true ]; then return 1; fi
    sleep 2
  done
  return 1
}
"$engine" volume create "$volume" >/dev/null
startup='printf "nameserver 192.0.2.1\n" > /etc/resolv.conf; exec diorama-entrypoint --container-mode --node-ip=127.0.0.1'
if [ "$mode" = host ]; then
  startup='set -e; printf "nameserver 192.0.2.1\n" > /etc/resolv.conf; dioramactl install --offline-install="$1" --path=/var/lib/diorama; exec /var/lib/diorama/bin/diorama --path=/var/lib/diorama --container-mode --node-ip=127.0.0.1'
fi
"$engine" create --pull=never --name "$name" --hostname diorama-node \
  --privileged --network=none --tmpfs /tmp:exec --tmpfs /run --entrypoint /bin/sh \
  -v "$volume:/var/lib/diorama" "$image" -c "$startup" node-bootstrap "/$(basename "$host")" >/dev/null
if [ "$mode" = host ]; then "$engine" cp "$host" "$name:/$(basename "$host")"; fi
"$engine" start "$name" >/dev/null
copy_into_node "$kubectl" /tmp/kubectl 0755
until_ok k get nodes
k -n local-path-storage wait --for=condition=available deployment/local-path-provisioner --timeout=180s

# Host extraction and direct socket loading use the Linux CLI carried by the core image.
host="$bundles/diorama-$version-linux-$arch-host-offline.tar.gz"
copy_into_node "$host" "/tmp/$(basename "$host")"
"$engine" exec "$name" dioramactl install --offline-install="/tmp/$(basename "$host")" --path=/tmp/host-node
"$engine" exec "$name" test -x /tmp/host-node/bin/ctr
"$engine" exec "$name" test ! -e /tmp/host-node/payloads
"$engine" exec "$name" test ! -e /tmp/host-node/images/diorama.tar.gz

for addon in d2k portainer-agent; do
  archive="$bundles/diorama-$version-linux-$arch-addon-$addon-offline.tar.gz"
  mkdir "$work/$addon"
  extract_install_job "$archive" "$work/$addon"
  sed 's/replace-with-loaded-node/diorama-node/g' "$work/$addon/install-job.json" > "$work/$addon/job.json"
  copy_into_node "$work/$addon/job.json" "/tmp/$addon-job.json"
done

# The Job cannot pull its absent image, even with valid API bootstrap resources.
k apply -f /tmp/d2k-job.json
missing_image() {
  k -n d2k get pod diorama-install-d2k-0 -o json | jq -e \
    '.status.containerStatuses[]?.state.waiting.reason == "ErrImageNeverPull"' >/dev/null
}
until_ok missing_image
k -n d2k delete job diorama-install-d2k --wait=true

for addon in d2k portainer-agent; do
  archive="$bundles/diorama-$version-linux-$arch-addon-$addon-offline.tar.gz"
  "$ctl" addon load "$archive" --container="$name" --engine="$engine"
done
# Exercise the host runtime-socket adapter too, without a registry.
d2k_pack="$bundles/diorama-$version-linux-$arch-addon-d2k-offline.tar.gz"
copy_into_node "$d2k_pack" "/tmp/$(basename "$d2k_pack")"
"$engine" exec "$name" dioramactl addon load "/tmp/$(basename "$d2k_pack")" --path=/var/lib/diorama

# Missing credentials must fail with useful diagnostics before creating workloads.
for addon in d2k portainer-agent; do
  ns=d2k; [ "$addon" != portainer-agent ] || ns=portainer
  k apply -f "/tmp/$addon-job.json"
  k -n "$ns" wait --for=condition=failed "job/diorama-install-$addon" --timeout=90s
  k -n "$ns" logs "diorama-install-$addon-0" | grep 'create Secret'
  test -z "$(k -n "$ns" get deployments -o name)"
  k -n "$ns" delete job "diorama-install-$addon" --wait=true
done

k -n d2k create secret generic d2k-tls \
  --from-file=ca.crt=/var/lib/diorama/pki/ca.crt \
  --from-file=tls.crt=/var/lib/diorama/pki/d2k-server.crt \
  --from-file=tls.key=/var/lib/diorama/pki/d2k-server.key

# A local polling fixture lets the real Portainer health executable succeed offline.
k apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: portainer-fixture
  labels: {app: portainer-fixture}
spec:
  nodeName: diorama-node
  containers:
    - name: server
      image: docker.io/library/busybox:latest
      imagePullPolicy: Never
      command: [sh, -c, 'mkdir -p /www/api/endpoints/1/edge; echo "{\"Status\":\"IDLE\",\"CheckinInterval\":5}" > /www/api/endpoints/1/edge/status; exec httpd -f -p 8080 -h /www']
---
apiVersion: v1
kind: Service
metadata:
  name: portainer-fixture
spec:
  selector: {app: portainer-fixture}
  ports: [{port: 8080, targetPort: 8080}]
EOF
k wait --for=condition=ready pod/portainer-fixture --timeout=90s
fixture_ip=$(k get service portainer-fixture -o jsonpath='{.spec.clusterIP}')
fixture_key=$(printf 'http://%s:8080|%s:8080|fixture|1' "$fixture_ip" "$fixture_ip" | base64 | tr -d '\n=')
k -n portainer create secret generic portainer-agent-edge-key \
  --from-literal=edge.id=offline-test --from-literal="edge.key=$fixture_key"

for addon in d2k portainer-agent; do
  ns=d2k; [ "$addon" != portainer-agent ] || ns=portainer
  before=$(k -n "$ns" get secrets -o json | jq -c '[.items[] | {name:.metadata.name,data}]')
  k -n "$ns" create configmap unrelated --from-literal=keep=yes
  for run in install repeat upgrade; do
    if [ "$run" != install ]; then
      k -n "$ns" delete job "diorama-install-$addon" --wait=true
    fi
    if [ "$run" = upgrade ]; then
      # Exercise replacement with a distinct release tag over the tested image bytes.
      old="ghcr.io/geoffsee/diorama-addon-$addon:$version"
      "$engine" exec "$name" ctr --address /var/lib/diorama/containerd/state/containerd.sock \
        --namespace k8s.io images tag "$old" "$old-upgrade"
      "$engine" exec "$name" ctr --address /var/lib/diorama/containerd/state/containerd.sock \
        --namespace k8s.io images export "/var/lib/diorama/images/addons/$addon-upgrade.tar" "$old-upgrade"
      "$engine" exec "$name" gzip -f "/var/lib/diorama/images/addons/$addon-upgrade.tar"
      sed "s|$old|$old-upgrade|g" "$work/$addon/job.json" > "$work/$addon/upgrade.json"
      copy_into_node "$work/$addon/upgrade.json" "/tmp/$addon-job.json"
    fi
    k apply -f "/tmp/$addon-job.json"
    k -n "$ns" wait --for=condition=complete "job/diorama-install-$addon" --timeout=360s
    test "$(k -n "$ns" get configmap unrelated -o jsonpath='{.data.keep}')" = yes
    after=$(k -n "$ns" get secrets -o json | jq -c '[.items[] | {name:.metadata.name,data}]')
    test "$before" = "$after"
  done
done

# Provision with Delete, while preserving the product's default Retain policy.
k get storageclass local-path -o json | jq \
  '.metadata={name:"offline-delete"} | .reclaimPolicy="Delete"' | k apply -f -
k apply -f - <<'EOF'
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: offline-storage
spec:
  storageClassName: offline-delete
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 16Mi
---
apiVersion: v1
kind: Pod
metadata:
  name: offline-writer
spec:
  nodeName: diorama-node
  containers:
    - name: writer
      image: docker.io/library/busybox:latest
      imagePullPolicy: Never
      command: [sh, -c, 'echo persists > /data/proof; sleep 3600']
      volumeMounts:
        - {name: data, mountPath: /data}
  volumes:
    - name: data
      persistentVolumeClaim: {claimName: offline-storage}
EOF
k wait --for=condition=ready pod/offline-writer --timeout=180s
test "$(k exec offline-writer -- cat /data/proof)" = persists
pv=$(k get pvc offline-storage -o jsonpath='{.spec.volumeName}')
path=$(k get pv "$pv" -o jsonpath='{.spec.local.path}')
test -n "$path"
k get pod offline-writer -o json | jq \
  '.metadata={name:"offline-reader"} | del(.status) | .spec.containers[0].command=["sh","-c","test $(cat /data/proof) = persists; sleep 3600"]' > "$work/reader.json"
k delete pod offline-writer --wait=true
k apply -f - < "$work/reader.json"
k wait --for=condition=ready pod/offline-reader --timeout=90s
"$engine" restart "$name"
copy_into_node "$kubectl" /tmp/kubectl 0755
until_ok k get nodes
until_ok k exec offline-reader -- cat /data/proof
for addon in d2k portainer-agent; do
  ns=d2k; [ "$addon" != portainer-agent ] || ns=portainer
  k -n "$ns" wait --for=condition=available "deployment/$addon" --timeout=180s
done
k delete pod offline-reader --wait=true
k delete pvc offline-storage --wait=true
k wait --for=delete "pv/$pv" --timeout=180s
"$engine" exec "$name" test ! -e "$path"
printf 'Offline add-ons and persistent storage passed for %s (%s)\n' "$arch" "$mode"
