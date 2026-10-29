#!/bin/sh
# Run against a disposable managed Linux node with its state and pod logs shared.
# Requires curl, jq, crictl. Set ARTIFACTS to retain manifests and observations.
set -eu
for tool in curl jq crictl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Required tool not found: $tool" >&2; exit 1; }
done
state=${DIORAMA_STATE:-/var/lib/diorama}
api=${DIORAMA_API:-https://127.0.0.1:6443}
name=oci-storage-$$
work=${ARTIFACTS:-$(mktemp -d)}
mkdir -p "$work"
request() {
    curl --connect-timeout 5 --max-time 15 -fsS --cacert "$state/pki/ca.crt" \
        --cert "$state/pki/admin.crt" --key "$state/pki/admin.key" \
        -H 'Content-Type: application/json' "$@"
}
cri() { crictl --runtime-endpoint "unix://$state/oci-cri/cri.sock" "$@"; }
pods="$api/api/v1/namespaces/default/pods"
claims="$api/api/v1/namespaces/default/persistentvolumeclaims"
classes="$api/apis/storage.k8s.io/v1/storageclasses"
cleanup() {
    for pod in "$name-writer" "$name-reader"; do
        request -X DELETE -d '{"gracePeriodSeconds":0}' "$pods/$pod" >/dev/null 2>&1 || true
    done
    request -X DELETE "$claims/$name" >/dev/null 2>&1 || true
    request -X DELETE "$classes/$name" >/dev/null 2>&1 || true
    if [ -z "${ARTIFACTS:-}" ]; then rm -rf "$work"; fi
}
trap cleanup EXIT
until_ok() {
    for attempt in $(seq 1 120); do
        if "$@"; then return 0; fi
        sleep 1
    done
    echo "Timed out: $* (evidence: $work)" >&2
    return 1
}
provisioner_ready() {
    request "$api/api/v1/namespaces/local-path-storage/pods" > "$work/provisioner.json" || return 1
    jq -e 'any(.items[]; .metadata.labels.app == "local-path-provisioner" and
        .status.phase == "Running" and .status.containerStatuses[0].ready)' "$work/provisioner.json" >/dev/null
}
pod_ready() {
    request "$pods/$1" > "$work/$1.json" || return 1
    jq -e '.status.phase == "Running" and .status.containerStatuses[0].ready' "$work/$1.json" >/dev/null
}
gone() {
    # Require a real 404: loss of API connectivity must not count as deletion.
    code=$(curl --connect-timeout 5 --max-time 15 -sS -o "$work/deletion-response.json" -w '%{http_code}' \
        --cacert "$state/pki/ca.crt" --cert "$state/pki/admin.crt" \
        --key "$state/pki/admin.key" "$1") || return 1
    [ "$code" = 404 ]
}
until_ok provisioner_ready
echo 'Storage provisioner is Running and Ready'
node=$(request "$api/api/v1/nodes" | jq -er '.items[] | select(any(.status.conditions[]; .type == "Ready" and .status == "True")) | .metadata.name' | head -1)
[ -n "$node" ]
request "$classes/local-path" > "$work/default-class.json"
jq -e '.reclaimPolicy == "Retain" and .volumeBindingMode == "WaitForFirstConsumer"' "$work/default-class.json" >/dev/null
# Use an isolated Delete class so successful runs reclaim their own test data.
jq --arg name "$name" '.metadata={name:$name} | .reclaimPolicy="Delete"' "$work/default-class.json" > "$work/class.json"
request --data-binary @"$work/class.json" "$classes" >/dev/null
jq -n --arg name "$name" '{apiVersion:"v1",kind:"PersistentVolumeClaim",metadata:{name:$name},
    spec:{storageClassName:$name,accessModes:["ReadWriteOnce"],resources:{requests:{storage:"16Mi"}}}}' > "$work/claim.json"
request --data-binary @"$work/claim.json" "$claims" >/dev/null
make_pod() {
    jq -n --arg name "$name-$1" --arg claim "$name" --arg node "$node" --arg command "$2" '{
        apiVersion:"v1",kind:"Pod",metadata:{name:$name},spec:{nodeName:$node,restartPolicy:"Never",
        containers:[{name:"storage",image:"docker.io/library/busybox:1.37.0",command:["sh","-ec",$command],
            volumeMounts:[{name:"data",mountPath:"/data"}]}],
        volumes:[{name:"data",persistentVolumeClaim:{claimName:$claim}}]}}'
}
make_pod writer 'echo persistent-proof > /data/proof; sleep 3600' > "$work/writer.json"
request --data-binary @"$work/writer.json" "$pods" >/dev/null
until_ok pod_ready "$name-writer"
request "$claims/$name" > "$work/bound-claim.json"
jq -e '.status.phase == "Bound"' "$work/bound-claim.json" >/dev/null
pv=$(jq -er '.spec.volumeName' "$work/bound-claim.json")
request "$api/api/v1/persistentvolumes/$pv" > "$work/volume.json"
path=$(jq -er '.spec.local.path // .spec.hostPath.path' "$work/volume.json")
id=$(jq -er '.status.containerStatuses[0].containerID | sub("^oci-cri://"; "")' "$work/$name-writer.json")
[ "$(cri exec --sync "$id" cat /data/proof)" = persistent-proof ]
echo 'PVC bound; writer mounted and wrote the volume'
request -X DELETE -d '{"gracePeriodSeconds":0}' "$pods/$name-writer" >/dev/null
until_ok gone "$pods/$name-writer"
make_pod reader 'test "$(cat /data/proof)" = persistent-proof; sleep 3600' > "$work/reader.json"
request --data-binary @"$work/reader.json" "$pods" >/dev/null
until_ok pod_ready "$name-reader"
id=$(jq -er '.status.containerStatuses[0].containerID | sub("^oci-cri://"; "")' "$work/$name-reader.json")
[ "$(cri exec --sync "$id" cat /data/proof)" = persistent-proof ]
cri exec --sync "$id" sh -c 'grep -E "^(Seccomp|NoNewPrivs)" /proc/1/status' > "$work/kernel-security.txt"
echo 'Replacement pod read the persisted data'
request -X DELETE -d '{"gracePeriodSeconds":0}' "$pods/$name-reader" >/dev/null
until_ok gone "$pods/$name-reader"
request -X DELETE "$claims/$name" >/dev/null
until_ok gone "$claims/$name"
until_ok gone "$api/api/v1/persistentvolumes/$pv"
until_ok test ! -e "$path"
echo 'Delete reclaim removed the PV and its data directory'
