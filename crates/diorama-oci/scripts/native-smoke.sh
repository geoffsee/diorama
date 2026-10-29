#!/bin/sh
# Run on the Linux node (or with its state, pod logs, and network shared).
# Requires a running managed diorama node, curl, jq, iproute2, and crictl.
set -eu
for tool in curl jq ip crictl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Required tool not found: $tool" >&2; exit 1; }
done
state=${DIORAMA_STATE:-/var/lib/diorama}
api=${DIORAMA_API:-https://127.0.0.1:6443}
name=oci-smoke-$$
work=$(mktemp -d)
node_interface=$(ip -o route show default | awk '{print $5; exit}')
request() {
    curl -fsS --cacert "$state/pki/ca.crt" --cert "$state/pki/admin.crt" \
        --key "$state/pki/admin.key" -H 'Content-Type: application/json' "$@"
}
cri() { crictl --runtime-endpoint "unix://$state/oci-cri/cri.sock" "$@"; }
pod_url() { printf '%s/api/v1/namespaces/default/pods/%s' "$api" "$1"; }
cleanup() {
    for pod in "$name" "$name-seccomp"; do
        request -X DELETE -d '{"gracePeriodSeconds":0}' "$(pod_url "$pod")" >/dev/null 2>&1 || true
    done
    rm -rf "$work"
}
trap cleanup EXIT
node=
for attempt in $(seq 1 60); do
    node=$(request "$api/api/v1/nodes" 2>/dev/null | jq -er '.items[0].metadata.name') || node=
    if [ -n "$node" ] && [ "$node" != null ]; then break; fi
    sleep 1
done
[ -n "$node" ] && [ "$node" != null ] || { echo 'Node registration timed out' >&2; exit 1; }
make_pod() {
    jq -n --arg name "$1" --arg profile "$2" --arg node "$node" '{
      apiVersion:"v1",kind:"Pod",metadata:{name:$name,namespace:"default"},
      spec:{nodeName:$node,restartPolicy:"Never",securityContext:{seccompProfile:{type:$profile}},
        containers:[{name:"smoke",image:"docker.io/library/busybox:1.37.0",
          command:["sh","-c","echo managed-smoke; sleep 3600"],
          resources:{limits:{memory:"64Mi",cpu:"100m"}}}]}}'
}
# The pod must start, and an exec process must inherit the selected filter.
make_pod "$name-seccomp" RuntimeDefault > "$work/seccomp.json"
request --data-binary @"$work/seccomp.json" "$api/api/v1/namespaces/default/pods" >/dev/null
confined=false
for attempt in $(seq 1 60); do
    request "$(pod_url "$name-seccomp")" > "$work/status.json"
    if jq -e '.status.phase == "Running" and .status.containerStatuses[0].ready' "$work/status.json" >/dev/null; then
        confined=true
        break
    fi
    sleep 1
done
[ "$confined" = true ] || { cat "$work/status.json"; exit 1; }
seccomp_id=$(jq -er '.status.containerStatuses[0].containerID | sub("^oci-cri://"; "")' "$work/status.json")
cri exec --sync "$seccomp_id" sh -c 'grep "^Seccomp:" /proc/self/status' > "$work/seccomp-mode.txt"
grep -Eq '^Seccomp:[[:space:]]+2$' "$work/seccomp-mode.txt"
echo 'RuntimeDefault pod started and exec inherited its seccomp filter'
make_pod "$name" Unconfined > "$work/pod.json"
request --data-binary @"$work/pod.json" "$api/api/v1/namespaces/default/pods" >/dev/null
ready=false
for attempt in $(seq 1 60); do
    request "$(pod_url "$name")" > "$work/status.json"
    if jq -e '.status.phase == "Running" and .status.containerStatuses[0].ready' "$work/status.json" >/dev/null; then
        ready=true
        break
    fi
    sleep 1
done
[ "$ready" = true ] || { cat "$work/status.json"; exit 1; }
id=$(jq -er '.status.containerStatuses[0].containerID | sub("^oci-cri://"; "")' "$work/status.json")
ip=$(jq -er '.status.podIP | select(. != "" and . != "127.0.0.1")' "$work/status.json")
cri exec --sync "$id" sh -c 'mkdir -p /tmp/web; echo cni-ok > /tmp/web/index.html; httpd -p 8080 -h /tmp/web'
[ "$(curl -fsS "http://$ip:8080")" = cni-ok ]
cri logs "$id" | grep -F managed-smoke
cri stats -o json "$id" | jq -e --arg id "$id" '.stats[] | select(.attributes.id == $id) | (.cpu.usageCoreNanoSeconds.value | tonumber) > 0 and (.memory.usageBytes.value | tonumber) > 0' >/dev/null
cri inspect "$id" | jq -e '.spec.linux.resources.memory.limit == 67108864 and .spec.linux.resources.cpu.quota == 10000 and .spec.linux.resources.cpu.period == 100000' >/dev/null
# Exercise the pod's configured resolver, not an explicit server override.
dns_ip=$(request "$api/api/v1/namespaces/kube-system/services/kube-dns" | jq -er '.spec.clusterIP')
service_ip=$(request "$api/api/v1/namespaces/default/services/kubernetes" | jq -er '.spec.clusterIP')
cri exec --sync "$id" cat /etc/resolv.conf > "$work/resolv.conf"
grep -F "nameserver $dns_ip" "$work/resolv.conf" >/dev/null
dns_ready=false
for attempt in $(seq 1 30); do
    if cri exec --sync "$id" nslookup kubernetes.default.svc.cluster.local > "$work/dns.txt" 2>&1 &&
        grep -F "$service_ip" "$work/dns.txt" >/dev/null; then
        dns_ready=true
        break
    fi
    sleep 1
done
[ "$dns_ready" = true ] || { cat "$work/resolv.conf" "$work/dns.txt"; exit 1; }
echo 'Pod resolver and cluster DNS lookup passed'
for pod in "$name" "$name-seccomp"; do
    request -X DELETE -d '{"gracePeriodSeconds":0}' "$(pod_url "$pod")" >/dev/null
done
for attempt in $(seq 1 60); do
    if ! cri ps -a -o json | jq -e --arg id "$id" '.containers[] | select(.id == $id)' >/dev/null; then
        # CNI DEL must not remove the node interface or break its API.
        request "$api/api/v1/nodes" >/dev/null
        [ -z "$node_interface" ] || ip link show "$node_interface" >/dev/null
        echo 'Managed pod networking, exec, logs, resources, stats, and removal passed'
        exit 0
    fi
    sleep 1
done
echo 'Container cleanup timed out' >&2
exit 1
