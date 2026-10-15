#!/bin/sh
# Link the image's containerd, crun, and CNI plugins into the data directory.
# A mounted volume hides paths created at image build time, so this runs at start.
set -eu

state=${DIORAMA_PATH:-${KUBESOLO_PATH:-/var/lib/diorama}}
prev=
for arg in "$@"; do
    if [ "$prev" = "--path" ]; then
        state=$arg
    fi
    case $arg in
        --path=*)
            state=${arg#--path=}
            ;;
    esac
    prev=$arg
done

mkdir -p "$state/bin" "$state/cni/bin"

link_bin() {
    name=$1
    src=$(command -v "$name") || {
        printf 'missing %s\n' "$name" >&2
        exit 1
    }
    ln -sfn "$src" "$state/bin/$name"
}

link_bin containerd
link_bin containerd-shim-runc-v2
link_bin crun

for plugin in bridge host-local portmap loopback; do
    src=/usr/libexec/cni/$plugin
    if [ ! -x "$src" ]; then
        printf 'missing CNI plugin %s\n' "$src" >&2
        exit 1
    fi
    ln -sfn "$src" "$state/cni/bin/$plugin"
done

# cgroup v2: a cgroup with processes cannot delegate controllers to children
# ("no internal processes"). Drain this container's root cgroup into /init so
# crun can create pod cgroups. The kubelet repeats this in Rust (see
# ContainerEnvironment::prepare_cgroups); doing it here covers the window
# before the kubelet starts.
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    mkdir -p /sys/fs/cgroup/init || true
    if [ -f /sys/fs/cgroup/cgroup.procs ]; then
        for pid in $(cat /sys/fs/cgroup/cgroup.procs 2>/dev/null || true) $$; do
            echo "$pid" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true
        done
    fi
    controllers=$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || true)
    if [ -n "$controllers" ]; then
        enable=""
        for c in $controllers; do
            enable="$enable +$c"
        done
        echo "$enable" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || {
            for c in $controllers; do
                echo "+$c" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
            done
        }
    fi
fi

# The apiserver listens on 127.0.0.1. In container mode with published ports (-p 6443:6443),
# route incoming host traffic to the loopback listener.
if command -v iptables >/dev/null 2>&1; then
    sysctl -w net.ipv4.conf.all.route_localnet=1 2>/dev/null || true
    iptables -t nat -C PREROUTING -p tcp --dport 6443 -j DNAT --to-destination 127.0.0.1:6443 2>/dev/null || \
    iptables -t nat -A PREROUTING -p tcp --dport 6443 -j DNAT --to-destination 127.0.0.1:6443 2>/dev/null || true
fi

exec /usr/local/bin/diorama "$@"
