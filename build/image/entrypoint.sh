#!/bin/sh
# Link the image's containerd, crun, and CNI plugins into the data directory.
# A mounted volume hides paths created at image build time, so this runs at start.
set -eu

state=${KUBESOLO_PATH:-/var/lib/diorama}
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

exec /usr/local/bin/diorama "$@"
