#!/bin/sh
# Incremental host build, then a runtime image that only copies that binary.
set -eu

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)

case "$(uname -m)" in
    arm64|aarch64) target=aarch64-unknown-linux-musl ;;
    x86_64) target=x86_64-unknown-linux-musl ;;
    *)
        printf 'unsupported host architecture: %s\n' "$(uname -m)" >&2
        exit 1
        ;;
esac

engine=${CONTAINER_ENGINE:-podman}
image=${IMAGE:-localhost/diorama:latest}

export PATH="${HOME}/.cargo/bin:${PATH}"
cd "$root"
if ! cargo build --locked --target "$target" -p diorama; then
    if [ "$(uname -s)" != "Linux" ]; then
        printf 'host musl build failed on %s; run "make image-source" to compile inside the container\n' "$(uname -s)" >&2
    fi
    exit 1
fi

mkdir -p "$root/dist"
cp "$root/target/$target/debug/diorama" "$root/dist/diorama"
chmod +x "$root/dist/diorama"

case "$engine" in
    *podman*)
        exec "$engine" build --ignorefile "$root/container/.dockerignore" -t "$image" -f "$root/container/Dockerfile" "$root"
        ;;
    *)
        exec "$engine" build -t "$image" -f "$root/container/Dockerfile" "$root"
        ;;
esac
