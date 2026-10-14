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

export PATH="${HOME}/.cargo/bin:${PATH}"
cd "$root"
cargo build --locked --target "$target" -p diorama

mkdir -p "$root/dist"
cp "$root/target/$target/debug/diorama" "$root/dist/diorama"
chmod +x "$root/dist/diorama"

exec podman build --ignorefile "$root/container/.dockerignore" -t diorama -f "$root/container/Dockerfile" "$root"
