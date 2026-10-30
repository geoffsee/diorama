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
target_env=$(printf '%s' "$target" | tr '-' '_')
target_arch=${target%%-*}
if command -v "${target}-gcc" >/dev/null 2>&1; then
    cc_bin=$(command -v "${target}-gcc")
    export "CC_${target_env}=${cc_bin}"
    if command -v "${target}-g++" >/dev/null 2>&1; then
        cxx_bin=$(command -v "${target}-g++")
        export "CXX_${target_env}=${cxx_bin}"
    fi
    if command -v "${target}-ar" >/dev/null 2>&1; then
        ar_bin=$(command -v "${target}-ar")
        export "AR_${target_env}=${ar_bin}"
    fi
    if command -v "${target}-ranlib" >/dev/null 2>&1; then
        ranlib_bin=$(command -v "${target}-ranlib")
        export "RANLIB_${target_env}=${ranlib_bin}"
    fi
    sysroot=$("${cc_bin}" -print-sysroot)
    export "BINDGEN_EXTRA_CLANG_ARGS_${target_env}=--sysroot=${sysroot}"
    mkdir -p "$root/target"
    toolchain_file="$root/target/${target}-toolchain.cmake"
    cat > "$toolchain_file" <<EOF
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ${target_arch})
set(CMAKE_C_COMPILER "${cc_bin}")
set(CMAKE_CXX_COMPILER "${cxx_bin:-${cc_bin}}")
set(CMAKE_ASM_COMPILER "${cc_bin}")
set(CMAKE_AR "${ar_bin:-ar}" CACHE FILEPATH "Archiver" FORCE)
set(CMAKE_RANLIB "${ranlib_bin:-ranlib}" CACHE FILEPATH "Ranlib" FORCE)
EOF
    export "CMAKE_TOOLCHAIN_FILE_${target_env}=${toolchain_file}"
fi
if ! RUSTC_WRAPPER="" CARGO_PROFILE_DEV_CODEGEN_BACKEND=llvm cargo build --locked --target "$target" -p diorama -p dioramactl; then
    if [ "$(uname -s)" != "Linux" ]; then
        printf 'host musl build failed on %s; run "make image-source" to compile inside the container\n' "$(uname -s)" >&2
    fi
    exit 1
fi

mkdir -p "$root/dist"
cp "$root/target/$target/debug/diorama" "$root/dist/diorama"
cp "$root/target/$target/debug/dioramactl" "$root/dist/dioramactl"
chmod +x "$root/dist/diorama" "$root/dist/dioramactl"

case "$engine" in
    *podman*)
        exec "$engine" build --ignorefile "$root/container/.dockerignore" -t "$image" -f "$root/container/Dockerfile" "$root"
        ;;
    *)
        exec "$engine" build -t "$image" -f "$root/container/Dockerfile" "$root"
        ;;
esac
