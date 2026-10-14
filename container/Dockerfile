# diorama runtime image. The binary is built on the host so a code change
# does not recompile inside Podman. See container/dev-image.sh.
#
#   container/dev-image.sh
#
# A machine with no Rust toolchain can still compile in the image:
#   podman build --ignorefile container/.dockerignore -f container/Dockerfile.source -t diorama .
#
# Run:
#   podman run -d --privileged \
#     --hostname diorama \
#     --security-opt seccomp=unconfined \
#     --security-opt apparmor=unconfined \
#     --tmpfs /tmp --tmpfs /run \
#     -v /lib/modules:/lib/modules:ro \
#     -v diorama-data:/var/lib/diorama \
#     -p 6443:6443 \
#     --name diorama \
#     localhost/diorama:latest
#
# Drop the apparmor option on a host that has no AppArmor.
# The same flags work with docker. Reuse the named volume between
# restarts so PKI and images survive a binary swap.
#
# Kubeconfig:
#   podman exec diorama cat /var/lib/diorama/pki/admin.kubeconfig > kubeconfig.yaml
#   Rewrite that file's server address to https://127.0.0.1:6443.
#
# Stop:
#   podman stop diorama && podman rm diorama

FROM alpine:3.22

RUN printf '%s\n' \
        "https://dl-cdn.alpinelinux.org/alpine/v3.22/main" \
        "https://dl-cdn.alpinelinux.org/alpine/v3.22/community" \
        > /etc/apk/repositories \
    && apk add --no-cache \
        iptables \
        ip6tables \
        nftables \
        conntrack-tools \
        iproute2 \
        kmod \
        e2fsprogs \
        ca-certificates \
        containerd \
        crun \
        cni-plugins \
    && mkdir -p /var/lib/diorama /opt/cni/bin \
    && for plugin in bridge host-local portmap loopback; do \
        ln -sfn "/usr/libexec/cni/$plugin" "/opt/cni/bin/$plugin"; \
    done

COPY --chmod=755 dist/diorama /usr/local/bin/diorama
COPY --chmod=755 container/entrypoint.sh /usr/local/bin/diorama-entrypoint

VOLUME ["/var/lib/diorama"]

EXPOSE 6443 10250

STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/diorama-entrypoint"]
CMD ["--container-mode"]
