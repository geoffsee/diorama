#!/usr/bin/env bash

# Docker cp writes below tmpfs mounts. Stream fixtures through the running
# container's mount namespace so /tmp files are visible to the test commands.
copy_into_node() {
  "$engine" exec -i "$name" /bin/sh -c 'cat > "$1" && chmod "$2" "$1"' \
    copy-into-node "$2" "${3:-0644}" < "$1"
}

extract_install_job() {
  # The bundle builder archives '.', so GNU tar requires the './' member prefix.
  tar -xzf "$1" -C "$2" ./install-job.json
}
