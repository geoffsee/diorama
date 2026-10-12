# diorama-portainer

Portainer Edge Agent bootstrap and lifecycle management for KubeSolo clusters.

## Overview

`diorama-portainer` generates, validates, and manages Kubernetes resources for bootstrapping the Portainer Edge Agent into the cluster. It provides:
- **Namespace**: `portainer`
- **ServiceAccount**: `portainer-sa-clusteradmin` in `portainer`
- **ClusterRoleBinding**: `portainer-crb-clusteradmin` binding `portainer-sa-clusteradmin` to `cluster-admin`
- **ConfigMap**: `portainer-agent-edge` containing edge agent environment variables (`EDGE_ID`, `EDGE_INSECURE_POLL`, `EDGE_ASYNC`, and optional `EDGE_SECRET`)
- **Secret**: `portainer-agent-edge-key` storing the sensitive `edge.key`
- **Service**: Headless service `portainer-agent` on ports 9001 (`edge`) and 80 (`http`)
- **Deployment**: `portainer-agent` running the configured agent image with correct environment mappings

## Security & Credential Redaction

- Edge keys and secret tokens are treated as sensitive credentials.
- `PortainerAgentConfig` implements custom `Debug` formatting which automatically replaces `edge_key` and `edge_secret` with `"<redacted>"`.
- Errors and log events never expose plaintext edge credentials.

## Architecture and Enablement

- **Supported Architectures**: `amd64`, `arm64`, and `armv7`.
- **Unsupported Architectures**: `riscv64` (Portainer Agent is not published for RISC-V). Attempts to generate resources or select images on unsupported platforms fail safely with `PortainerError::UnsupportedArchitecture`.
- **Enablement**: Portainer Edge Agent is only activated when BOTH `edge_id` and `edge_key` are provided and non-empty, and the platform architecture is supported.
- **Partial/Missing Credentials**: Handled deterministically with `PortainerError::MissingCredentials` or `PortainerError::IncompleteCredentials`.
- **Image Selection**: Unsupported images are never selected. Default image is `docker.io/portainer/agent:lts`, with full support for custom references.

See [docs/bootstrap-resources.md](docs/bootstrap-resources.md) for detailed resource specifications and architecture notes.
