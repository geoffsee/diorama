# Portainer Edge Agent Bootstrap Resources and Credentials

Recorded for [E19.01](https://github.com/geoffsee/diorama/issues/88).

This document details the generation and security model of Kubernetes resources for the optional Portainer Edge Agent component.

## Resource Inventory

When enabled, `diorama-portainer` creates the following Kubernetes resources:

| Resource Kind | Name | Namespace | Description |
|---|---|---|---|
| `Namespace` | `portainer` | Cluster-scoped | Isolated namespace for Portainer agent resources |
| `ServiceAccount` | `portainer-sa-clusteradmin` | `portainer` | Service account used by the agent pod |
| `ClusterRoleBinding` | `portainer-crb-clusteradmin` | Cluster-scoped | Grants `cluster-admin` privileges to the agent service account |
| `ConfigMap` | `portainer-agent-edge` | `portainer` | Stores non-sensitive edge parameters (`EDGE_ID`, `EDGE_ASYNC`, `EDGE_INSECURE_POLL`, optional `EDGE_SECRET`) |
| `Secret` | `portainer-agent-edge-key` | `portainer` | Stores sensitive edge key (`edge.key`) as `Opaque` secret |
| `Service` | `portainer-agent` | `portainer` | Headless service (`clusterIP: None`, `publishNotReadyAddresses: true`) exposing ports 9001 and 80 |
| `Deployment` | `portainer-agent` | `portainer` | Single-replica Deployment running `docker.io/portainer/agent:lts` (or custom image) |

## Credential Handling & Redaction

Edge credentials grant remote administrative control to Portainer Server / Edge environments. To protect cluster security:
1. `PortainerAgentConfig` custom `Debug` implementation ensures all log messages, panic strings, and traces redact `edge_key` and `edge_secret` to `"<redacted>"`.
2. `PortainerError` variants reporting incomplete credentials describe which fields are present/absent without ever logging the secret values themselves.
3. Secrets are passed to the Pod via Kubernetes `secretKeyRef` referencing `portainer-agent-edge-key`.

## Mode Selection: Sync vs. Async

Portainer Edge Agent supports two communication modes:
- **Synchronous Mode (`edge_async: false`)**:
  - `EDGE_ASYNC: "false"` in `portainer-agent-edge` ConfigMap.
  - The agent opens persistent or long-polling channels to Portainer Server.
- **Asynchronous Mode (`edge_async: true`)**:
  - `EDGE_ASYNC: "true"` in `portainer-agent-edge` ConfigMap.
  - The agent periodically polls Portainer Server for tasks according to polling schedule.

## Platform Architecture Support

- **Supported Platforms**: `linux/amd64`, `linux/arm64`, `linux/arm/v7`.
- **Unsupported Platforms**: `linux/riscv64` (the upstream Portainer Agent image is not compiled or published for RISC-V).
- **Enforcement**: When evaluating `Architecture::Riscv64`:
  - `is_architecture_supported()` evaluates to `false`.
  - `is_enabled()` evaluates to `false`.
  - `selected_image()` returns `None`, guaranteeing that containerd image download/import pipelines do not attempt to fetch or extract unsupported payloads.
  - Manifest generation returns `PortainerError::UnsupportedArchitecture(Architecture::Riscv64)`.
