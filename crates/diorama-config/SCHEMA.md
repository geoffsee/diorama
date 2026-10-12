# Configuration setting descriptors

`describe_settings()` returns `Vec<SettingDescriptor>` in lexical path order.
Its JSON serialization matches the pinned KubeSolo `config.Describe()` descriptor
array used by the configuration API schema endpoint. This is a setting inventory,
not a JSON Schema validation dialect. No endpoint or CLI command is implemented
by this module. Each descriptor exposes `path`, `type`, `default`, optional
`flag`/`envar`, `mutability`, and `secret` (omitted when false).

`FIELDS` supplies membership, JSON type, secrecy and mutability;
`INPUT_BINDINGS` supplies environment and deprecated flag names;
`Config::default()` supplies values. Schema metadata `apiVersion` and `kind`
is carried by the model and example, not counted among the 30 settings.
A null default can still have type boolean, array or object. A secret default
is always null, even though the desired model stores an empty string by default.
`immutable` and `restart` describe baseline policy, not an implemented live-update
mechanism. Component ownership remains in `FIELDS` rather than extending the
baseline descriptor wire format.

[The default example](examples/default-config.yaml) is exactly
`render_effective_yaml(&Config::default())`. It describes the unresolved desired
configuration: the empty socket path is derived later from the final state path,
container mode remains automatic, and node name is discovered later. Omitted
optional fields decode to their model defaults. Rendering arbitrary user
configuration can include credentials; this default example contains none.

The complete table below is checked against the public descriptors in tests.
Update it and the example when intentionally changing model defaults or metadata;
independent captured Go descriptors must also remain compatible or a deviation
must be explicitly reviewed. No descriptor/default compatibility deviation is
currently declared. The renderer's approved empty-path and Unicode-linebreak
preservation policies are described in [LAYERING.md](LAYERING.md); neither changes
this default example.

<!-- settings:start -->
| Setting | JSON type | Default | Legacy flag | Environment | Mutability | Secret |
| --- | --- | --- | --- | --- | --- | --- |
| `api.enabled` | boolean | `false` | — | KUBESOLO_API_ENABLED | restart | false |
| `api.socketPath` | string | `""` | — | KUBESOLO_API_SOCKET_PATH | restart | false |
| `d2k.enabled` | boolean | `false` | d2k | KUBESOLO_D2K | restart | false |
| `d2k.namespace` | string | `"d2k"` | d2k-namespace | KUBESOLO_D2K_NAMESPACE | restart | false |
| `kubernetes.apiServer.extraSANs` | array | `null` | apiserver-extra-sans | KUBESOLO_APISERVER_EXTRA_SANS | restart | false |
| `kubernetes.apiServer.startupTimeoutSeconds` | integer | `600` | startup-timeout | KUBESOLO_STARTUP_TIMEOUT | restart | false |
| `kubernetes.kubelet.cpuManager.policy` | string | `"none"` | cpu-manager-policy | KUBESOLO_CPU_MANAGER_POLICY | restart | false |
| `kubernetes.kubelet.cpuManager.policyOptions` | object | `null` | cpu-manager-policy-options | KUBESOLO_CPU_MANAGER_POLICY_OPTIONS | restart | false |
| `kubernetes.kubelet.cpuManager.reservedCPUs` | string | `""` | reserved-cpus | KUBESOLO_RESERVED_CPUS | restart | false |
| `kubernetes.kubelet.systemReserved` | object | `null` | system-reserved | KUBESOLO_SYSTEM_RESERVED | restart | false |
| `kubernetes.nodeName` | string | `""` | — | KUBESOLO_NODE_NAME | restart | false |
| `logging.debug` | boolean | `false` | debug | KUBESOLO_DEBUG | restart | false |
| `logging.pprof` | boolean | `false` | pprof-server | KUBESOLO_PPROF_SERVER | restart | false |
| `metrics.bindAddress` | string | `"127.0.0.1:9105"` | metrics-bind-address | KUBESOLO_METRICS_BIND_ADDRESS | restart | false |
| `metrics.enabled` | boolean | `false` | metrics-server | KUBESOLO_METRICS_SERVER | restart | false |
| `network.disableIPv6` | boolean | `false` | disable-ipv6 | KUBESOLO_DISABLE_IPV6 | restart | false |
| `network.loadBalancer.enabled` | boolean | `true` | load-balancer | KUBESOLO_LOAD_BALANCER | restart | false |
| `network.loadBalancer.ip` | string | `""` | load-balancer-ip | KUBESOLO_LOAD_BALANCER_IP | restart | false |
| `network.mtu` | integer | `0` | mtu | KUBESOLO_MTU | restart | false |
| `network.nodeIP` | string | `""` | node-ip | KUBESOLO_NODE_IP | restart | false |
| `path` | string | `"/var/lib/diorama"` | path | KUBESOLO_PATH | immutable | false |
| `portainer.async` | boolean | `false` | portainer-edge-async | KUBESOLO_PORTAINER_EDGE_ASYNC | restart | false |
| `portainer.edgeID` | string | `""` | portainer-edge-id | KUBESOLO_PORTAINER_EDGE_ID | restart | false |
| `portainer.edgeKey` | string | `null` | portainer-edge-key | KUBESOLO_PORTAINER_EDGE_KEY | restart | true |
| `portainer.image` | string | `"docker.io/portainer/agent:lts"` | portainer-edge-image | KUBESOLO_PORTAINER_EDGE_IMAGE | restart | false |
| `runtime.containerMode` | boolean | `null` | container-mode | KUBESOLO_CONTAINER_MODE | restart | false |
| `runtime.endpoint` | string | `""` | container-runtime-endpoint | KUBESOLO_CONTAINER_RUNTIME_ENDPOINT | restart | false |
| `storage.dbWALRepair` | boolean | `false` | db-wal-repair | KUBESOLO_DB_WAL_REPAIR | restart | false |
| `storage.localPath.enabled` | boolean | `true` | local-storage | KUBESOLO_LOCAL_STORAGE | restart | false |
| `storage.localPath.sharedPath` | string | `""` | local-storage-shared-path | KUBESOLO_LOCAL_STORAGE_SHARED_PATH | restart | false |
<!-- settings:end -->

The independent oracle is `tests/fixtures/bindings-reference.json`, extracted from
`tools/parity/fixtures/config-api/configapi.json`, with its source hash recorded
in the fixture. It captures actual baseline Go descriptor output at revision
`2ef1c4787989f11f868f81bb84ae2afd4a49a81d`. The test compares the entire serialized
array, including null defaults, omitted optional metadata and sorted order.
Other tests ensure every inventory entry has a model leaf and input binding,
and that the checked-in example decodes to the complete default model and renders
back byte-for-byte. These checks require no host discovery or running cluster.
