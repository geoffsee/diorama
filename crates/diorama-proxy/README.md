# diorama-proxy

`diorama-proxy` manages kube-proxy configuration generation, backend selection (`iptables` vs `nftables`), conntrack tuning adaptation, Service and EndpointSlice routing verification, and supervised service lifecycle in diorama.

## Features

- **v1alpha1 KubeProxyConfiguration Generation**: Full parity with Kubernetes `kubeproxy.config.k8s.io/v1alpha1`.
- **Automatic Backend Selection**: Dynamically detects kernel and userspace capabilities, seamlessly selecting `iptables` or `nftables` (Kubernetes 1.31+).
- **Container Mode Conntrack Zeroing**: In container mode, all six conntrack settings are set to zero (`maxPerCore = 0`, `min = 0`, `tcpEstablishedTimeout = 0s`, `tcpCloseWaitTimeout = 0s`, `udpTimeout = 0s`, `udpStreamTimeout = 0s`), enabling flawless operation on read-only `/proc/sys` filesystems.
- **Host Mode Upstream Defaults**: Preserves upstream Kubernetes host defaults when running on bare metal or virtual machine hosts.
- **Service Routing & EndpointSlice Tracking**: Validates ClusterIP and NodePort routing against ready endpoints across TCP and UDP protocols, adapting dynamically to endpoint additions, removals, and degradation.
- **Dataplane Rule Synthesis**: Generates and inspects deterministic `iptables` (KUBE-SERVICES, KUBE-NODEPORTS, KUBE-SVC, KUBE-SEP) and `nftables` (tables, chains, and maps) rules.
- **Diagnostic Distinction**: Rigorously separates component startup readiness from active dataplane probe results in logs and health reports.
- **Supervised Lifecycle & Health**: Fully integrated with `diorama-supervisor`, checking health and verifying SNAT pod egress masquerade readiness before signaling component ready.
- **Routing & Foreign Firewall Preservation Across Restart**: Preserves foreign firewall rules and E15 pod egress SNAT masquerade rules across proxy restarts and backend churn without blanket NAT flushes.
- **Actionable Diagnostics**: Actionable operator guidance on missing backends, read-only `/proc/sys`, and credential failures.

## Documentation

- [Proxy Baseline Configuration & Backend Selection](docs/proxy-baseline.md)
- [Service Routing & EndpointSlice Verification](docs/service-routing.md)
- [Routing and Foreign Firewall Preservation Across Restart](docs/restart-and-firewall-preservation.md)
