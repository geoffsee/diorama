# System networking manifests

`cilium.yaml` is rendered from the upstream Cilium Helm chart 1.20.4 using
`cilium-values.yaml`:

```sh
helm template cilium cilium --repo https://helm.cilium.io --version 1.20.4 \
  --namespace kube-system -f cilium-values.yaml > cilium.yaml
```

After rendering, express projected-volume `defaultMode: 0400` as decimal
`defaultMode: 256`. This preserves the permission bits and produces an integer
when decoded as YAML 1.2 and served as Kubernetes JSON. Keep the Namespace document
at the beginning of the file. The manifest test checks this upstream-client
compatibility requirement and ordinary-node scheduling constraints.

The runtime substitutes the direct API address and configured Pod pool before
applying these manifests, and supplies `cilium-config.data.mtu` when the existing
control-plane `network.mtu` setting is nonzero. Cilium creates and manages its CRDs and cluster-pool
allocations. Hubble and Envoy are disabled in this baseline. The separate
`kube-proxy.yaml` runs upstream kube-proxy 1.35.7 with Cilium's
`kubeProxyReplacement=false`. There is one supported networking profile.
Its conntrack configuration preserves existing host limits and TCP timeouts.
