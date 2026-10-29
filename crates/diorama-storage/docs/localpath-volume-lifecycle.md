# Local-path volume lifecycle

Production storage reconciliation installs the local-path provisioner workload,
its RBAC/configuration, and the `local-path` StorageClass. It does not allocate a
directory on the control-plane host or choose the first Node in the API.
Local-path is an external provisioner, not a CSI driver. Production does not
register a `CSIDriver` or require `CSIStorageCapacity` reports. Reconciliation
removes the incorrectly advertised driver from older installations only when it
has the local-path provisioner's ownership label.

The StorageClass uses `WaitForFirstConsumer` and ordinary-node topology. Upstream
kube-scheduler selects a suitable ordinary node and records
`volume.kubernetes.io/selected-node` on the PVC before binding the consumer Pod.
The volume controller then supplies the storage-provisioner annotation required
by the external provisioner, after validating the selected ordinary node.
The provisioner creates node-local helper Pods and a PV whose node affinity fixes
subsequent consumers to the selected host. Helpers and the provisioner require
`diorama.io/runtime=ordinary`; they do not tolerate the foreign-worker taint.

Retain/Delete behavior is executed by the provisioner workload and its node-local
helpers. Data remains on the selected node across consumer restarts; this does
not provide replicated storage or automatic data movement when that node is lost.

`LocalPathVolumeManager` remains a library fixture for historical filesystem and
reclaim tests. The production service and supervisor do not call its provisioning
loop. Those tests do not qualify remote-node provisioning. The independent Linux
fixture verifies a scheduled PVC, its selected-node annotation, and a file written
and read through the resulting mount. See
[qualification](../../../tests/multinode/QUALIFICATION.md).
