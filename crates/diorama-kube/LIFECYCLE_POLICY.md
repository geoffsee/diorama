# Component startup policy

`LifecyclePolicy::from_config(&ValidatedConfig)` converts the existing
`kubernetes.apiServer.startupTimeoutSeconds` setting into a component startup
budget. `startup_timeout()` returns the duration. `apply(ComponentSpec)` changes
only that spec's timeout; identity, dependencies, component kind and required or
optional failure policy remain the caller's decisions. This pure boundary performs
no registration, host probing, component startup or CLI dispatch.

The read-only diorama baseline `2ef1c4787989f11f868f81bb84ae2afd4a49a81d`
sets a shared retry count only for positive configured values in
`cmd/diorama/main.go:144–146`. `types/const.go` defines the default startup budget
as 600 seconds and the polling interval as five seconds; `types/var.go` initializes
the retry count from those defaults. Therefore zero and negative configuration
values retain a 600-second effective budget. The configuration document remains
unchanged, including its explicit nonpositive value.

Positive values become exact elapsed-second deadlines, following the accepted
supervision contract rather than reproducing the baseline's polling/retry
approximation. This is a startup readiness budget, not an API-server HTTP request
timeout. The supervisor starts each budget when its component launches, after
prerequisites become usable. Large values are preserved; the supervisor rejects
unrepresentable deadlines rather than silently shortening them. Applying this
policy does not change the separate 30-second graceful and 35-second cooperative
shutdown budgets or promise a hard operating-system scheduling/reaping bound.

Five focused tests cover default/positive/nonpositive policy, unchanged graph
metadata, actual file/environment/explicit-flag precedence through a virtual-time
graph deadline, cleanup with a blocked dependent, dependency waiting and oversized
deadline rejection. Run:

```sh
cargo test -p diorama --locked --test suite lifecycle_policy::
```

Concrete component registration and full distribution startup remain separate
integration work. This module supplies their configuration boundary.
