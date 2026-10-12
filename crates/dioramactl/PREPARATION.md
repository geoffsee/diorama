# Explicit prerequisite preparation

`dioramactl check --install-prereqs` authorizes two fixed Alpine actions. Existing
`KUBESOLO_INSTALL_PREREQS` parsing is unchanged; a false flag overrides the environment.
Help/version/parse errors require neither a Tokio runtime nor signal registration.
The synchronous `execute` library API remains read-only; the executable selects
`execute_check_with_preparation` only for an explicitly parsed opt-in.

The pure preflight report selects the first nonpassing check in baseline order.
Root, hostname, Docker and xt_comment blockers/unknowns suppress preparation.
Each action variant runs at most once; every successful action causes full fresh
discovery and supplemental observations before further actions or port probes.
Exit zero from a command is never interpreted as host readiness. Persistent missing
requirements stop without a retry loop. External runtime ownership is not granted
by either action: no runtime, registry, image or CNI operations are exposed.

The executor accepts only `PreparationAction` and a permit derived from parsed
options; callers cannot supply a program, arguments or environment. Commands are:

* `/sbin/apk add --no-cache` followed only by missing `nftables` and/or `iptables`,
  in that order; five-minute execution deadline.
* `/sbin/rc-update add cgroups boot`, then only on success
  `/sbin/rc-service cgroups start`; one-minute execution deadline each.

These are shared host effects. A failed, timed-out or interrupted command may have
changed package/service state. The invocation retains that fact across successful
steps and reports it on later failures. There is no destructive compensation:
preexisting registrations/services/packages are never removed or stopped. Unlike
Go's ignored rc-update error, Rust stops before rc-service when registration fails.
Fixed absolute command paths and a cleared environment with only fixed system
PATH and LANG=C are deliberate privileged-execution differences from baseline PATH
lookup/environment inheritance. Proxy variables and customized APK environments
are not forwarded. Child stdin/stdout/stderr are discarded, so there is no child
output accumulation or private package output in diagnostics.

One local async signal bridge installs SIGINT and SIGTERM before polling workflow
effects and remains alive through command cleanup and gaps. Installation failure
polls no workflow. Tokio registration is process-global/permanent; SIGINT can remain
registered if SIGTERM registration fails. The current-thread runtime enables I/O
and time. The host trait and stdout/stderr locks remain local and need not be Send.
There is no detached signal task. Pending notifications win over workflow polling;
a persistent latch and atomically registered StopHandle prevent a new command after
observed cancellation. Explicit yield checkpoints precede actions/steps. Repeated
signals never reset cleanup deadlines. Dropping the async API future is not a clean
shutdown protocol: callers must drive it to completion.

Every command uses the existing one-shot OwnedProcessAdapter and its independent
owner thread. Deadlines request supervisor shutdown (30s graceful, 35s cooperative
scheduler limit); one extra second observes owner termination. Kernel operations
and escaped daemon descendants have no hard wall-clock guarantee. A joined owner
whose executable failed to spawn is an execution error, not an incomplete cleanup.
An unfinished owner, unreaped child or lost ownership returns **exit 2** immediately,
with no subsequent synchronous output, discovery, action or port probe. The typed
receipt remains available to library callers and the stop request stays retained.
Exit 2 is not proof of kernel/descendant cleanup. Inspect the host before retrying.
Ordinary failed checks/commands or cancellation return 1; observed checks passing
return 0. Power loss, SIGKILL and panic=abort cannot run Rust cleanup.

Synchronous discovery and output occur only between commands whose ownership is
settled; their filesystem/writer latency is not bounded. On the exceptional exit-2
path no post-child output is attempted. The managed check still does not start a
node, reserve ports, install other prerequisites, load modules, change mount
propagation, move PIDs into cgroups, or provide a general installer.

Tests separate injected workflow decisions, notification/receipt regressions,
synthetic fixed-command chroot qualification, and actual Alpine package/OpenRC
behavior. Historical parser-only Go captures remain unchanged. Synthetic helpers
prove command selection, stopping and child ownership, not real apk/OpenRC behavior.
