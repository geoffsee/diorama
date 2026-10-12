# Pure host preflight policy

`preflight::evaluate_preflight(&HostEvidence, &PreflightInputs)` evaluates the
baseline's seven host checks without IO, command execution, installation, port
binding, mounts, cgroup movement or module loading. The result always contains seven
findings in baseline order and the first non-passing check. Callers can render the
prefix through `first_blocker` to preserve fail-fast CLI presentation; evaluation
itself deliberately describes all supplied evidence because it has no effects.
No `check` subcommand or preparation executor is wired by this slice.

`CheckStatus` separates `Pass`, `NotApplicable`, `Blocker`, `Unknown` and
`NeedsPreparation`. Unknown or planned preparation cannot yield `ready() == true`.
The name means only that the supplied observations satisfy these seven checks; it
is not component readiness, a privilege grant, reserved ports or a kernel capability
proof. Findings contain static reason/remediation enums, bounded lists of missing
requirements, an optional probe-failure category and allowlisted plans. They do not
echo hostnames, command output, arbitrary environment, endpoint strings or secrets.
There are at most two plan records, five missing controllers or four missing ports.
Input maps/text remain caller-owned; policy scans them without copying arbitrary
contents into reports. Initial Linux platform/target validation remains with discovery
and the command's earlier detection phase, as in the baseline.

## Rules and evidence

The source is KubeSolo `2ef1c4787989f11f868f81bb84ae2afd4a49a81d`,
`internal/cli/preflight/preflight.go`. The order is:

1. **Root:** real UID must equal zero, matching `os.Getuid()`. Effective UID and
   Linux capabilities are distinct facts; this check does not claim they permit
   later operations. Missing UID evidence is unknown.
2. **Hostname:** validate the raw hostname, without trim/lowercase/fallback. Total
   UTF-8 byte length <=253; each dot-separated label is nonempty and <=63 bytes;
   only lowercase ASCII letters, digits and hyphens, with alphanumeric endpoints.
   Runtime node-name normalization remains with config conversion.
3. **Docker conflict:** existence of `/var/run/docker.sock`, `/usr/bin/docker`, or
   `/usr/local/bin/docker` is a blocker in that order. No managed containerd/CRI-O
   conflict is inferred from an explicitly external runtime. Actual Docker evidence
   remains a separate baseline conflict; external mode does not blindly skip it.
4. **xt_comment:** a first whitespace field `xt_comment` in `/proc/modules`, a
   trimmed exact `comment` line in `/proc/net/ip_tables_matches`, or explicitly
   observed baseline module candidate/glob existence satisfies the legacy check.
   The baseline loaded-module scanner accepts a one-field line, so this policy
   intentionally does not substitute the stricter full module-line classifier.
   `modules.dep`/`modules.builtin` indexes alone never prove file existence or
   loadability and cannot satisfy this check.
5. **Alpine networking:** non-Alpine is not applicable. Alpine requires nft at one
   of `/usr/sbin/nft`, `/sbin/nft`, `/usr/bin/nft`, plus iptables at one of
   `/sbin/iptables`, `/usr/sbin/iptables`, `/bin/iptables`, `/usr/bin/iptables`.
   These match existence-only Go checks, not executable/ABI verification. Other
   fixed discovery directories do not silently widen the accepted sets.
6. **Cgroups:** require `cpuset`, `cpu`, `io`, `memory`, `pids`, in that order. Read
   v2 controller text when present; absent v2 uses `/sys/fs/cgroup` plus per-controller
   v1 landmarks, with `io` mapped to `blkio`. Present empty v2 text is not v1.
   On Alpine, absent/empty v2 and present `/sbin/rc-service` require explicit service
   preparation before rechecking; a nonempty v2 list bypasses that preparation even
   when incomplete, matching the baseline helper. Unreadable evidence stays unknown.
7. **Ports:** explicit wildcard TCP bind observations for 2379, 6443, 10443 and,
   only with pprof enabled, 6060. Any failed bind blocks; this includes non-conflict
   errors, so the reason says bind failed rather than asserting another PID owns it.
   Known failures remain blockers even if other port observations are unknown;
   supplied unknown failure categories remain attached. No socket is opened here.

`PreflightInputs` supplies facts not present in current `HostEvidence`:
`xt_comment_on_disk` is an aggregate actual observation of the Go candidate set:
`/lib/modules/<release>/kernel/net/netfilter/xt_comment.ko` with empty/`.xz`/`.zst`/
`.gz` suffix, then `/lib/modules/<release>/*/xt_comment.ko*`. Baseline release is the
third whitespace field of `/proc/version`; current discovery's uname/index facts
must not silently be substituted. The supplement also supplies exact rc-service
existence and the four bind results. Default supplemental values are unknown, never
an implicit successful probe. `Absent` on a filesystem supplement means a completed
absence observation; absent non-filesystem identity/port evidence is unknown.

## Plans and deviations

Missing Alpine packages block normally. `install_prerequisites=true` changes this
into `NeedsPreparation` with `InstallAlpineNetworking { nftables, iptables }`.
Alpine cgroup setup similarly yields `EnableAlpineCgroups`. These are desired work,
not authorization or proof of success: a future executor must perform bounded,
owned operations and obtain fresh observations before a pass can be claimed.
A plan is returned even when an earlier rule blocks, but must not be executed on
that basis. The whole report and ownership/authorization gate must be satisfied.

`RuntimeOwnership` is explicit reporting context, not authority to install/stop an
external runtime, replace binaries, import images or rewrite external configuration.
No such actions exist in `PreparationAction`. Host-prerequisite plans arise solely
from explicit prerequisite opt-in and observed need, for either runtime mode.
They do not grant ownership of the host's OpenRC services or package state. General
module loading, rshared propagation and cgroup PID movement are intentionally absent
from the action enum until their separate ownership/execution contracts are tested.

Go often collapses read/stat errors into absence or falls back to v1 on v2 read
failure. This policy explicitly retains `Unknown` instead; unreadable evidence
cannot silently become a pass or justify preparation. All observations can race;
metadata/index existence and previous port availability do not replace execution
validation. These corrections follow the accepted discovery uncertainty contract.
Rust diagnostics use typed codes, not exact Go error-message byte parity.

The baseline installer calls broad process stop/file-conflict cleanup before its
preflight suite. This pure policy performs neither. Later integration must use
owned-resource quiesce/reprobe and cannot treat a port failure as authority to kill
an arbitrary listener. Failed preflight must not create or partly replace a service.

## Evidence and remaining work

`tools/parity/fixtures/preflight-policy` captures 44 actual Go observations twice:
raw hostname edge cases, real container UID, Docker landmarks, module loaded/match/
file/glob evidence, Alpine exact tool paths, both cgroup generations and OpenRC
preparation-required state, isolated wildcard binds with and without pprof, and
actual RunSuite fail-fast control flow. Rust tables compare independent reviewed
expectations for each record. Unknown handling and allowlisted plans have separate
Rust regressions because actual Go is not the oracle for corrected uncertainty.

The Go harness never invokes install-prerequisites=true; package/service execution
and post-preparation verification are not claimed. The RunSuite failure injection
uses explicit synthetic closures only for ordering; all other captured functions
are real unchanged baseline code with supplied owned filesystem/network context.
Further tests must execute preparation twice in fresh disposable guests/namespaces,
verify owned step failures and inventories, and prove no partial service installation.

#46 remains open for live missing probes, check-command output/exit wiring, actual
owned preparation and failure/restart qualification. #47 owns nftables-only,
read-only-but-already-correct sysctls, external runtime/CNI responsibilities and
constrained cgroup/mount adaptations. Current check results do not claim those
combinations are qualified. Parent E05 retains E03/E04 and real-platform integration.
