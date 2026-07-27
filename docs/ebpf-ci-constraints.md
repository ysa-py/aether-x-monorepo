# eBPF CI capability constraints

**Observed:** 2026-07-27

## Result

The current GitHub-hosted CI configuration cannot perform a privileged eBPF
attach test. The repository workflow uses ordinary `ubuntu-latest` jobs and
contains no privileged container, self-hosted runner label, `CAP_BPF`,
`CAP_NET_ADMIN`, or network-namespace setup step. The CI workflow may compile
userspace Rust and deployment artifacts, but it does not provide evidence that
an XDP/sockops program attached to a kernel interface.

The available agent sandbox demonstrates the same boundary:

| Check | Observation | Interpretation |
| --- | --- | --- |
| Kernel | Linux `6.1.158+` | Linux kernel is present. |
| Kernel config | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_CGROUP_BPF=y`, `CONFIG_XDP_SOCKETS=y`, `CONFIG_NET_CLS_ACT=y`, `CONFIG_BPF_STREAM_PARSER=y` | Required feature families are enabled in this kernel. |
| bpffs | `/sys/fs/bpf` mounted, mode `0700 root:root` | bpffs exists but is inaccessible to the unprivileged agent. |
| Initial effective capabilities | `CapEff: 0000000000000000` | No `CAP_BPF` or `CAP_NET_ADMIN`. |
| Direct BPF syscall | `bpf(BPF_MAP_CREATE, null)` → `EPERM` | Unprivileged BPF map/program creation is denied. |
| User+network namespace | `unshare -Urn` succeeds and gets a user-namespace effective capability set | Namespace creation alone is insufficient. |
| BPF syscall inside that namespace | `EPERM` | A user namespace cannot grant the host capability needed for BPF loading/attachment. |
| `bpftool` | Not installed in the agent image | No alternate privileged loader is available. |

## CI classification

| Required activity | CI status | Reason |
| --- | --- | --- |
| Build/load test userspace eBPF controller | ✅ when source is added | Ordinary Rust CI can compile/test safe userspace code. |
| Create BPF maps/programs | 🟡 | Denied with `EPERM`; no `CAP_BPF`. |
| Attach XDP to a veth | 🟡 | Requires `CAP_NET_ADMIN` and BPF loading rights. |
| Attach sockops to a cgroup | 🟡 | Requires cgroup/BPF attachment rights unavailable to hosted CI. |
| Read actual kernel BPF map counters | 🟡 | Depends on loading/attaching the program first. |
| Network-namespace/veth packet test | 🟡 | Namespace exists, but veth and BPF attachment need capabilities unavailable here. |

A green ordinary CI result must therefore **never** be reported as eBPF
attachment or packet-path validation. The privilege-dependent test remains
manual/self-hosted until a runner with the capabilities below is attached.

## Required privileged runner contract

A valid verification runner must provide all of the following:

1. Linux kernel with the BPF config options listed above.
2. Root, or effective `CAP_BPF` and `CAP_NET_ADMIN` in the relevant user and
   network namespaces.
3. Writable bpffs and cgroup v2 mount.
4. `iproute2`/`bpftool` or an equivalent maintained loader for inspection.
5. Permission to create a network namespace and a veth pair.
6. Permission to attach/detach XDP and sockops programs and read their actual
   maps.

See `docs/ebpf-verification-runbook.md` for the required real-kernel drill and
acceptance assertions. No Iranian ISP, DPI, latency, or blackout claim follows
from a local veth test.
