# Privileged eBPF/XDP verification runbook

**Status:** required manual/self-hosted validation; not executed by GitHub-hosted CI

This runbook is for a root-equivalent Linux runner meeting the contract in
`docs/ebpf-ci-constraints.md`. It produces evidence from real kernel BPF maps;
a userspace `HashMap`, a unit test, or an unprivileged CI log is not an
acceptable substitute.

> **Safety boundary:** Run only on a disposable host or VM. The test program can
> drop TCP RST packets whose source address is entered into its BPF map. Never
> run it on production traffic before an authorized change window and rollback
> plan.

## 1. Preconditions

```bash
set -euo pipefail
id -u                         # must print 0, or use a capability-equivalent service
uname -a
zcat /proc/config.gz | grep -E 'CONFIG_(BPF|BPF_SYSCALL|CGROUP_BPF|XDP_SOCKETS)=y'
mountpoint -q /sys/fs/bpf
mountpoint -q /sys/fs/cgroup
command -v ip
command -v bpftool
command -v clang
```

The run must stop if any check fails. Capture this output in the run record.

## 2. Compile the real XDP object

The current XDP source is `ebpf/xdp_rst_dropper.c`. Rebuild it on the target;
do not trust a prebuilt object copied from another architecture/kernel toolchain.

```bash
cd /path/to/aether-x-monorepo/ebpf
clang -O2 -g -target bpf -Wall -Werror \
  -I/usr/include/$(uname -m)-linux-gnu \
  -c xdp_rst_dropper.c -o /tmp/aether-xdp-rst.o
llvm-objdump -S /tmp/aether-xdp-rst.o | sed -n '1,160p'
```

## 3. Create an isolated veth packet path

```bash
ip netns add aether-xdp-a
ip netns add aether-xdp-b
ip link add veth-a type veth peer name veth-b
ip link set veth-a netns aether-xdp-a
ip link set veth-b netns aether-xdp-b
ip -n aether-xdp-a addr add 198.18.0.1/30 dev veth-a
ip -n aether-xdp-b addr add 198.18.0.2/30 dev veth-b
ip -n aether-xdp-a link set lo up
ip -n aether-xdp-b link set lo up
ip -n aether-xdp-a link set veth-a up
ip -n aether-xdp-b link set veth-b up
ip netns exec aether-xdp-a ping -c 1 -W 1 198.18.0.2
```

## 4. Attach the real program and identify its actual maps

```bash
ip netns exec aether-xdp-a \
  ip link set dev veth-a xdpgeneric obj /tmp/aether-xdp-rst.o sec xdp
ip netns exec aether-xdp-a ip -details link show dev veth-a
bpftool prog show
bpftool map show
```

Record the program ID and the map IDs for `dpi_sources` and `rst_drop_count`.
The process must fail if `ip -details link` does not report XDP attached.

## 5. Populate the real BPF map and exercise real packets

The IPv4 bytes below are `198.18.0.2`, the source sent from `aether-xdp-b`.
Replace `<DPI_MAP_ID>` and `<COUNTER_MAP_ID>` with the IDs found above.

```bash
bpftool map update id <DPI_MAP_ID> key hex c6 12 00 02 value hex 01
bpftool map lookup id <COUNTER_MAP_ID> key hex 00 00 00 00
```

Install `hping3` if it is absent, then send a real TCP RST from the peer
namespace toward the XDP ingress interface:

```bash
ip netns exec aether-xdp-b hping3 --rst -c 3 -p 443 -s 42424 198.18.0.1
sleep 1
bpftool map lookup id <COUNTER_MAP_ID> key hex 00 00 00 00
```

**Acceptance:** the actual `rst_drop_count` map value increases by at least
three. Save before/after output and `tcpdump -ni veth-a tcp` evidence showing
the traffic was attempted. Then remove the source key, repeat the packet send,
and assert the counter does not increment.

## 6. Sockops acceptance requirement

A real sockops test additionally requires a shipped `sockops` BPF object,
`BPF_MAP_TYPE_SOCKHASH`, an `sk_msg` redirect program, and cgroup attachment.
The current repository does **not** yet ship that real object/loader; do not
substitute `core-supervisor/src/sockops.rs` in-memory state for a kernel map.
When a real Aya sockops object is delivered, this runbook must be extended with:

1. `bpftool cgroup attach /sys/fs/cgroup sock_ops pinned ...`;
2. real TCP sockets in the two namespaces;
3. actual sockhash entries read through `bpftool map dump`;
4. traffic redirection observed by packet capture; and
5. actual map counter changes.

Until then, sockops is **🟡 NotConfigured**, not a tested eBPF path.

## 7. Cleanup and evidence bundle

```bash
ip netns exec aether-xdp-a ip link set dev veth-a xdp off || true
ip netns del aether-xdp-a || true
ip netns del aether-xdp-b || true
rm -f /tmp/aether-xdp-rst.o
```

Attach command transcript, kernel version/config, capability output, object
hash, program/map IDs, counter before/after values, packet capture summary, and
cleanup output to the deployment change record. A successful local veth drill
is not evidence of carrier filtering behavior, Iranian ISP reachability, or
blackout continuity.
