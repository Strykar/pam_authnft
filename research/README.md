# Research

Background work that informs the module but is not part of it. Nothing here is
shipped, installed, or run by CI. The user-facing conclusions live in
[../docs/ALTERNATIVES.md](../docs/ALTERNATIVES.md); this directory holds the
evidence behind them.

| Path | What it is |
| --- | --- |
| [linux-kernel-integration.md](linux-kernel-integration.md) | What authpf's core feature would need from the Linux kernel, and what Linux already provides. Thirteen sections, every claim marked `[exec]`, `[src]`, or listed in §12 as unverified |
| [packet-flow-audit.md](packet-flow-audit.md) | What the wire does with the module's rules, allow and deny both, across session open and close and every placement an admin can pick for the site's default-deny. The evidence behind issues #103 and #105 |
| [packet-flow-testbed/](packet-flow-testbed/) | Run record and `nft monitor trace` captures for the cases in that audit |
| [probes/](probes/) | The scripts behind every `[exec]` claim |

## Why this is here rather than in docs/

`docs/` is the user-facing set, indexed and held to the documentation checklist.
This is working material: it argues, it records dead ends, and two of its claims
were wrong on the first pass and are corrected in place with an explanation of
how the mistake happened. That is useful to keep and wrong to ship.

## Running the probes

They need a Linux host with nftables. The first two need no privileges
(`unshare -rn` gives an isolated user and network namespace); the rest need root
but confine themselves to throwaway tables, network namespaces, and cgroups they
create and remove.

| script | how to run |
| --- | --- |
| `linux-nft-primitives-1.sh` | `unshare -rn sh <it>` |
| `linux-nft-primitives-2.sh` | `unshare -rn sh <it>` |
| `linux-revocation-matrix.sh` | `ip netns exec <ns> bash <it>` |
| `linux-owner-and-flush.sh` | `ip netns exec <ns> bash <it>` |
| `linux-postflush-ctstate.sh` | `ip netns exec <ns> bash <it>` |
| `linux-cgroup-elem-gap.sh` | `sudo bash <it>` |
| `linux-socket-cgroup-hooks.sh` | `sudo bash <it>` |

Three traps, all of which produced a wrong answer at least once here.

**Check the running kernel's module tree exists before believing anything.** A
kernel package upgrade without a reboot removes `/lib/modules/$(uname -r)`, after
which no netfilter module can autoload. That made `conntrack(8)` fail outright
and made every rule using the `socket` expression return ENOENT, which reads
exactly like a hook rejection and was diagnosed as one.
`linux-socket-cgroup-hooks.sh` now refuses to run rather than produce an
artefact; the others do not check.

**`ip netns exec` remounts `/sys`**, so cgroupv2 paths cannot resolve inside it.
Run anything cgroup-keyed on the host, or enter the namespace with
`nsenter --net=/run/netns/<ns>`, which leaves mounts alone.

**`nft reset counters` only resets named counter objects**, not the anonymous
counters inside rules, so a probe that tries to zero rule counters mid-run is
reading cumulative totals.
