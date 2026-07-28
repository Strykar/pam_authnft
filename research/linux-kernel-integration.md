# 11 — What authpf's core feature would need from the Linux kernel

**Type:** design study, continuation of [linux-prior-art.md](linux-prior-art.md)
**State:** EXECUTED on Linux 6.18.40-1-lts and, for §11 and the corrected half of
§1, 6.18.40-2-lts, nftables v1.1.6. Every claim marked [exec] was run in an
isolated netns or userns on this host; the probe scripts are in
[probes/](probes/). Claims marked [src] are read out of `~/src/openbsd-src` or
`~/arch_packages/github/linux`. §12 lists what is still unverified. Nothing sent
anywhere.

One claim in §1 was wrong in the first version and is corrected in place: the
`pfctl -k` transliteration does revoke. §11 says how that happened.

## The question

Assume netfilter agreed to carry an `authnft`. What would it need the *kernel*
to provide that Linux does not already have?

Short answer: much less than the BSD design suggests, and none of the pieces
authpf leans on hardest. Decomposing authpf into its five mechanisms, three need
nothing new, one dissolves once you read the nftables evaluation model
correctly, and only the fifth is a real gap.

| authpf mechanism | Linux status |
| --- | --- |
| bind an address to an authenticated session | already better (concat sets carry IP + MAC) [exec] |
| inject per-user rules at a fixed ruleset point (anchors) | present, different semantics (see §2) |
| revoke at session end | present, and instant without state surgery (§1) [exec] |
| kill live flows on revoke (`DIOCKILLSTATES`) | **not needed at all** (§1) [exec] |
| survive the session dying uncleanly | the one real gap (§3, §4) |

## 1. The state-kill requirement dissolves

authpf calls `DIOCKILLSTATES` twice at logout, once for states from the user's
address and once for states to it, host-masked
([authpf.c:899-933][authpf-kill]). It has to. In pf, `pf_test_rule()` runs only
in the `else if (st == NULL)` branch after the state lookup misses
([pf.c:8547-8553][pf-bypass]) [src]. A packet matching an existing state never
reaches the ruleset, so deleting the pass rule does nothing to flows already
running, and the code comment says exactly that: without the kill, "luser
sessions" outlast their ssh session.

nftables has no such bypass. Every packet walks the chains. So whether
revocation is instant depends only on whether the ruleset consults the
authorization set on every packet. Four arms against one live TCP connection,
same netns, element removed mid-flow [exec]:

| ruleset | after removing the element |
| --- | --- |
| `ct state established,related accept` then `ip saddr @allow ct state new accept` | **traffic continues** |
| `ip saddr @allow accept` | cut immediately |
| `ct original ip saddr @allow accept` | cut immediately |
| `ct original ip saddr @allow accept` then `ct state established,related accept` | **traffic continues** |

Arm 1 is authpf's shape and it reproduces authpf's problem. Arm 3 is the
idiomatic answer: matching the conntrack tuple's original source covers both
directions with one rule and still re-evaluates per packet. Arm 4 is the trap.
Ordering does not save you. Any unconditional state-based accept that does not
itself consult the set defeats revocation, and `ct state established,related
accept` is the single most copy-pasted line in Linux firewalling.

Two consequences.

First, the kernel ask disappears and is replaced by a ruleset-authoring
constraint. That makes it a tooling problem: an authnft has to own the shape of
the authorization rules rather than let an admin hand-write them next to a
stock ruleset.

Second, the obvious transliteration of `pfctl -k` does work. An earlier version
of this note said it did not, on the strength of a substitute experiment, and
that was wrong. `conntrack -D -s <ip>` cut the arm 1 flow immediately, with
`nf_conntrack_tcp_loose` at its default 1, and again with it at 0 [exec].

Which state the post-flush packet carries decides why, and the two settings
differ. Measured with policy accept and counters that consult no set, so the
counters report state and nothing else [exec]:

| tcp_loose | the flow's next packet after the flush |
| --- | --- |
| 1 (default) | `ct state new`, invalid=0 |
| 0 | `ct state invalid`, no entry created |

With the default, a flush leaves the flow with no entry, its next packet creates
one, and the packet that creates an entry arrives as `new` whatever TCP state the
entry is given. It is therefore re-gated on the authorization set, which no
longer holds the address. With `tcp_loose=0` no entry is created and the packets
are invalid instead, so a ruleset that drops invalid traffic cuts the flow for a
different reason. Both revoke. Only the mechanism changes.

The substitute experiment had shown exactly this and was misread: new=1 was the
packet that created the entry and established=1 was its reply, which was read as
"the flow is back on the established fast path".

One cost worth knowing: `conntrack -D -s <ip>` is a userspace dump-and-delete
loop, not a kernel-side filtered flush. Over four injected entries, two sharing
the source address, strace showed one `IPCTNL_MSG_CT_GET`, four entries dumped
back, and two targeted `IPCTNL_MSG_CT_DELETE` [exec]. Deauthorizing one user
dumps the whole conntrack table, which on a busy gateway is the opposite of
cheap. That is one more reason to prefer arm 3, where revocation needs no
conntrack surgery at all.

Also worth knowing: revocation blackholes rather than kills. The connection
stalls, TCP retransmits, and re-adding the element resumes the same stream with
the buffered data intact [exec]. pf's state kill destroys the flow. If an
authnft wants "dead now" rather than "blocked now", that is a separate ask and
nothing in nftables provides it.

## 2. Anchors map to owned tables, but not for allow rules

`flags owner` is a genuinely better primitive than a pf anchor. Verified [exec]:

- the table is removed when the creating netlink socket closes
- `flags persist` keeps it, and the orphan can be adopted by a new owner
- a foreign process gets EPERM adding a chain to it or deleting it, even as root
- a foreign `nft flush ruleset` destroys other tables and **skips the owned one**

The last point matters operationally. An admin reloading `/etc/nftables.conf`,
which conventionally starts with `flush ruleset`, cannot wipe live session
state by accident.

But the natural mapping of "one anchor per session" to "one owned table per
session" fails, because a verdict in one table is not authoritative across
tables. Two tables at the same hook, priorities -100 and 100, the first
accepting icmp and the second dropping it: both counters incremented and the
ping failed [exec]. Accept only ends evaluation of that chain; the next base
chain still runs. So a per-session owned table can deny, never grant. authpf's
model is grant.

You can launder the decision through a mark and let the admin's table act on
it, but then every session registers its own base chain, and base chains at a
hook are walked linearly per packet. That does not scale past a few dozen
sessions. So the authorization has to live in one shared set, which is what
pam_authnft does, and shared-set elements have no owner. Cleanup is back in
userspace, which is where authpf's leak lives.

## 3. What is actually missing: element lifetime

The nftables set-element flag space has room for exactly this and does not use
it. `enum nft_set_elem_flags` defines only `INTERVAL_END` and `CATCHALL`
(`/usr/include/linux/netfilter/nf_tables.h:434`), while the table-level
precedent has existed since Pablo's 2021 owner work. The generalization writes
itself: elements added over this socket are removed when it closes.

The honest counter-argument is that timeouts already cover it, and the probe
data supports the counter. Expiry is enforced, and GC reaped a 2s-timeout
element about 2s after insertion [exec]. So this is a convenience, not a
capability gap, and it should be argued on "every daemon that adds elements
reimplements crash-resync" (fail2ban, captive portals, DHCP allowlists, VPN
session managers) rather than on impossibility.

One related negative worth recording: element expiry is invisible on the
notification channel. `nft monitor` captured the adds and produced no
delete-element event when the element was reaped, for both a plain `flags
timeout` set and a `flags dynamic,timeout` set, over a 9s window [exec]. A
daemon cannot learn that an authorization lapsed by watching netlink. It has to
poll.

## 4. Let the kernel notice the session died

(This was ranked strongest when the note was written. §8 demotes it, because
systemd already removes the element when the cgroup dies. The mechanism below is
still the only one that closes the case where the manager itself dies.)

`cgroup_lifetime_notifier` exists in 6.18, with `enum cgroup_lifetime_events {
CGROUP_LIFETIME_ONLINE, CGROUP_LIFETIME_OFFLINE }` in vmlinux BTF and the
symbol in kallsyms [exec]. pam_authnft already keys its elements on the cgroup
id of a systemd transient scope. Put those together and nf_tables could drop
cgroup-keyed elements when the cgroup goes OFFLINE.

That is the design authpf cannot have. On BSD there is no kernel object whose
lifetime is the login session, so cleanup must be a userspace promise. On Linux
the session *is* a kernel object. Revocation becomes kernel-driven: session
dies, cgroup dies, element vanishes. No heartbeat, no reaper, no dependency on
`close_session` ever running, and the leak class disappears rather than being
mitigated.

Cost: a real kernel patch. Registering the notifier is trivial; finding the
affected elements is not, since it means either walking every set or keeping a
reverse index from cgroup id to element. Probably needs a per-set opt-in flag.

This also closes pam_authnft's own K2 item as a side effect.

## 5. A small userspace bug found on the way, worth reporting regardless

nft prints a cgroupv2 element it cannot parse back. Full reproducer [exec]:

```sh
mkdir /sys/fs/cgroup/authnft_probe_scope          # inode 50834
nft add set ip t cg '{ typeof socket cgroupv2 level 0; flags timeout; }'
nft add element ip t cg '{ "authnft_probe_scope" }'   # ok
rmdir /sys/fs/cgroup/authnft_probe_scope             # session scope reaped
nft list set ip t cg                                 # elements = { 50834 }
nft delete element ip t cg '{ "authnft_probe_scope" }'
    Error: cgroupv2 path fails: No such file or directory
nft destroy element ip t cg '{ "authnft_probe_scope" }'
    Error: cgroupv2 path fails: No such file or directory
nft add element ip t cg '{ 50834 }'
    Error: cgroupv2 path fails: No such file or directory
nft flush set ip t cg                                # succeeds
```

The listing renders the raw id once the path is gone, the input grammar refuses
a numeric key, and `destroy` does not help because the failure is in userspace
key parsing before netlink is touched. So the element cannot be addressed by
key at all. The only escape is flushing or deleting the containing set.

pam_authnft's TODO says of this "no fix available without nftables API
changes". That is right about the cause and pessimistic about the size: the fix
is accepting on input what the listing already emits, which is userspace-only
and touches a datatype whose listing path has had recent attention
("datatype: skip cgroupv2 rootfs in listing"). No UAPI change. Highest odds of
merge of anything in this note.

Note that pam_authnft is not currently exposed to this, because it deletes the
whole per-session set at logout rather than the element. A shared-set design
would be stuck.

## 6. What needs nothing from anybody

- **Address binding.** `ip saddr . ether saddr` concat sets work, including in
  the forward hook, with per-element timeouts [exec]. authpf authorizes an IP
  and nothing else, so this is strictly stronger for the gateway case.
- **Single session per user.** `nft create element` returns EEXIST on a
  duplicate while `add` silently overwrites [exec]. The set is the mutex,
  kernel-side and atomic. authpf uses a pidfile.
- **Per-user rule text.** libnftables is a real library with a stable entry
  point and a JSON interface. The entire problem blocking the FreeBSD work,
  a parser trapped inside the CLI binary, does not exist here.
- **Audit.** nf_tables emits AUDIT_NETFILTER_CFG for ruleset changes.

## 7. The privilege lesson transfers, inverted

authpf installs `BINOWN=root BINGRP=authpf BINMODE=6555` [src], so it is a
setuid-root binary that is an unprivileged user's login shell. The FreeBSD
parse.y audit from this project (8.4k lines, 154 exit sites, 113 ENOMEM paths)
is an audit of a parser sitting on the far side of that boundary.

Linux removes the boundary rather than hardening it: a PAM module runs inside
sshd's already-privileged monitor, so there is no setuid binary and no user
shell. But the same temptation returns in a new place, because libnftables
makes executing admin-supplied rule text trivial, and pam_authnft does exactly
that, mitigated by root-ownership checks on the fragment plus seccomp on the
child that loads it. The rule the parse.y audit earns is unchanged: the
privileged component should accept a fixed, tiny message vocabulary, and rule
text is not one.

## 8. systemd already ships the userspace half

`NFTSet=family:table:set` in `systemd.resource-control(5)`, since systemd v255,
inserts a unit's cgroup id, uid or gid into a named nftables set when the cgroup
is realized and removes it when the cgroup or unit goes away. The man page's own
example is pam_authnft's mechanism:

```nft
NFTSet=cgroup:inet:filter:my_service

table inet filter {
        set my_service { type cgroupsv2 }
        chain x {
                socket cgroupv2 level 2 @my_service accept
                drop
        }
}
```

Two sentences of that documentation carry most of the weight. "systemd only
inserts elements to (or removes from) the sets, so the related NFT rules, tables
and sets must be prepared elsewhere in advance" is the same division of labour §1
argues an authnft must enforce anyway. And "if the firewall rules are reinstalled
so that the contents of NFT sets are destroyed, command `systemctl daemon-reload`
can be used to refill the sets" is a documented resync path, which is the answer
Pablo would give to §3.

Not just documented, executed. A transient unit carrying the property had its
element inserted while it ran and removed when it stopped, and the listing
rendered it as a path because the cgroup still existed [exec]. It uses
`sd_nfnl_socket_open()` and hand-rolls the netlink message, with no libnftnl or
libmnl linkage, so ids go in numerically [src].

What it does not do, and therefore what still justifies a PAM module: it inserts
exactly one 8-byte scalar, so it cannot express a concatenated `cgroup . ip saddr`
element and cannot bind a session to the address the user authenticated from
(`src/core/cgroup.c`) [src]:

```c
uint64_t element = crt->cgroup_id;

r = nft_set_element_modify_any(u->manager->nfnl, add, nft_set->nfproto,
                               nft_set->table, nft_set->set,
                               &element, sizeof(element));
```

Pointed at a set declared `typeof socket cgroupv2 level 0 . ip saddr`, the set
stays empty and the kernel rejects the key length [exec]:

```text
Failed to add NFT set entry: family inet, table authnft_audit, set sd_concat,
cgroup 16415, ignoring: Invalid argument
```

Splitting that into two sets checked by one rule is strictly weaker on a
multi-user host, because it stops matching the pair.

Two smaller findings. The failure mode is ignored but **not** silent, contrary to
what an earlier reading of the man page's "failures will be ignored" suggested: a
missing set produces a `log_warning_errno()` line and the unit still starts
[exec]. And `if (!MANAGER_IS_SYSTEM(u->manager)) return;` sits at the top of the
same function [src], which is the code behind the man page's note that this does
not work in per-user service manager instances.

The full write-up, including what NFTSet is genuinely better at, is
[../docs/ALTERNATIVES.md](../docs/ALTERNATIVES.md).

## 9. Ranked asks, after systemd and a no-daemon constraint

Ranking with two constraints applied: no new long-running daemon, and §8.

1. **nft: accept a numeric cgroupv2 id on input** (§5). Strengthened. Userspace
   only, small, and it now has a motivation that never mentions authpf, because
   systemd writes numeric cgroup ids into sets over netlink and `nft` then
   refuses its own printed output as input. Upstream already knows the round trip
   is broken: `tests/shell/testcases/packetpath/cgroupv2` works around it in
   `cleanup()` with the comment "nft list is broken after cgroupv2 removal, as
   nft can't find the human-readable names anymore".
2. **nf_tables: cgroup-lifetime-driven element removal** (§4). Weakened, not
   dead. systemd already removes the element when the cgroup dies, so the kernel
   notifier now only covers the case where the manager itself dies, or where a
   non-systemd agent inserted the element. Stop calling it the strongest.
3. **nf_tables: element-level socket ownership** (§3). Dead. It only works while
   some process holds the owning netlink socket for the session's lifetime, which
   is a daemon, and the problem it solves is the one systemd answers with
   `systemctl daemon-reload`.

Nothing here needs `DIOCKILLSTATES`'s equivalent, and asking for one would be
asking for the wrong thing (§1).

## 10. Venue

The 2003 rejection stands on the record ([linux-prior-art.md](linux-prior-art.md)),
and netfilter's userspace repos (nft, libnftnl, conntrack-tools, ulogd) have no
shape that a PAM module or a login shell fits. The strategically better split
is the one that is already true: the tool stays out of tree, and the two or
three netfilter patches go up on their own merits. None of them requires
mentioning authpf. Bundling them into a "port authpf to Linux" pitch is what
re-opens the argument Harald Welte closed, and the WireGuard answer is stronger
now than it was then.

## 11. The two open questions, closed

Both were blocked by one environmental fault, not by anything about netfilter.
The running kernel's `/lib/modules` tree had been removed by a package upgrade,
so no netfilter module could autoload. `nf_conntrack_netlink` was missing, which
is why `conntrack(8)` failed with `-EINVAL` on nlmsg_type `0x101`, and
`nft_socket` was missing, which is why every rule using the `socket` expression
returned ENOENT. An ENOENT on rule add is indistinguishable by eye from a hook
rejection, and the first reading of that probe was wrong on exactly that point.
Both were re-run after a reboot onto a kernel whose modules exist. Results that
used already-loaded modules, including every `ct` arm in §1, were unaffected.

**`conntrack -D` revokes, and is a dump-and-delete loop.** Folded into §1, which
it corrects.

**`socket cgroupv2` is refused in the forward hook, not merely unmatched.** The
kernel returns EOPNOTSUPP at rule-add time. `nft_socket_validate()` passes
`(1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_LOCAL_OUT)`
to `nft_chain_validate_hooks()`, and forward is not in that mask
(`net/netfilter/nft_socket.c:262-265`) [src]. Executed: rejected in forward,
accepted in prerouting, input and output, with the mandatory positive control in
the input hook matching a local socket in the target cgroup, 4 packets against a
control rule's 5 [exec].

That is a firmer boundary than reasoning gave. Any socket-based session binding,
pam_authnft's included, is confined to traffic delivered to or originated by a
local socket. authpf's own use case, a gateway forwarding a remote client's
traffic, cannot use this expression at all, and no amount of ruleset authoring
works around a hook mask. For the gateway case the only handles are the ones in
§6, the address and the MAC.

## 12. Still not verified

- Prior art for the §3 and §4 asks. The `lei` negatives recorded earlier are
  worthless: `lei q` here wraps a multi-word query in quotes, making it a phrase
  search, and `l:` list filters hang rather than return. The method that works is
  a POST to lore, `curl -d '' 'https://lore.kernel.org/all/?x=m&t=1&q=...'`, which
  also sidesteps Anubis. That method was used for the §5 ask and found no
  duplicate; §3 and §4 have not been re-checked with it.
- `bugzilla.netfilter.org` for any of the asks. Anubis-walled from this host.
- Per-session base chain scaling (§2) is asserted from the linear hook walk,
  not measured.

[authpf-kill]: https://cvsweb.openbsd.org/src/usr.sbin/authpf/authpf.c
[pf-bypass]: https://cvsweb.openbsd.org/src/sys/net/pf.c
