# Rejected alternatives

Why pam_authnft exists rather than a configuration of something that already
ships. Each entry states what the alternative does, what it cannot do, and how
that was established. Claims marked **[exec]** were run; claims marked **[src]**
cite a source tree read locally.

Audited 2026-07-26 against systemd 261 (Arch `261.2-1-arch`), Linux 6.18.40-2-lts,
nftables v1.1.6.

## systemd `NFTSet=`

`systemd.resource-control(5)` has carried `NFTSet=family:table:set` since v255.
It inserts a unit's cgroup id, uid or gid into a named nftables set when the
cgroup is realized and removes it when the cgroup or unit goes away. The man
page's own example is the mechanism pam_authnft uses:

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

This is the closest thing in the base system, it is real, and on this host it
works. A transient unit started with that property had its element inserted while
it ran and removed when it stopped **[exec]**. So the question is not whether it
works. The question is whether it can express what pam_authnft expresses.

### It cannot bind a session to the address it authenticated from

This is the load-bearing reason.

pam_authnft's element is a concatenation, `cgroup . ip saddr`, so a session
matches only from the address the user actually logged in from. `NFTSet=` inserts
exactly one 8-byte scalar and has no way to say anything else
(`src/core/cgroup.c`) **[src]**:

```c
uint64_t element = crt->cgroup_id;

r = nft_set_element_modify_any(u->manager->nfnl, add, nft_set->nfproto,
                               nft_set->table, nft_set->set,
                               &element, sizeof(element));
```

Pointing `NFTSet=` at a set declared `typeof socket cgroupv2 level 0 . ip saddr`
leaves the set empty. systemd tries, the kernel rejects the wrong key length, and
systemd logs and carries on **[exec]**:

```text
Failed to add NFT set entry: family inet, table authnft_audit, set sd_concat,
cgroup 16415, ignoring: Invalid argument
```

Splitting it into two sets checked by one rule is not equivalent. On a
multi-user host `socket cgroupv2 @sessions ip saddr @addresses accept` passes
alice's session presenting bob's address, because nothing ties the pair. The
whole point of the concatenation is that it does.

### Everything else is a consequence of it being a unit property

- **Granularity.** `NFTSet=` is set on a unit. A login session is a transient
  scope that logind creates, and logind has no setting that would attach the
  property to it, so the reachable granularity is a drop-in on the user slice,
  which is per user and not per session. pam_authnft keys on the session scope.
- **System manager only.** `if (!MANAGER_IS_SYSTEM(u->manager)) return;`
  in the same function **[src]**, matching the man page's note that this is
  unsupported in per-user service manager instances.
- **No per-user policy.** `NFTSet=` conveys membership. It has no notion of a
  per-user rule fragment, so any per-user differentiation has to be pre-written
  into the admin's static ruleset. That is arguably the safer design and is worth
  saying plainly, but it is not the same feature.
- **Failures are ignored, not fatal.** The unit still starts if the set is
  missing; systemd logs a warning and continues **[exec]**. For an allow-listing
  ruleset this fails closed for the user, but the admin's only signal is a log
  line.

### What it is genuinely better at

Worth stating, because it bounds what pam_authnft should claim. `NFTSet=` needs
no PAM module, no fragment parsing, and no privileged helper: the manager that
already owns the cgroup lifecycle also owns the set membership. Where the policy
can be expressed as "traffic from this unit's cgroup, or this uid" with no
address binding and no per-user rules, `NFTSet=` is the correct answer and
pam_authnft is unnecessary weight.

### Honest positioning

pam_authnft is not "the authpf model for Linux" as against a base system that
lacks it. The accurate description is **NFTSet plus the client address, keyed on
the session rather than the unit, with per-user fragments**. A reviewer who knows
systemd will ask this, and the answer should be the address binding, not novelty.

## `socket cgroupv2` for a forwarding gateway

Not applicable, and this is a kernel-enforced limit rather than a matching
accident. `nft_socket_validate()` passes
`(1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_LOCAL_OUT)`
to `nft_chain_validate_hooks()`, so the forward hook is not in the mask
(`net/netfilter/nft_socket.c:262-265`) **[src]**. A rule using the expression in
a forward chain is refused at load time with EOPNOTSUPP; the same rule is
accepted in prerouting, input and output, and a positive control in the input
hook matched a local socket in the target cgroup **[exec]**.

So any socket-based session binding, pam_authnft's included, is confined to
traffic delivered to or originated by a local socket. Gating a *remote* client's
forwarded traffic, which is what OpenBSD's authpf does, cannot use this
expression at all, and no ruleset authoring works around a hook mask. That case
needs address and MAC matching instead, and is out of scope for this module.

## Provenance

The full reasoning is in
[../research/linux-kernel-integration.md](../research/linux-kernel-integration.md),
with the probe scripts under [../research/probes/](../research/probes/). Every
claim above can be re-run from there.
