# RFC: `SessionNFTSet=` for systemd-logind

Extend `NFTSet=` to login sessions: on session start insert (session cgroup +
login address) into a firewall set, remove it on stop. Membership only, the
`NFTSet=` contract from [#22527](https://github.com/systemd/systemd/issues/22527):
systemd manages the set, the administrator owns the rules. References read
against systemd `5578a22`; runtime observed on systemd 261, nftables 1.1.6.

## Problem

`NFTSet=` selects on a unit's cgroup id. For a session the useful key is the
pair (cgroup + the address the user logged in from). logind has both halves,
the scope it creates and `remote_host`, but nothing exports the pair.

`NFTSet=` can't, for two structural reasons:

1. It is applied by PID 1, which has no notion of a session or a remote host.
2. It emits one 8-byte scalar. Against a concatenated set the kernel rejects it:

   ```
   Failed to add NFT set entry: ... cgroup 16415, ignoring: Invalid argument
   ```

   (`NFTSet=cgroup:inet:t:s` on a transient unit, set keyed
   `socket cgroupv2 level 0 . ip saddr`, systemd 261.)

Out of tree, both options fall short: a PAM module (what I run) duplicates
logind's scope handling and parses administrator nftables fragments in a
privileged context, a security surface this design removes; a daemon on
logind's bus only trails its published state; and neither keys the element
before the session's first socket, which is the reason to put this in logind.

## Solution

```
# /etc/systemd/logind.conf
SessionNFTSet=inet:filter:sessions
```

Fragment showing the match, not a drop-in policy:

```
table inet filter {
    set sessions { typeof socket cgroupv2 level 0 . ip saddr }
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        socket cgroupv2 level 3 . ip saddr @sessions accept
    }
}
```

The `ct` accept is required. A socket's cgroup is fixed at creation
(`sk->sk_cgrp_data`), so the SSH connection that carried the login was made in
`sshd.service`'s cgroup and never matches `@sessions`: the set covers sockets
the session opens after it starts, not the login connection itself. Level 3 is
the session scope (`user.slice/user-<UID>.slice/session-<N>.scope`); delegated
sub-cgroups still resolve to it. nft normalises the set's `typeof` level to 0 on
output (nftables 1.1.6), so only the rule's level matters.

This keys traffic on sockets the session creates. It does not confine the user:
their own `user@<UID>.service`, and anything they start with `systemd-run --user`,
sits outside the set by construction.

## Ordering: why logind, not a daemon

logind defers the `CreateSession` reply, over varlink (the default since
[#35264](https://github.com/systemd/systemd/pull/35264)) or D-Bus, until the
scope job completes: it holds `Session.create_link` or `create_message` and
answers from `session_send_create_reply`, which is gated by `session_job_pending`
and replies over whichever transport created the session. Inserting the element
on that same edge, before the reply, makes it exist before
`pam_sm_open_session()` returns, before the user's shell or services run. A
daemon on `SessionNew` receives the signal asynchronously and cannot block the
reply, so nothing sequences its insert before the session's first socket.

## Feasible with what exists

- `nft_set_element_modify_any()` (`src/shared/firewall-util.c`, libshared, which
  logind links) is generic over the key buffer.
- `path_to_handle_u64()` (a `static inline` in `src/basic/mountpoint-util.h`,
  libbasic) gives the cgroup id; logind can call it directly.
- Scope lifecycle is already tracked (`SESSION_OPENING`, `SESSION_CLOSING`).

No PID 1 change.

## Open questions

- **`remote_host` is the raw `PAM_RHOST`.** It may be a hostname, IPv6 with a
  scope id, or v4-mapped, and it is only as trustworthy as the PAM service that
  set it, so the guarantee is "the address the service attested". Needs parsing
  and a skip-or-cgroup-only fallback.
- **Insert failure.** A session that starts before the ruleset is loaded (a
  rescue shell, boot misordering, or after an admin flush) hits a failed insert.
  Ordering the ruleset unit early shrinks the window but cannot close it, so a
  stance is needed regardless: log-and-continue like `NFTSet=`, which makes the
  ordering guarantee conditional on the set being present.
- **Element lifecycle.** A ruleset reload flushes the elements; logind restart
  and `KillUserProcesses=no` lingering need a defined stance. `NFTSet=`'s is the
  starting point.
- **Level coupling.** The level the admin writes ties the ruleset to systemd's
  slice layout; document it.
- **Config surface.** `SessionNFTSet=` is global; restricting by session class
  may need syntax room.

## Alternatives

- **`IPAddressAllow=` on the scope** (logind can set scope properties): native,
  but a blunt per-unit allowlist. It cannot gate a port or compose with the
  admin's ruleset. #22527 built `NFTSet=` for exactly this reason.
- **External daemon on logind's bus:** works, but loses the ordering guarantee.
- **`NFTSet=` on the scope, or a concatenated `NFTSet=`:** still PID 1, still
  cgroup-only or wrong layer.

Happy to implement, or to be told the layering is wrong.
