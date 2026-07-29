# Session cgroup + address firewall keying: design note

This started as a `SessionNFTSet=` feature request for systemd-logind and was
discussed with the `NFTSet=` author (Topi Miettinen,
[#22527](https://github.com/systemd/systemd/issues/22527),
[#29039](https://github.com/systemd/systemd/pull/29039)). His read was that a
standalone PAM module is the simpler home, so the design lands in pam_authnft
rather than systemd. This note is kept as the rationale, and the record of what
the logind route would and would not have bought. References read against
systemd `5578a22`; runtime observed on systemd 261, nftables 1.1.6.

## The problem

`NFTSet=` selects on a unit's cgroup id. For a session the useful key is the
pair (cgroup + the address the user logged in from). logind holds both halves,
the scope it creates and `remote_host`, but nothing exports the pair, and
`NFTSet=` cannot: it is applied by PID 1, which has no notion of a session or a
remote host, and it emits a single 8-byte scalar, so against a concatenated set
the kernel rejects it (`Failed to add NFT set entry: ... ignoring: Invalid
argument`).

## Why the PAM module, not logind

The original pitch was that logind should own this, on the argument that it
could insert the element before the session's first socket. That argument does
not hold: a PAM session module runs in `pam_open_session` before the shell, so
its element is in place before the first socket too; only an asynchronous bus
consumer lacks that timing. So ordering is not a reason to prefer logind.

The one real difference is cleanup. `NFTSet=` removes the element when the
control group or unit is removed; a PAM module removes on `close_session`, which
is not guaranteed to run (sshd killed, host crash). That matters for the address
design below, but it is work the module has to do rather than a reason to move
into systemd. Weighed against the cost of a systemd change, the module is the
simpler home.

## The design (in pam_authnft)

- **Parse the address, do not concatenate it with the cgroup id**, so it can be
  used with masks and ranges (geo blocking). This follows networkd's
  `address`/`prefix` set sources. The concatenation had one safety property the
  bare address loses: its cgroup-id half goes dead when the scope does, and
  kernfs ids are never reused, so a stale pair matches nothing. A stale bare
  address keeps matching new connections from it, so the module must bind
  removal to teardown (`close_session`, with the element timeout as the
  backstop). Where the session-to-its-own-address pairing is wanted, a concat
  set can sit alongside.
- **Reuse the `NFTSet=` syntax**, the four-part `source:family:table:set`
  (source is `cgroup`/`user`/`group` for units, `address`/`prefix`/`ifindex`
  for networkd); the session address is a new source type.
- **An address bound for a `flags interval` set needs an explicit `/32` or
  `/128`**; a bare address there is a sharp edge (unbounded range). Mask it, or
  refuse interval sets for the address source.
- **Expose more PAM data**, such as `PAM_SERVICE`, alongside the address.

## Scope and caveats

- It keys traffic on sockets the session creates, not the login connection.
  `PAM_RHOST` is only known after the connection is accepted, so this cannot
  gate login, only what the session reaches afterward. A socket's cgroup is
  fixed at creation, so the SSH connection keeps sshd's cgroup and is handled by
  a `ct state established,related accept` rule ahead of the session match.
- It does not confine the user: their own `user@<UID>.service`, and anything
  under `systemd-run --user`, sits outside the set by construction.
- `remote_host` is the raw `PAM_RHOST`. It may be a hostname, IPv6 with a scope
  id, or v4-mapped, and is only as trustworthy as the PAM service that set it,
  so the guarantee is "the address the service attested". It needs parsing and a
  skip-or-cgroup-only fallback.
- If the administrator's set does not exist yet when a session starts (early
  boot, a rescue shell, after a flush), the insert fails. Log and continue, so
  keying is conditional on the set being present.
