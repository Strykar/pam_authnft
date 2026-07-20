# pam_authnft

[![build](https://github.com/Strykar/pam_authnft/actions/workflows/build.yml/badge.svg)](https://github.com/Strykar/pam_authnft/actions/workflows/build.yml)
[![CIFuzz](https://github.com/Strykar/pam_authnft/actions/workflows/cifuzz.yml/badge.svg)](https://github.com/Strykar/pam_authnft/actions/workflows/cifuzz.yml)
[![cppcheck](https://github.com/Strykar/pam_authnft/actions/workflows/cppcheck.yml/badge.svg)](https://github.com/Strykar/pam_authnft/actions/workflows/cppcheck.yml)
[![CodeQL](https://github.com/Strykar/pam_authnft/actions/workflows/codeql.yml/badge.svg)](https://github.com/Strykar/pam_authnft/actions/workflows/codeql.yml)
[![sanitizers](https://github.com/Strykar/pam_authnft/actions/workflows/sanitizers.yml/badge.svg)](https://github.com/Strykar/pam_authnft/actions/workflows/sanitizers.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12496/badge?v=passing)](https://www.bestpractices.dev/projects/12496)
[![Coverity Scan](https://scan.coverity.com/projects/pam_authnft/badge.svg)](https://scan.coverity.com/projects/pam_authnft)
[![Language: C](https://img.shields.io/badge/language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![License: GPL v2+](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](LICENSE)

Linux has no built-in way to bind packet filter rules to an authenticated
user session and revoke them at logout. pam_authnft fills that gap: it
loads nftables rules when a PAM session opens and removes them when it
closes. If `close_session` never runs (daemon crash, OOM kill, kernel
panic, hard reset), the session's set element carries a 24-hour timeout
and stops matching traffic within a day. The per-session chain, sets and
jump rule have no timeout of their own; they persist until a later
login's PID recycles onto the leaked names, which trips the self-heal at
`open_session`, or until an administrator removes them by hand.

OpenBSD's authpf has had this for years: named anchors loaded per
session via pfctl and torn down when the session ends. authnft brings
the same model to Linux, as a PAM module. Named nftables sets stand in
for the anchors, and the cgroupv2 inode of a systemd transient scope
replaces the authenticated shell as the session identity.

No dedicated shell, no setuid binary, no kernel patches.

<p align="center">
  <img src="docs/mascot.svg" alt="pam_authnft mascot" width="200">
</p>

## What a session looks like

A session's entire runtime footprint is ordinary nftables state,
inspectable with standard `nft` tooling:

```
# nft list table inet authnft
table inet authnft {
    set session_alice_1127936_v4 {
        typeof socket cgroupv2 level 0 . ip saddr
        flags timeout
        elements = { "authnft.slice/authnft-alice-1127936.scope" . 192.0.2.1
                     timeout 1d expires 23h55m56s comment "alice (PID:1127936)" }
    }

    set session_alice_1127936_v6 {
        typeof socket cgroupv2 level 0 . ip6 saddr
        flags timeout
    }

    set session_alice_1127936_cg {
        typeof socket cgroupv2 level 0
        flags timeout
    }

    chain filter {
        type filter hook input priority filter - 1; policy accept;
        ct state established,related accept
        jump session_alice_1127936
    }

    chain session_alice_1127936 {
        socket cgroupv2 level 2 . ip saddr @session_alice_1127936_v4 accept
    }
}
```

The quoted path is the session's cgroupv2 scope under `authnft.slice`;
the kernel resolves it to an inode when the element is inserted. When a
packet is classified, `socket cgroupv2 level 2` reads the socket's
originating cgroup and matches it against the set. That binds the rule
to the session without referencing PIDs, UIDs or usernames. The 24-hour
timeout is a safety net; explicit deletion at logout is the primary
cleanup.

See [docs/CONCEPTS.md](docs/CONCEPTS.md) for how it works and
[docs/ADMIN_GUIDE.md](docs/ADMIN_GUIDE.md) for installation and
configuration.

## Limitations

- Needs the cgroupv2 unified hierarchy. Hybrid setups are untested.
- Requires systemd. Other init systems are not supported.
- Syntax errors in a fragment are caught at load time and logged.
  Semantic mistakes, rules that parse but do the wrong thing, are the
  administrator's responsibility.
- If cleanup fails at logout, say because nftables is unavailable, the
  session's set element expires on its own after 24 hours. Leftover
  session JSON files are removed after 7 days by systemd-tmpfiles.
- The match only applies to sockets created inside the session. A
  socket that existed before the session opened, such as the SSH
  control connection, keeps the cgroup it was created in and is never
  matched. The module handles that traffic by adding `ct state
  established,related accept` to the shared `filter` chain.
- Fragments may `include` other files, but pam_authnft only checks
  ownership and mode on the top-level fragment. Keeping every included
  file root-owned and not world-writable is the administrator's job.

## Documentation and contributing

All documentation is indexed in [docs/](docs/); see the
[roadmap](docs/ROADMAP.md) and [CONTRIBUTING.txt](docs/CONTRIBUTING.txt).
Report security issues privately via
[GitHub Security Advisories](https://github.com/Strykar/pam_authnft/security/advisories)
([SECURITY.md](SECURITY.md)).

## License

GPL-2.0-or-later.  See [LICENSE](LICENSE) for details.

Every source file carries an `SPDX-License-Identifier: GPL-2.0-or-later`
tag.  Recipients may redistribute and/or modify the software under the
terms of GPL-2.0, or, at their option, any later version published by
the Free Software Foundation.

Copyright (C) 2025-2026 Avinash H. Duduskar.
