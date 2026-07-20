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
user session and revoke them at logout. pam_authnft fills that gap. Rules
are removed by `close_session` at logout via the per-session state stored
through `pam_set_data`. If `close_session` never runs at all — daemon
crash, OOM kill, kernel panic, hard reset — the session's set element
carries a 24-hour timeout, so it stops matching traffic within a day.
The per-session chain, sets, and jump rule have no timeout of their own.
Nothing reaps them on a timer: that session's `close_session` is never
coming, so they persist until either a later login's PID recycles onto
the leaked names — which trips the self-heal that reclaims the stale
state at `open_session` — or an administrator removes them by hand.

OpenBSD's pf has had this for years — named anchors loaded per-session via
pfctl, torn down when the session ends. pam_authnft brings the same model
to Linux: nftables named sets serve as the anchor equivalent, and the
cgroupv2 inode of a systemd transient scope replaces the authenticated shell
as the session identity. No dedicated shell, no setuid binary, no kernel
patches.

<p align="center">
  <img src="docs/mascot.svg" alt="pam_authnft mascot" width="200">
</p>

> **Status: alpha (0.x.x).** The PAM interface (two exported symbols),
> nftables set schema, and fragment format are intended to be stable. The
> `claims_env` wire format, `rhost_policy=kernel` NETLINK details, and
> slice defaults may change before 1.0. See [Stability and
> roadmap](#stability-and-roadmap) below.

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

The quoted path is the session's cgroupv2 scope under `authnft.slice`. The
kernel resolves it to a cgroupv2 inode at insert time. At packet
classification time, `socket cgroupv2 level 2` reads the socket's
originating cgroup and matches it against the set — binding the firewall
rule to the session without referencing PIDs, UIDs, or usernames. The
24-hour timeout is a safety net; explicit deletion at logout is the primary
cleanup mechanism.

How the match works, use cases, installation, and the full
configuration reference live in [docs/CONCEPTS.md](docs/CONCEPTS.md)
and [docs/ADMIN_GUIDE.md](docs/ADMIN_GUIDE.md).

## Limitations

- cgroupv2 unified hierarchy only; hybrid setups untested.
- Hard systemd dependency; non-systemd init not supported.
- Fragment syntax errors are caught at load time and logged; semantic errors
  are the administrator's responsibility.
- If cleanup fails at logout (e.g., nftables unavailable), the set element
  expires after 24 hours via the safety-net timeout on insert. Session
  JSON orphans are reaped after 7 days by systemd-tmpfiles.
- The cgroup path is constructed deterministically from the scope unit name
  at `open_session`. The `socket cgroupv2` match applies to sockets created
  inside the session scope; sockets that existed before the scope was
  created (e.g., the SSH control connection) carry their original cgroup
  and are not matched. The module adds `ct state established,related
  accept` to the shared `filter` chain to handle pre-scope traffic.
- Transitively included fragments are NOT validated by pam_authnft for
  ownership or mode. The admin must ensure every included file is
  root-owned and not world-writable.

## Stability and roadmap

**Stable now** — the PAM interface (exactly two exported symbols), the three
nftables set types and their schemas, the fragment ownership model
(`st_uid == 0`, no world-writable), the element comment grammar documented
in [INTEGRATIONS.txt §6.1](docs/INTEGRATIONS.txt), the session-identity
JSON schema (`v=2`, §5.6), the structured journald audit fields (§6.2),
and the Linux audit-syscall channel
(`AUDIT_USER_ERR` with reason tags `missing | perms | content | nft-syntax`,
§6.2.7).

**May change before 1.0** — `claims_env` wire format details,
`rhost_policy=kernel` NETLINK internals, `authnft.slice` shipped defaults.

**Planned** — OSS-Fuzz registration (project files staged at
[tests/fuzz/oss-fuzz/](tests/fuzz/oss-fuzz/), submission gated on project age),
fragment linter (wraps libnftables dry-run), pluggable fragment
sources, packaging for Arch (AUR) and Debian. See
[docs/TODO.txt](docs/TODO.txt) for the full list.

## Contributing

Patches, testing on new distros/kernels, and integration experiments are
welcome. The areas where help is most wanted:

- **Packaging** — AUR, Debian, Fedora COPR, NixOS, Gentoo ebuilds
- **Distro and kernel testing** — especially non-Fedora systemd distros and
  kernels newer than 6.x
- **Integration prototypes** — if you maintain a PAM module, VPN daemon,
  or AAA stack and want to try the `claims_env` path, seed
  `AUTHNFT_CORRELATION` for audit joining, or drive fragment generation,
  open an issue describing the use case
- **Fuzzing** — the eight harnesses in `tests/fuzz/` all clear the 90% region-coverage
  gate (see [docs/FUZZ_SURFACE.md](docs/FUZZ_SURFACE.md)). Wanted: harnesses for
  functions not yet on that surface map, and property assertions for the
  crash-only harnesses
- **Documentation** — man page improvements, deployment guides, example
  fragments for common scenarios

Before opening a pull request, read
[docs/CONTRIBUTING.txt](docs/CONTRIBUTING.txt) — it documents the
invariants that must be preserved, the test stage matrix, the CI
gates a PR must clear, and the seccomp allowlist derivation
procedure.

Report security issues privately via [GitHub Security
Advisories](https://github.com/Strykar/pam_authnft/security/advisories)
(see [SECURITY.md](SECURITY.md) for scope and expectations).

## Project documentation

| Document | Contents |
|---|---|
| [docs/CONCEPTS.md](docs/CONCEPTS.md) | Use cases, how the cgroupv2 match binds rules to sessions, integration surface |
| [docs/ADMIN_GUIDE.md](docs/ADMIN_GUIDE.md) | Quick start, configuration reference (module arguments, claims_env, PAM stack options, fragments, systemd controls), testing |
| [docs/ARCHITECTURE.txt](docs/ARCHITECTURE.txt) | Lifecycle, trust model, session identity, seccomp design, session-identity files, audit events |
| [docs/INTEGRATIONS.txt](docs/INTEGRATIONS.txt) | Stable contracts for producers and consumers: PAM stack (§1), claims_env keyring (§2), nft fragment composition (§4.6), systemd scopes (§5), session JSON (§5.6), structured journal events (§6.2), Linux audit-syscall events (§6.2.7) |
| [docs/CONTRIBUTING.txt](docs/CONTRIBUTING.txt) | Build, layout, invariants, style, test procedures, seccomp allowlist derivation |
| [docs/TODO.txt](docs/TODO.txt) | Near-term, medium-term, and deferred work items |
| [docs/THIRD_PARTY.md](docs/THIRD_PARTY.md) | Authoritative dependency inventory: licenses, version floors, security feeds |
| [docs/INCIDENT_RESPONSE.md](docs/INCIDENT_RESPONSE.md) | Internal runbook for handling a security report (the public policy is [SECURITY.md](SECURITY.md)) |
| [docs/SECURITY_PRACTICES.md](docs/SECURITY_PRACTICES.md) | Single-page overview of every security tool, doc, goal, and milestone in the project |
| [docs/REPRODUCIBLE_BUILDS.md](docs/REPRODUCIBLE_BUILDS.md) | What reproducibility we provide, what we don't, and how a packager verifies a release artefact |
| [docs/FUZZ_SURFACE.md](docs/FUZZ_SURFACE.md) | Fuzz-surface map: which functions are fuzzed, by which harness, at what coverage, and the bugs the harnesses found |
| [docs/CI_LOCAL.md](docs/CI_LOCAL.md) | Replicating the CI gates locally (the container audit tier, the fault matrix, the kernel packet-match check) |
| [SECURITY.md](SECURITY.md) | Vulnerability scope and reporting procedure |

## License

GPL-2.0-or-later.  See [LICENSE](LICENSE) for details.

Every source file carries an `SPDX-License-Identifier: GPL-2.0-or-later`
tag.  Recipients may redistribute and/or modify the software under the
terms of GPL-2.0, or, at their option, any later version published by
the Free Software Foundation.

Copyright (C) 2025-2026 Avinash H. Duduskar.
