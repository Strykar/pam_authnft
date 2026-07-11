# Third-party dependency inventory

This document is the authoritative list of every external library, tool,
and CI service pam_authnft depends on. Each entry names the upstream
security-advisory feed so a downstream packager (or this project's own
maintainer) can subscribe and react to CVEs without having to discover
the right channel ad-hoc.

OSTIF best-practices guide §5 ("Knowledge Base — Maintain third-party
library inventory") is satisfied by keeping this document current. The
guide §4 ("Security Currency — Subscribe to CVE publications") is
satisfied by the security-feed column.

Updated whenever a dependency is added, removed, or has its version-floor
shifted.

**What "Min ver" means.** It is the lowest version the project is *tested*
against — CI and the maintainer's host — not a proven hard minimum. An older
version may well work; nobody has run it. Treat the column as "known good",
not "anything below this is broken". Where the distinction matters, it is
called out in the notes below.

For **libnftables** specifically: every libnftables function the module calls
(`nft_ctx_new`, `nft_run_cmd_from_buffer`, `nft_ctx_output_set_flags`,
`nft_ctx_get_output_buffer`, `nft_ctx_get_error_buffer`,
`nft_ctx_buffer_output`) and the `socket cgroupv2` parser support both exist as
far back as nftables 1.0.0, so the true minimum is probably well below 1.1.0.
It is listed at 1.1.0 because that is what CI and the dev host actually run
(1.1.x). If you are packaging for a distro that ships 1.0.x — Debian 12 has
1.0.6, RHEL 9 has 1.0.4, Ubuntu 22.04 has 1.0.2 — it very likely works, but
confirm it rather than trusting this table: `sudo make test-packet-match`
drives the real `socket cgroupv2` set, rule, and match end to end.

## Build- and run-time C libraries

The shipped `pam_authnft.so` is dynamically linked against six system
libraries. None are vendored; the operating distribution provides them.

| Library | License | pkg-config | Min ver | Used for | Security feed |
|---|---|---|---|---|---|
| **libnftables** | LGPL-2.0-or-later | `libnftables` | 1.1.0+ | nftables transactions, fragment parsing | <https://lwn.net/Alerts/> (filter on `nftables`); upstream patches at <https://git.netfilter.org/nftables/> |
| **libseccomp** | LGPL-2.1-only | `libseccomp` | 2.5.0+ | seccomp-BPF allowlist; `SCMP_ACT_KILL` default | <https://github.com/seccomp/libseccomp/security/advisories> |
| **libsystemd** | LGPL-2.1-or-later | `libsystemd` | 250+ | sd-bus (StartTransientUnit / StopUnit); sd_journal_send | <https://github.com/systemd/systemd/security/advisories> |
| **libpam (linux-pam)** | BSD-3-Clause | `pam` | 1.5.0+ | PAM session module API | <https://github.com/linux-pam/linux-pam/security/advisories> |
| **libcap** | BSD-3-Clause / GPL-2.0 | `libcap` | 2.66+ | capability inspection helpers | <https://sites.google.com/site/fullycapable/> + distro CVE feeds |
| **libaudit** | LGPL-2.1-or-later | `audit` | 4.0+ | `AUDIT_USER_ERR` emission on fragment rejection | <https://github.com/linux-audit/audit-userspace/issues> |

The version floors above are advisory — pam_authnft will compile
against older releases that provide the API surface it uses. The
floors are the versions the maintainer actually tests on (Arch Linux
LTS as of the current minor release).

## Build tooling (host requirements)

These are needed to **build** pam_authnft from source. They do not
ship inside the binary.

| Tool | License | Required for | Version notes |
|---|---|---|---|
| GCC | GPL-3.0-or-later | release build | 12+ tested |
| Clang | Apache-2.0-with-LLVM-Exception | sanitizer + libFuzzer builds | 18+ tested |
| GNU Make | GPL-3.0-or-later | build orchestration | 4.x |
| pkg-config | GPL-2.0-or-later | dependency resolution | 0.29+ |
| pandoc | GPL-2.0-or-later | manpage generation (`make man`) | optional; runtime install does not need it |

## Test / CI tooling

Required to run the test surface. Neither pam_authnft.so nor any
production deliverable links against these.

| Tool | License | Used for |
|---|---|---|
| podman | Apache-2.0 | `make test-container` (booted-systemd Fedora image) |
| valgrind | GPL-2.0+ | `make test-integration` leak detection |
| pamtester | GPL-2.0+ | integration test harness driving open/close cycles |
| Python 3 | PSF-2.0 | differential-oracle re-implementations (`tests/oracle/oracle.py`) |
| llvm-cov / llvm-profdata | Apache-2.0-with-LLVM-Exception | `make fuzz-coverage` HTML report |

## CI / GitHub Actions

GitHub-hosted reusable actions used by `.github/workflows/*.yml`. All
pinned to a specific major version; Dependabot tracks updates weekly
(see `.github/dependabot.yml`).

| Action | Purpose | Version |
|---|---|---|
| actions/checkout | clone the repo into the runner | v6 |
| actions/upload-artifact | stash crash artefacts, SARIF | v4 |
| actions/github-script | issue auto-creation on fuzz crash | v8 |
| github/codeql-action | CodeQL scan + SARIF upload | v3 |
| ossf/scorecard-action | OpenSSF Scorecard run | v2 |

## Optional / deferred third-party services

These are referenced by the project but not currently active:

| Service | Status | Where mentioned |
|---|---|---|
| OSS-Fuzz | submission staged at `infra/oss-fuzz/`; gated on project age | `docs/TODO.txt` near-term |
| Coverity Scan | weekly cron present | `.github/workflows/coverity.yml` |
| OpenSSF Best Practices badge | active, project 12496 | README badge row |

## How to refresh this document

After adding or removing a dependency:

1. Update the relevant table here.
2. Update `Makefile` `LIBS` if it's a build-time C library.
3. Update `Containerfile` (`dnf install` line) for Fedora-specific names.
4. Update every `.github/workflows/*.yml` `apt install` line.
5. Update `infra/oss-fuzz/{Dockerfile,build.sh}`.
6. Update `docs/CONTRIBUTING.txt` "Build" section count.

A merge that touches `Makefile` `LIBS` without updating this doc is a
bug — flag it in PR review.
