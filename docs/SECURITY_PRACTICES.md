# Security practices

This document is the single overview of the security-tooling and
security-process surface around pam_authnft. It exists so a new
contributor (or a third-party reviewer like OSTIF, Trail of Bits,
NCC, etc.) can see what's in place at a glance, without reading every
workflow YAML and every doc file.

OSTIF best-practices guide §5 ("Document security tools, practices,
and goals") + §7 ("Security milestones") are satisfied by keeping
this document current.

---

## Security tools in use

Each row below is a real, running, **automated** check. The "Catches"
column lists the bug class or signal each tool produces.

| Tool | Where | Cadence | Catches |
|---|---|---|---|
| **GCC + Clang build matrix** | `.github/workflows/build.yml` | every PR | compiler warnings (`-Wall -Wextra -Werror=implicit-fallthrough`), hardening-flag survival |
| **cppcheck** | `.github/workflows/cppcheck.yml` | every PR | static analysis: dangerous constructs, leaks, simple misuse |
| **CodeQL** | `.github/workflows/codeql.yml` | every PR | static taint analysis, OWASP-style classes |
| **Coverity Scan** | `.github/workflows/coverity.yml` | weekly cron | deeper static analysis (path-sensitive, inter-procedural) |
| **AddressSanitizer + UBSan + LeakSanitizer** | `.github/workflows/sanitizers.yml` | every PR | `sanitizer-link` proves the .so links under each sanitizer; `sanitized-tests` runs the unit suite under ASan+UBSan+LSan in `AUTHNFT_AUDIT_MODE=1` (skips only the seccomp stages that conflict with the sanitizer runtime), giving real leak-checked execution of the sanitization, cgroup-path, rhost, netlink peer-parser, keyring, and inode-cap paths |
| **OpenSSF Scorecard** | `.github/workflows/scorecard.yml` | weekly cron + push | supply-chain hygiene (pinned action versions, branch protection, signed releases, dangerous workflows) |
| **OpenSSF Best Practices** | bestpractices.dev project 12496 | manual self-attest | governance / policy items the badge program tracks |
| **CIFuzz** | `.github/workflows/cifuzz.yml` | every PR | 60 s × 8 fuzz harnesses (memory-safety regressions) |
| **Nightly fuzz cron** | `.github/workflows/fuzz-nightly.yml` | daily 03:17 UTC | 30 min × 8 fuzz harnesses (deeper bugs that 60 s won't surface), auto-issue on crash |
| **Mutation testing (mull)** | `.github/workflows/mutation.yml` + `make mutation-report` | weekly Sunday 06:43 UTC | LLVM-IR mutations across `src/*.c` + `tests/test_suite.c`; surviving mutations indicate either coverage gaps or dead code |
| **Differential oracle** | `tests/oracle/`, run via `make test` | every PR | logic bugs in 5 small parsers (C vs Python re-implementation diff) |
| **Property-based tests** | `tests/oracle/properties.py` | every PR | idempotence + round-trip violations on the same 5 parsers |
| **Unit suite** | `tests/test_suite.c`, run via `make test` | every PR | 14 stages (0-13): symbol whitelist, sanitization, sandbox kill/survive, nft dry-run, cgroup invariant, hardening flags, rhost normalization, peer lookup, keyring fetch, inode cap, session-file perms, setup-path syscall coverage |
| **Integration suite (tier 1)** | `.github/workflows/integration.yml` → `make test-integration-container` + `make audit-container` | nightly + dispatch | the 25-stage suite in the booted-systemd container: pamtester open+close cycles, leftover-state assertions, per-session isolation, failure-path rollback, real-sshd loopback, plus the nft_handler_setup fault matrix under ASan/LSan + valgrind lifecycle. Shares the runner kernel; the `socket cgroupv2 level 2` match is checked against that one kernel |
| **Kernel-matrix audit (tier 2)** | `.github/workflows/audit-vm.yml` → `make audit-vm` (virtme-ng, `/dev/kvm`) | nightly + dispatch | unit + seccomp enforcement + the fault matrix under a real, pinnable kernel; the only tier that can sweep a kernel matrix. Part B (integration) is excluded here (headless coupling) |
| **valgrind on unit suite** | `make test-integration` | manual | leaks, use-after-free, double-free |
| **Dependabot** | `.github/dependabot.yml` | weekly | GitHub Actions version bumps |
| **fuzz-coverage measurement** | `make fuzz-coverage` → `docs/fuzz-coverage/` | manual / per-PR | per-function fuzz region/line/branch coverage; gates the ≥90% bar in `docs/FUZZ_SURFACE.md` |
| **Reproducibility check** | `.github/workflows/reproducibility.yml` → `make reproducibility-check` | every PR | builds pam_authnft.so twice from a clean tree and fails on a sha256 mismatch (bit-identical same-machine builds) |
| **Trace-based seccomp provenance** | `make trace`, `make trace-features` | manual | confirms the seccomp allowlist matches actually-used syscalls |

## Security practices documents

Each artefact below has a single owner-doc. Don't duplicate; cross-link.

| Topic | Authoritative doc |
|---|---|
| What's fuzzed, what isn't, with bug log | [`docs/FUZZ_SURFACE.md`](FUZZ_SURFACE.md) |
| Public vulnerability reporting policy | [`SECURITY.md`](../SECURITY.md) |
| Internal incident-response runbook | [`docs/INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) |
| Third-party dependency inventory | [`docs/THIRD_PARTY.md`](THIRD_PARTY.md) |
| RFC 9116 reporting metadata | [`.well-known/security.txt`](../.well-known/security.txt) |
| Build reproducibility expectations | [`docs/REPRODUCIBLE_BUILDS.md`](REPRODUCIBLE_BUILDS.md) |
| Architecture / lifecycle / trust model | [`docs/ARCHITECTURE.txt`](ARCHITECTURE.txt) |
| Stable producer/consumer contracts | [`docs/INTEGRATIONS.txt`](INTEGRATIONS.txt) |
| Build invariants + style + concurrency claims | [`docs/CONTRIBUTING.txt`](CONTRIBUTING.txt) |

## Security goals

These are the things we are trying to be true. Each is tracked by one
or more tools above; if a tool that backs a goal fails, we treat it as
a blocker, not a warning.

1. **Memory safety in every parser of attacker-influenced bytes.**
   Backed by: ASan/UBSan in CI, libFuzzer with property assertions,
   valgrind on unit suite. Per-function ≥ 90% region coverage on every
   fuzzed function.

2. **The seccomp allowlist matches reality.** Backed by `make trace`,
   plus invariant guard #5 in `docs/CONTRIBUTING.txt`.

3. **Logic bugs in the small parsers don't ship silently.** Backed by
   the differential oracle (5 functions, 286 inputs, C vs Python diff)
   and property-based tests (idempotence, round-trips).

4. **Failed open_session leaves no kernel or systemd state behind.**
   Backed by integration test 10.14 and the partial-cleanup helper in
   `nft_handler_setup`.

5. **Fragment trust boundary is enforced.** Backed by `validate_fragment_content`
   plus integration tests 10.4 (uid != 0) and 10.5 (world-writable),
   plus the `audit(7) AUDIT_USER_ERR` emission on every rejection path.

6. **The exported PAM symbol set is exactly two.** Backed by stage 0 of
   the unit suite (`test-symbols`).

7. **Same-machine reproducible builds.** Backed by
   `make reproducibility-check`.

## Security milestones

Recurring schedule. The "every minor release" items run as part of the
release process; a release that skips one is incomplete.

| Cadence | Activity | Owner |
|---|---|---|
| Every PR | All `every PR` tools above | author + reviewer |
| Every minor release (0.X.0) | `make trace` + diff vs `src/sandbox.c` allowlist | maintainer |
| Every minor release | `make reproducibility-check` + record release-notes hash | maintainer |
| Every minor release | `make fuzz-coverage` + verify per-function ≥ 90% holds | maintainer |
| Every minor release | Refresh `docs/THIRD_PARTY.md` if any dep moved | maintainer |
| Daily | `fuzz-nightly` workflow | automated; auto-files issues on crash |
| Weekly | OpenSSF Scorecard run | automated; SARIF surfaces in code-scanning |
| Weekly | Coverity Scan | automated; defect dashboard |
| Weekly | Mutation testing (`mutation.yml`, Sunday 06:43 UTC) | automated; surviving mutations reviewed against `tests/test_suite.c` |
| Weekly | Dependabot scan | automated; PR per outdated action |
| Soft-ongoing | Re-run `make trace` on kernel / glibc upgrades | maintainer (per `docs/TODO.txt`) |

## Audit history

A running record of internal and external audits. External engagements
get a formal write-up; internal audits are summarised in the relevant
`docs/` file or in PR descriptions.

| When | Type | Scope | Outcome |
|---|---|---|---|
| 2026-04 (this audit) | Internal multi-phase | Phase 1 alloc paths, Phase 2 concurrency claims, Phase 3 trust model, Phase 4 differential + property + mutation testing, Phase 6.1 nightly fuzz, 6.5 audit hook | 4 real bugs found and fixed (3 heap OOBs + 1 off-by-one); harness coverage from 0 to 9 functions ≥ 90%; mutation testing wired in (mull, weekly cron); OSTIF best-practices alignment to mostly green |
| 2026-07 | Internal pre-1.0 readiness | Full-tree adversarial audit (memory safety, trust boundary, sandbox, lifecycle, DoS, info-leak, logic) with per-finding reachability verification | No attacker-reachable memory-safety, injection, or sandbox-escape defect. Fixed: session-file `claims_tag` cross-user disclosure (now root:root); moved NSS group resolution to the unsandboxed parent (closes the sss/ldap SIGSYS lockout); per-session-state self-heal on PID-recycle EEXIST; best-effort `nft_handler_cleanup` (removed the false fallback comment); fragment validator now statement-aware (`;`/whitespace/brace bypass closed); peer lookup prefers the inbound listener socket. CI: added `sanitized-tests` (ASan+UBSan+LSan runtime, was build-only). Docs reconciled to shipped behavior |

When external audits land, append a row.

## What this document is NOT

- A threat model. The threat model lives in
  [`docs/ARCHITECTURE.txt`](ARCHITECTURE.txt) and
  [`SECURITY.md`](../SECURITY.md) "Scope" section.
- An implementation guide. Look at `docs/CONTRIBUTING.txt` for that.
- A bug log. Bugs are tracked in `docs/FUZZ_SURFACE.md` "Bugs found"
  and on the GitHub issue tracker.

## When to update this document

- A new automated check joins (or leaves) CI: update the "Security
  tools in use" table.
- A new security practice doc is written: update the "Security
  practices documents" table.
- An external audit completes: add a row to "Audit history".
- The release process gains or loses a step: update "Security
  milestones".
