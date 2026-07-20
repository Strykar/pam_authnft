# Incident response runbook

Internal procedure for handling a security report. Lives next to
[`SECURITY.md`](../SECURITY.md), which is the public-facing
disclosure-policy document — this file is the *operational* checklist
the maintainer-of-the-day follows once a report comes in.

OSTIF best-practices guide §2 + §6 are satisfied by following this runbook.

The steps below are written for a single-maintainer project. As the
project grows, replace "the maintainer" with "the on-call rotation" and
add explicit hand-offs.

---

## Phase 1 — Triage (target: ≤ 5 business days)

The goal of this phase is to confirm receipt of the report and begin
working on it. Nothing is publicly visible yet.

1. **Read the report end-to-end.** Note any embargo or disclosure
   constraints the reporter named.
2. **Reply to the reporter** acknowledging receipt. Use the GitHub
   Security Advisory comment thread (or the email channel if that's how
   it arrived). State the next-step target (initial triage by day 10).
3. **Open a private GitHub Security Advisory** if the report came in
   via another channel. The advisory becomes the tracking artefact.
4. **Capture artefacts**: any PoC inputs, crash dumps, network captures.
   Attach them to the advisory.
5. **Initial scope check** against [`SECURITY.md`](../SECURITY.md)'s
   "Scope" section. If clearly out-of-scope (misconfiguration of a
   user-authored fragment, non-systemd init, etc.), reply with the
   reasoning and close. Do not silently drop reports.

## Phase 2 — Confirm and analyze (target: by day 10)

1. **Reproduce the report locally.** If the PoC is a fuzz crash, save it
   to `tests/fuzz/corpus/<harness>/regression_<short-id>` and re-run the
   harness against it; this is the regression artefact for later.
2. **Reduce to a minimal reproducer.** A 10-byte input is easier to
   reason about than a 10-KB one.
3. **Identify root cause.** Walk the code path with the help of the
   relevant `docs/FUZZ_SURFACE.md` row, the seccomp allowlist, and
   `docs/ARCHITECTURE.txt`'s lifecycle diagram if needed.
4. **Determine affected versions.** `git log --oneline -- <file>` since
   the introducing commit. Cross-check against released tags.
5. **Score severity.** Use a CVSSv3.1 vector if the bug class permits;
   note the trust-boundary context (admin-only fragment vs. unauth
   network attacker, etc.). The fragment trust boundary often reduces
   real-world severity even when the technical bug is bad.
6. **Check related code.** Bug #2 in the audit OOB hunt was found
   *because* the same pattern was inspected after fixing bug #1; do that
   pass deliberately.
7. **Notify the reporter** with the analysis and the proposed fix
   timeline.

## Phase 3 — Fix

1. **Develop the fix on a private branch** in the GitHub Security
   Advisory drafting tab (these branches don't trigger CI on pull-request
   triggers from forks; the visibility is by design).
2. **Add a regression test.** One of:
   - fuzz corpus entry (memory-safety bugs)
   - oracle / property-test input (logic bugs)
   - integration-test stage (lifecycle / state-leak bugs)
3. **Self-review**, then if a second reviewer is available, brief them
   under the same advisory.
4. **Decide on backports.** Currently alpha-only, so this means: latest
   released minor only. Note the decision in the advisory.

## Phase 4 — Disclosure planning

1. **Apply for a CVE.** GitHub will assign one via the Security Advisory
   workflow if requested; otherwise apply via MITRE.
2. **Draft the advisory body**: summary, affected versions, fix release,
   workaround (if any), credit. Aim for the level of detail the affected
   packagers need to decide whether to ship a backport.
3. **Identify downstream packagers.** Currently none, but if the project
   makes it into Arch / Debian / Fedora packages, the maintainers there
   need pre-disclosure notice (~7 days) per their security-team SOP.
4. **Set the embargo end date.** Default: 90 days from acknowledgment
   per `SECURITY.md`. Earlier if the fix ships sooner, later only by
   mutual agreement with the reporter.

## Phase 5 — Release

1. **Tag the security release.** Convention: bump the patch version
   and prefix the tag note with `[security]`.
2. **Publish the GHSA + CVE simultaneously** with the release tag.
3. **Update the README badges** if a new active release replaces the
   previous one in any badge link.
4. **Post-release notification**: the original reporter, any pre-disclosure
   downstream packagers, and (if the bug is high-severity) a brief note
   on the appropriate ML — `oss-security@` for CVE-grade, otherwise
   the project's own announcements channel.

## Phase 6 — Post-mortem

A post-mortem is mandatory for any High or Critical bug; optional for
Medium and below. Goals: improve detection, reduce recurrence, share
learning.

1. **Categorise the bug class.** Add a row to `docs/FUZZ_SURFACE.md`
   "Bugs found" if the class is fuzz-detectable; otherwise note the
   detection mechanism that should have caught it.
2. **Add detection.** A new fuzz harness, oracle case, integration test,
   or static-check rule. The regression test from Phase 3 is the floor;
   a class-level detector is the ceiling.
3. **Write a public post-mortem** if the learning value warrants it
   (e.g., the K-numbered findings in HANDOFF). Link from the advisory
   to the post-mortem.
4. **Retro the runbook.** If a step in this document slowed you down or
   was wrong, fix this document. The next incident benefits.

---

## Severity scoring shortcut

| Severity | Approximate definition for pam_authnft |
|---|---|
| **Critical** | Pre-auth remote unauth attacker can bypass session-pinning policy or execute code in the PAM process. |
| **High** | Remote unauth attacker can crash the PAM process / cause persistent kernel-state leak / read or modify other sessions' policy. |
| **Medium** | Authenticated user can violate session policy or accumulate kernel state. Memory-safety bugs in attacker-influenced parsers (netlink, keyring). |
| **Low** | Admin-controlled trust-boundary issues (fragment with hostile content), defense-in-depth gaps that aren't currently exploitable. |

Use the scoring as a guide; if in doubt round up.

## Common artefacts and where to find them

- **Crash inputs** → `tests/fuzz/corpus/<harness>/regression_*`
- **Coverage report** → `docs/fuzz-coverage/index.html`
- **Fuzz inventory** → `docs/FUZZ_SURFACE.md` (also tracks bugs found)
- **Trust model** → `docs/ARCHITECTURE.txt` "Trust model"
- **Seccomp allowlist** → `src/sandbox.c`
- **Test surface** → `tests/test_suite.c`, `tests/integration_test.sh`,
  `tests/oracle/`, `tests/fuzz/`
