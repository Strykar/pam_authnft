# Security assurance case

A structured argument that pam_authnft is adequately secure for its
purpose, with pointers to the evidence. The threat model and trust
boundaries are stated first, then the design argument, then the
argument that common implementation weaknesses are countered.
Companion documents: [ARCHITECTURE.txt](ARCHITECTURE.txt) (full
lifecycle and trust model), [SECURITY_PRACTICES.md](SECURITY_PRACTICES.md)
(tooling inventory and audit history), [FUZZ_SURFACE.md](FUZZ_SURFACE.md)
(what is fuzzed and how hard).

## Top-level claims

On a supported kernel, configured as documented, pam_authnft upholds:

- **C1. No escalation.** A non-root user cannot use the module to run
  code as root, load rules of their choosing, or escape the sandbox
  around the module's parsing code.
- **C2. Session isolation.** One subject's session rules, session
  identity file and claims tag cannot be read or altered by another
  non-root subject.
- **C3. Bounded persistence.** Session state cannot outlive its
  session without bound, even when teardown never runs.
- **C4. Fail closed on open.** Malformed, missing or hostile input at
  session open denies the session before any nftables state exists;
  teardown at close is deliberately best-effort so a session can
  always unwind (invariant 4 of [CONTRIBUTING.txt](CONTRIBUTING.txt)).

## Threat model and trust boundaries

Untrusted or semi-trusted inputs, and where each is handled:

| Input | Trust | Handling |
|---|---|---|
| `PAM_USER` | authenticated by the PAM service | validated against a strict username charset before any use |
| `PAM_RHOST` | untrusted (network-supplied) | parsed as an IP literal, zone-stripped, policy-gated (`rhost_policy`); non-parseable values fall back to the cgroup-only set, never into command text |
| Per-user fragment | trusted content, hostile placement | must be root-owned, not world-writable, checked with `stat(2)` before load; content passes a brace, quote and comment-aware statement scanner with verb and shared-chain guards |
| Transitively included files | administrator's responsibility | documented limitation (README, ADMIN_GUIDE); an `include` in a fragment is logged at open |
| `claims_env` keyring payload | untrusted bytes from an earlier PAM module | read from a UID-locked kernel key, sanitised to a printable-ASCII charset, embedded only as an nftables comment |
| `NETLINK_SOCK_DIAG` responses | kernel-supplied | length-checked chunk parsing (fuzzed); only inbound ESTABLISHED sockets whose local port is a host listener qualify |
| D-Bus (systemd) | trusted system service | scope names constructed from validated username and PID, never from free text |
| NSS (`getgrnam` and friends) | system-configured backends | runs in the setup child before the seccomp filter, so sss and ldap backends cannot be SIGSYS-killed; never runs in the monitor process |

Trust boundaries: (1) the PAM process boundary between the service's
monitor (root, never filtered) and the forked setup child, which is
locked with a seccomp-BPF allowlist (`SCMP_ACT_KILL` default) before
it touches fragment content; (2) the root/user boundary for all
on-disk state (fragments are root-owned inputs, session files are
0640 root:root outputs); (3) the kernel boundary, where packet
matching is keyed on the socket's originating cgroup, not on any
name the user controls.

## Secure design argument

- **Least privilege.** Exactly two exported symbols; the code that
  parses untrusted input runs in a short-lived child under seccomp;
  the child's nftables state lives on in the kernel while the process
  that produced it exits.
- **Fail closed at open.** A missing, insecure or rejected fragment
  returns `PAM_AUTH_ERR` before any nftables object is created. Error
  paths after partial creation roll back what they made
  (`nft_partial_cleanup`, `bus_handler_stop`), so a failed open leaves
  no residue and a retry is always clean (integration stage 10.14).
- **Isolation by construction.** Each session gets its own chain and
  sets keyed `session_<user>_<pid>`; alice's chain never references
  bob's set. Asserted per kernel by the packet-match invariants
  (allowed and disallowed match, per-session isolation).
- **Bounded persistence.** Set elements carry a 24-hour timeout;
  session JSON orphans are reaped after 7 days by systemd-tmpfiles; a
  login whose PID recycles onto leaked names self-heals the stale
  state at open.
- **Information exposure minimised.** Session identity files are
  root-only because the `authnft` group is exactly the
  monitored-subject population (2026-07 audit fix); the claims tag is
  UID-locked in the kernel keyring in transit.
- **Economy of mechanism.** No plugin ABI, no callback registry;
  every integration contract is an existing kernel or userspace
  primitive with a narrow schema ([INTEGRATIONS.txt](INTEGRATIONS.txt)).

## Implementation weakness argument

Common weakness classes and the standing counter for each, with the
gate that enforces it (inventory in
[SECURITY_PRACTICES.md](SECURITY_PRACTICES.md)):

- **Memory safety.** Hardened build flags gated by `checksec` (Full
  RELRO, stack protector, CFI where available); the unit suite runs
  under ASan, UBSan and LSan on every pull request; integration runs
  under valgrind; eight libFuzzer harnesses cover the parsing
  surfaces with an enforced 90 percent region-coverage floor; nightly
  fuzzing compounds a persistent corpus; a fault-injection matrix
  drives allocation and libnftables failures under sanitizers on
  every code commit.
- **Injection.** The fragment validator is a statement scanner aware
  of braces, quotes and comments, so semicolon-separated or padded
  statements cannot bypass the verb and shared-chain guards;
  placeholder substitution derives its bounds from token lengths;
  keyring payloads are sanitised to a fixed charset before embedding.
- **Logic and lifecycle defects.** Mutation testing (mull) gates the
  pure validator surfaces per pull request and reports on the whole
  binary weekly; the integration suite pins the lifecycle invariants
  (25 stages), including rollback and self-heal behaviour.
- **Static weaknesses.** CodeQL (security-and-quality), Coverity,
  cppcheck and clang scan-build run per pull request or on schedule;
  warnings are errors in CI.
- **Supply chain.** Actions are hash-pinned, dependencies inventoried
  and drift-gated ([THIRD_PARTY.md](THIRD_PARTY.md)), builds checked
  reproducible, releases ship an SBOM and SLSA Build L3 provenance,
  and Scorecard runs weekly.
- **Adversarial review.** A July 2026 adversarial audit found no
  attacker-reachable memory-safety, injection or sandbox-escape
  defect; the caveats it raised were fixed and regression-tested
  (audit history in [SECURITY_PRACTICES.md](SECURITY_PRACTICES.md)).

## Residual risks and assumptions

- Root-owned fragments are trusted input: a hostile root already owns
  the host, so fragment content is validated for safety against
  mistakes, not against a malicious administrator.
- Transitively included fragment files are not re-validated; this is
  a documented administrator responsibility.
- The kernel must carry commit 05ae2fba821c or the match silently
  never fires; `make test-packet-match` exists because no version
  check can answer this.
- One documented teardown edge: if the jump-rule transaction commits
  but the kernel handle cannot be parsed, that rule leaks until the
  element timeout clears its effect (invariant 4, CONTRIBUTING.txt).
- Single maintainer; continuity arrangements are in
  [GOVERNANCE.md](GOVERNANCE.md).
