# Security Policy

pam_authnft is alpha software. It runs inside the PAM process of services
like `sshd`, `login`, and `su` with whatever privilege that service holds —
typically root. Security reports are taken seriously.

## Scope

In scope:

- Anything that bypasses the fragment permission check
  (`st_uid == 0 && !world-writable`)
- Anything that causes `pam_authnft.so` to execute attacker-controlled code
  or syscalls outside the seccomp allowlist
- Username, `PAM_RHOST`, or fragment-path handling that permits injection
  into nftables commands, D-Bus method calls, or filesystem operations
- Leaks of per-session nftables state that outlive the session. Note the
  asymmetry: the set *element* carries a 24h timeout, so it stops matching
  within a day even if `close_session` never runs, but the per-session chain,
  sets, and jump rule have **no timeout of their own** — nothing reaps them on
  a timer. They persist until a later login's PID recycles onto the leaked
  names (which trips the self-heal) or an operator removes them. A leak of the
  element beyond its timeout, or any leak reachable without a crash, is in
  scope
- Misuse of the `rhost_policy=kernel` sock_diag path: incorrect peer-address
  resolution that binds a session element to the wrong source IP
- Misuse of the `claims_env` keyring-payload path: command injection via
  an insufficiently sanitized tag, read amplification that bypasses the
  `CLAIMS_TAG_MAX` bound, or privilege escalation via keyring interactions
- Cleanup or resource-exhaustion issues triggerable by an unauthenticated
  remote party via repeated session churn

Out of scope:

- Misconfiguration of user-authored fragments (administrator responsibility)
- Non-systemd init systems (explicitly unsupported)
- Cgroupv1 / hybrid hierarchies (explicitly unsupported)

## Reporting

Report privately via GitHub Security Advisories at
<https://github.com/Strykar/pam_authnft/security/advisories/new>
("Report a vulnerability" tab under Security). Please include a
minimal reproducer, kernel version, nftables version, and the PAM service
stack (`/etc/pam.d/<service>`) in use.

Public issues and pull requests are not the right channel for vulnerability
reports. Backup contact channels and any PGP details live in the
RFC 9116 security.txt at
<https://github.com/Strykar/pam_authnft/blob/main/.well-known/security.txt>.

## Response timeline

Given the alpha status and single-maintainer cadence, the targets below
are best-effort and will firm up as the project matures. They are stated
explicitly so reporters know what to expect and when to escalate.

| Step | Target | Notes |
|---|---|---|
| Acknowledgment | within **5 business days** of the report being read | acknowledgment confirms receipt and that triage has begun; it is not a confirmation that the issue is in-scope or reproducible |
| Initial triage (in-scope, reproducible, severity-rated) | within **10 business days** | a report flagged out-of-scope is closed at this step with reasoning |
| Coordinated disclosure window | **90 days** from acknowledgment unless mutually negotiated | shorter if a fix ships sooner, longer if the reporter and maintainer agree (e.g., for downstream packagers) |
| Public advisory | simultaneous with the fix release | published as a GitHub Security Advisory + CVE if assigned, with credit to the reporter unless they request otherwise |
| Fix backports | as feasible to released versions | alpha series; long-term support branches do not exist yet |

Reporters who escalate during the window (e.g., observe an in-the-wild
exploit, or believe the issue is being exploited against them) MAY shorten
the disclosure window unilaterally; the maintainer will rush a fix in
parallel.

Reports that are not acknowledged within 14 days SHOULD be re-sent or
escalated via the email contact in
<https://github.com/Strykar/pam_authnft/blob/main/.well-known/security.txt>.

## Incident response runbook

The internal procedure followed for each report is documented in
<https://github.com/Strykar/pam_authnft/blob/main/docs/INCIDENT_RESPONSE.md>.
It exists so that a maintainer-of-the-day handling their first
incident has a clear path through triage → fix → disclosure →
post-mortem.
