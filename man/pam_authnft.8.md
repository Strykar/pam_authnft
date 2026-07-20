% PAM_AUTHNFT(8) pam_authnft | System Administration
% Avinash H. Duduskar
% 2026

# NAME

pam_authnft - PAM session module that binds nftables rules to authenticated sessions

# SYNOPSIS

**pam_authnft.so** [*rhost_policy=strict|lax|kernel*] [*claims_env=NAME*] [*AUTHNFT_NO_SANDBOX=1*]

# DESCRIPTION

**pam_authnft** is a PAM session module that pins each authenticated user
session to a systemd transient **.scope** unit and inserts a
*{ cgroup_path . src_ip }* element into a named nftables set. Rules
authored in a per-user fragment are then evaluated against that set,
binding packet-filter policy to the session for its entire lifetime
without referencing PIDs, UIDs, or usernames at match time.

The module exports only **pam_sm_open_session** and
**pam_sm_close_session**. It is not an authentication module.

# OPTIONS

**rhost_policy=lax** (default)
:   If *PAM_RHOST* parses as an IPv4 or IPv6 literal, it is normalized
    to canonical form (IPv6 v4-mapped addresses are extracted to plain
    IPv4) and the session element is bound into the per-session IPv4
    or IPv6 set as *{ cgroup_path . src_ip }*. Otherwise —
    *PAM_RHOST* missing, a hostname (*UseDNS yes* in sshd), or
    unparseable — fall back to the per-session cgroup-only set, keyed on
    *cgroup_path* alone. Session identity is still enforced; only the
    src_ip leg is dropped.

**rhost_policy=strict**
:   Restore the pre-0.2 behaviour: a valid IP literal in *PAM_RHOST* is
    required; the session is denied with **PAM_SESSION_ERR** otherwise.

**rhost_policy=kernel**
:   Derive the peer IP from the session process's own ESTABLISHED TCP
    socket via **NETLINK_SOCK_DIAG** (see **ss**(8)), querying AF_INET6
    first then AF_INET. The address comes from the kernel, not from the
    application, so a misconfigured or hostile PAM caller cannot forge it
    through *PAM_RHOST*. When the session process holds more than one
    ESTABLISHED TCP socket — for example an **nss_ldap** or krb5-over-TCP
    connection still open from the authentication phase — the module
    considers only the inbound server socket, the one whose local port is
    a TCP listener on the host; an outbound socket the process holds is
    excluded outright, not merely deprioritized. If that disambiguation
    cannot be made (listen-port enumeration denied), the filter is
    disabled and the first non-loopback match is used, so on such hosts
    verify the bound address matches the client. The kernel-reported address is normalized
    (including v4-mapped v6 extraction). If the kernel lookup succeeds and
    the normalized value differs from a parseable *PAM_RHOST*, the module
    logs a **LOG_WARNING** of the form
    *"PAM_RHOST/kernel peer divergence: app='X' kernel='Y' — trusting
    kernel"*. If *PAM_RHOST* was set but unparseable and the kernel
    lookup succeeds, a **LOG_WARNING** is emitted noting the silent
    substitution. Common causes: sshd behind a TCP load balancer (PROXY
    protocol not terminated) or **UseDNS yes**. If the kernel lookup
    fails (no ESTABLISHED TCP socket on the session PID, netlink denied),
    the module falls through to **rhost_policy=lax** semantics. The
    inode scan is capped at **INODES_CAP** (64); if the session PID
    holds more socket inodes, a **LOG_WARNING** is emitted and the
    lookup may miss the session's TCP socket.
    **sshd privsep note:** sshd runs **pam_open_session**(3) in its
    privileged monitor process, and that process keeps the client TCP
    socket open for the life of the connection, so the kernel lookup
    is expected to succeed there. Verified against the OpenSSH 10.4
    source, whose README.privsep documents the multi-binary privsep
    model. On a server whose PAM caller does not hold the connection
    socket, the lookup falls through to **rhost_policy=lax**. Test
    against your target OpenSSH version before relying on this policy
    in production.

**claims_env=NAME**
:   Look up PAM environment variable *NAME* for a kernel-keyring serial
    (decimal *key_serial_t*). When present, the keyed payload is read via
    **keyctl**(2), sanitized to a printable ASCII subset, and embedded
    inside the nftables element's *comment* field as
    *"\<user\> (PID:\<pid\>) [\<tag\>]"*. The producer of the keyring
    entry is responsible for setting an appropriate timeout
    (*KEYCTL_SET_TIMEOUT*) and access mode (*KEYCTL_SETPERM*); this
    module never writes keys, only reads. If the env var is absent, the
    serial is malformed, or the key is inaccessible, the module
    proceeds without a tag — **claims_env** is non-fatal by design.
    See **keyctl**(2), **keyrings**(7).

**AUTHNFT_NO_SANDBOX=1**
:   Disable the seccomp-BPF sandbox. Accepted as a module argument in the
    PAM config or as an environment variable. Intended for debugging
    only; do not enable in production.

# OPERATION

On session open, the module:

1. Validates *PAM_USER* against a conservative charset
   (*[A-Za-z0-9._-]*, maximum 32 characters, no leading hyphen or dot).
2. Short-circuits to **PAM_SUCCESS** for the **root** user.
3. Retrieves *PAM_RHOST* and normalizes it: IPv4 / IPv6 literals pass
   through; an IPv6 zone suffix (*fe80::1%eth0*) is stripped because
   nftables *ip6 saddr* does not accept zones. Hostnames (*UseDNS yes*)
   and unparseable values fall through to the cgroup-only path under
   the default **rhost_policy=lax**, or are rejected under
   **rhost_policy=strict**.
4. Installs a seccomp-BPF allowlist with **SCMP_ACT_KILL** as the
   default action, after setting **PR_SET_NO_NEW_PRIVS**.
5. Calls **StartTransientUnit** on
   *org.freedesktop.systemd1.Manager* to create a scope named
   *authnft-\<user\>-\<pid\>.scope* under *authnft.slice*.
6. Constructs the cgroup path deterministically from the scope unit
   name (e.g., *authnft.slice/authnft-alice-12345.scope*). The kernel
   resolves this path to a cgroupv2 inode at nft insert time; no
   **stat**(2) is performed by the module.
7. Persists session state (cgroup path, scope unit, per-session
   chain/set names, jump-rule handle, normalized remote IP, optional
   claims tag, correlation token) in PAM data under the key
   *authnft_cg_id*. The key name is retained for compatibility; the
   stored value shape is an internal ABI.
8. Verifies the user is a member of the **authnft** group. Non-members
   pass through with **PAM_SUCCESS**.
9. Validates the fragment at */etc/authnft/users/\<user\>*: must be
   root-owned, not world-writable. Content validation rejects
   disallowed verbs (*flush*, *delete*, *reset*, *list*, *rename*)
   and include paths outside */etc/authnft/*.
10. Issues three libnftables calls:
    - **Call 1**: *add table*, shared *filter* chain with
      *ct state established,related accept*, per-session chain
      *session_\<user\>_\<pid\>*, three per-session sets, session
      element.
    - **Call 2** (ECHO|HANDLE): *add rule* jump to per-session chain;
      parse kernel-assigned handle from output buffer.
    - **Call 3**: read fragment, substitute four placeholders
      (*@session_v4*, *@session_v6*, *@session_cg*, *@session_chain*)
      with live per-session names, execute.

On session close, the stored session state is retrieved from PAM data.
The jump rule is deleted by handle, the per-session chain is flushed
and deleted, and the three per-session sets are deleted (single
transaction). Cleanup failures are logged but do not prevent session
teardown.

If session open fails after the systemd transient scope was created,
the module rolls back the partial state: any per-session chain,
sets, and jump rule already inserted are removed best-effort, and
the scope is stopped via **StopUnit** on the same D-Bus path used
to create it. A failed open therefore leaves the kernel and systemd
state indistinguishable from "session was never attempted" — a
caller can retry without resource accumulation. The exception is
the narrow window where call 2 commits the jump rule but the
kernel-returned handle fails to parse: nftables has no
delete-by-name primitive, so the orphan jump rule persists until
the table is deleted. This path is empirically rare (it requires a
libnftables echo-format regression).

# FILES

*/etc/authnft/users/\<user\>*
:   Per-user nftables fragment. Must be owned by root and not
    world-writable. Included at the top level of the nftables command
    stream after the session element has been inserted. The fragment
    MAY use nftables' **include** directive to pull in shared rules
    from other files (e.g., a group-level fragment under
    */etc/authnft/groups/*); libnftables resolves includes
    transitively. pam_authnft does not recurse ownership checks into
    included files — the admin MUST ensure every transitively
    included file is also root-owned and not world-writable. When a
    fragment contains an **include** directive, the module emits a
    **LOG_INFO** reminder about this responsibility. See
    **docs/INTEGRATIONS.txt** §4.6 for the composition pattern and
    a cycle-detection note.

*/etc/systemd/system/authnft.slice*
:   Parent slice unit for all session scopes. Use
    **systemd.resource-control**(5) directives to apply combined
    limits. Shipped with all directives commented out.

*/usr/lib/security/pam_authnft.so*
:   The module itself.

*/run/authnft/sessions/\<scope_unit\>.json*
:   Per-session identity file written on open_session and removed on
    close_session. Mode 0644 root:root, JSON schema documented in
    **docs/INTEGRATIONS.txt** §5.6. Intended for unprivileged
    observers (SIEM agents, monitoring daemons, operator consoles)
    that need to correlate a cgroup inode back to the owning
    session. The directory is created by
    */usr/lib/tmpfiles.d/authnft.conf* at boot.

*/usr/lib/tmpfiles.d/authnft.conf*
:   systemd-tmpfiles(5) snippet that creates */run/authnft/sessions/*
    and reaps orphaned per-session files older than 7 days.

# ENVIRONMENT

**AUTHNFT_NO_SANDBOX**
:   If set to a non-empty value, **sandbox_apply** becomes a no-op.
    Identical effect to passing **AUTHNFT_NO_SANDBOX=1** as a PAM
    module argument.

**AUTHNFT_CORRELATION**
:   Read from the PAM environment (set via **pam_putenv**(3) by an
    upstream module) at **pam_sm_open_session** time. Used as the
    *AUTHNFT_CORRELATION* field in the journald audit events
    (AUTHNFT_EVENT=open, AUTHNFT_EVENT=close) to join session
    lifecycle events to the authentication event that produced
    them. Sanitized to *[A-Za-z0-9_.:-]* and truncated at 64 bytes.
    If absent or empty-after-sanitization, pam_authnft synthesizes
    a unique token for the session. See
    **docs/INTEGRATIONS.txt** §6.2 for the full contract.

# AUDIT EVENTS

pam_authnft emits structured events to the systemd journal at
session open and close with *SYSLOG_IDENTIFIER=pam_authnft*. Filter
with `journalctl -t pam_authnft`. The two events are joined by a
shared *AUTHNFT_CORRELATION* token. Fields and SIEM integration
guidance: **docs/INTEGRATIONS.txt** §6.2.

In parallel, every fragment-rejection path also emits an
**AUDIT_USER_ERR** (1109) record via the Linux audit subsystem
(see **audit**(7)). The application portion of the record carries
the structured key-value pair *op=authnft-fragment-reject*, a short
*reason* tag (*missing*, *perms*, *content*, or *nft-syntax*), the
PAM user, and the fragment path. SOC consumers that scrape
*/var/log/audit/audit.log* receive denied-session events without
having to subscribe to the systemd journal as well. The pam_syslog
prose channel stays in place for operator-facing logs; the audit
channel is additive. Audit-subsystem failure (disabled, missing
*CAP_AUDIT_WRITE*) is non-fatal — the PAM rejection still
propagates. Field schema: **docs/INTEGRATIONS.txt** §6.2.7.

# RETURN VALUES

**PAM_SUCCESS**
:   Session set up successfully, root short-circuit, or user is not a
    member of the **authnft** group.

**PAM_SESSION_ERR**
:   Generic session setup failure: invalid user, unparseable *PAM_RHOST*
    under **rhost_policy=strict**, seccomp load failure, systemd handoff
    failure, or cgroup inode resolution failure.

**PAM_AUTH_ERR**
:   Fragment missing, wrong ownership, world-writable, or contains a
    syntax error rejected by libnftables. A diagnostic is shown to the
    user via **pam_error**(3).

**PAM_SERVICE_ERR**
:   libnftables context allocation failed or the setup transaction
    failed at the kernel.

**PAM_BUF_ERR**
:   Command buffer overflow during nftables transaction assembly.

# EXAMPLE PAM STACK

In */etc/pam.d/sshd*, after *pam_systemd.so*:

    session  optional  pam_authnft.so

Or, with PAM-level group gating:

    session  [success=1 default=ignore]  pam_succeed_if.so  user notingroup authnft  quiet
    session  required  pam_authnft.so

# SECURITY

The fragment trust model is identical to */etc/nftables.conf* and
sudoers includes: only root writes fragments. The module enforces
ownership and mode before loading. End users cannot author or modify
their own fragments.

The seccomp allowlist is derived empirically from strace traces of
complete open/close cycles; syscalls reached only during pre-sandbox
startup (such as **execve**(2) from the service binary) are
deliberately excluded.

# BUGS

Cgroupv1 and hybrid hierarchies are unsupported. Non-systemd init is
unsupported. On PAM stacks where the process invoking
**pam_sm_open_session** is not the direct parent of the user session,
the resolved cgroup may differ from the session's eventual cgroup.

Report issues via GitHub Security Advisories on *Strykar/pam_authnft*
for security-sensitive reports, or the public issue tracker otherwise.

# SEE ALSO

**pam.conf**(5), **pam_systemd**(8), **nft**(8), **systemd.scope**(5),
**systemd.slice**(5), **systemd.resource-control**(5),
**seccomp**(2), **cgroups**(7)
