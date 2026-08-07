# Packet-flow audit: what the wire actually does

Run: `sudo make test-packet-flow` (harness: `tests/packet_flow_matrix.sh`).
Captured run and `nft monitor trace` output: `research/packet-flow-testbed/`.
Kernel 7.1.5-arch1-2, 43 cases, every one matched its expected verdict.
Captured with `sudo env AUTHNFT_TRACE_DIR=research/packet-flow-testbed/traces
./tests/packet_flow_matrix.sh`, colours stripped; run.txt is that output
verbatim, so the matrix below can be regenerated from it.

Why this exists: the suite had ten packet-level assertions and not one of
them ever watched a packet be denied. Every existing test builds a
`policy accept` chain, hangs a `counter` on it, and asserts the counter did
or did not move. That answers "did the rule match". It cannot answer "did
the traffic get through", which is the only question the module exists to
decide. Two shipped defects lived in that gap (#103, #105) and a third
turned up while the harness was being written (C3 below).

The harness asks the wire question instead: for each configuration, does a
TCP payload round-trip, yes or no. Every case declares its expected verdict
in advance and fails if the wire disagrees, so the matrix is evidence rather
than description. It runs in a throwaway netns because it needs real deny
rules, and the cgroup scopes are real host scopes because the module's match
key is a cgroup path.

## The matrix

```
    CASE   EXPECTED OBSERVED PINS
    A1     PASS     PASS     in-session socket, allowed source, allowed port
    A2     BLOCK    BLOCK    same session, port the fragment does not name
    A3     BLOCK    BLOCK    allowed port, source not in the session set
    A4     PASS     PASS     same session over v6, source in the v6 set
    A5     BLOCK    BLOCK    v6 source no longer in the set
    B1     BLOCK    BLOCK    bob's socket, only alice's session open
    B2     PASS     PASS     bob's socket once bob's own session is open
    B3     BLOCK    BLOCK    bob's port from a source in neither session's set
    C1     PASS     PASS     pre-session (Class B) flow survives, ct rule present
    C2     BLOCK    BLOCK    same flow with the ct rule deleted
    C3     BLOCK    BLOCK    flow that predates conntrack tracking, ct rule added after
    D1     BLOCK    BLOCK    flow admitted during the session, revoked at close_session
    D2     BLOCK    BLOCK    new flow after close_session
    D3     BLOCK    BLOCK    same flow after a conntrack flush by source address
    D4     BLOCK    BLOCK    untagged flow revoked by a conntrack flush alone (the no-id fallback)
    E1     PASS     PASS     deny appended to the shared chain AFTER the jump
    E2     BLOCK    BLOCK    deny added BEFORE the jump: session chain shadowed
    E3     BLOCK    BLOCK    site deny as a separate base chain at priority filter
    E4     BLOCK    BLOCK    session opened after the site deny: its jump is shadowed
    E5     PASS     PASS     the session that predates the deny still works (E4 control)
    E6     PASS     PASS     same session, jump positioned after the ct rule (#105 fix)
    E7     BLOCK    BLOCK    deny still denies with the jump positioned (E6 control)
    E8     PASS     PASS     deny placed BEFORE any session, jump positioned after the ct rule
    E9     PASS     PASS     established traffic short-circuits at the ct rule, never entering a session chain
    E10    PASS     PASS     deny restored at boot, before the gate existed; gate and jump inserted above it
    E11    BLOCK    BLOCK    the boot-restored deny still denies (E10 control)
    F1     PASS     PASS     fragment allow rule, no site deny in play
    F2     BLOCK    BLOCK    fragment deny rule inside the session chain
    F3     PASS     PASS     fragment deny does not outlive the session
    G1     BLOCK    BLOCK    per-session chain and sets are gone after close
    G2     PASS     PASS     shared chain and its ct rule survive close (by design)
    G3     PASS     PASS     chain a fragment created survives close (INTEGRATIONS 4.5)
    G4     PASS     PASS     rule a fragment put in the shared chain survives close
    G5     BLOCK    BLOCK    leftover shared-chain fragment rule still drops after close
    I1     PASS     PASS     session flow admitted while the session is live (control)
    I2     BLOCK    BLOCK    flow admitted during the session, after close (D1 fixed)
    I3     PASS     PASS     untagged flow survives the same close (the SSH connection)
    I4     PASS     PASS     reusing a session id resurrects the revoked flow (why ids must not repeat)
    I5     BLOCK    BLOCK    a fresh id does not resurrect it (I4 control)
    I6     PASS     PASS     the session tag preserved the admin's mark bits (0xab000001, admin slice 0xab000000)
    I7     PASS     PASS     bystander flow survives the session's close (it was never the session's to revoke)
    I8     PASS     PASS     one session's close does not revoke a flow it never admitted (two sessions live)
    U1     BLOCK    BLOCK    udp flow admitted during the session, revoked at close
```

Every control is asserted, not printed: counter_moved and counter_static
fail the run when a counter disagrees with the story. Negative cases carry
arrival controls (the deny counter has to move, so a BLOCK caused by
traffic never being sent reads as a failure, not a pass), and the E arms
carry shadow controls that distinguish the two ways a packet can be
denied: in E2 the session counter stays 0, meaning the jump was never
reached; in E3 it moves, meaning the module accepted the packet and was
overruled afterwards. Same verdict on the wire, opposite causes.

## The traces

`nft monitor trace` is the kernel narrating the traversal, so it settles
questions that counters can only imply.

Admitted (`traces/admitted.txt`; first the SYN through the session chain,
then an established packet short-circuiting at the gate's unsessioned arm):

```
inet authnft filter rule jump session_a (verdict jump session_a)
inet authnft session_a rule socket cgroupv2 level 2 . ip saddr @session_a_v4
    tcp dport 19100 counter accept comment "sess-a" (verdict accept)
inet authnft filter rule ct state established,related
    ct mark & 0x00ffffff == 0x00000000 counter accept comment "ct-accept" (verdict accept)
```

Denied by the site's rule inside the shared chain (`traces/denied-by-site.txt`):

```
inet authnft filter rule jump session_a (verdict jump session_a)
inet authnft filter rule tcp dport 19101 counter drop comment "deny-19101" (verdict drop)
```

The packet enters the session chain, finds no rule for that port, returns,
and the next rule in the shared chain drops it. This is the working
arrangement.

Denied by a chain the module cannot see (`traces/denied-by-foreign-chain.txt`):

```
inet authnft filter rule jump session_a (verdict jump session_a)
inet authnft session_a rule socket cgroupv2 level 2 . ip saddr @session_a_v4
    tcp dport 19100 counter accept comment "sess-a" (verdict accept)
inet authnft sitedeny policy drop
```

The module accepted the packet and the packet died anyway, one line later,
in a base chain at a higher priority number on the same hook. This is #105
in the kernel's own words. `accept` ends the chain it fires in, not the
hook.

## Where the module's boundaries actually are

**It decides connection establishment, for sockets created inside the
session, in the input hook, and only if nothing else on that hook says no.**
Everything below follows from that sentence.

What it controls:

- Whether a new inbound connection to an in-session socket is admitted
  (A1, A2, A3), keyed on the socket's originating cgroup and the source
  address, isolated per session (B1, B2, B3).
- What a session may reach, when the fragment carries denies of its own
  (F1, F2), and those denies die with the session (F3).

What it does not control, and cannot:

- ~~**Flows already established.**~~ Fixed. Teardown used to remove the
  admission path and nothing else, so an admitted flow ran to its natural
  end. Each session now tags its connections with an id in the conntrack
  mark and the shared chain accepts established traffic only while that id
  is live, so close revokes the flow on its next packet (D1, I2), for UDP
  the same as for TCP (U1). A conntrack flush by source address remains
  the fallback where no id was allocated; D4 isolates it (in D1-D3 the
  gate revokes first). The revocation boundary runs exactly along
  admission: an untag rule at the end of each session chain restores the
  mark of flows the chain walked but did not admit, so close never
  revokes a bystander the site admitted (I7, I8, issue #123) and never
  touches pre-session flows (I3).
- **Whether an accept is final.** Any base chain at a higher priority number
  on the same hook can overrule it (E3), and the module has no way to detect
  that arrangement. An earlier terminal rule in the shared chain used to
  prevent the session chain from running (E2); it no longer can, because the
  jump is now placed immediately after the ct rule rather than appended, so
  it precedes any deny whenever that deny was added (E6, E8). The ct rule
  stays first, so established traffic does not walk the session chains (E9).
- **Traffic conntrack never saw the start of.** The ct rule carries
  pre-session flows only when conntrack was already tracking them (C1
  versus C3). It is not a retroactive rescue.
- **Anything a fragment created outside the per-session chain.** Chains
  survive (G3), and rules placed in the shared chain survive and keep
  denying traffic for sessions that no longer exist (G4, G5).

What close_session cleans up, exactly: the jump rule, the per-session
chain, the three per-session sets (G1). What it leaves: the table, the
shared chain, the ct rule (G2, by design, they are shared), every conntrack
entry, and every object a fragment created outside its own chain (G3, G4).

## Audit of the tests we already had

| Test | What it proves | What it was read as proving |
|---|---|---|
| 10.11 / PM1 | the cgroup match fires for an allowed source and not for a disallowed one | that allowed traffic is admitted and disallowed traffic is blocked |
| 10.12 / PM2 | `socket cgroupv2` does not match a pre-scope socket | that Class B traffic survives via the ct rule (ARCHITECTURE.txt says this test validates it; it does not, it validates the negative half) |
| 10.13 / PM3 | one session's counter does not move on another's traffic | that sessions cannot reach each other's ports |
| 10.6, 10.15, 10.18 | the chain, sets, jump rule and scope are gone after close | that access ends at close |
| ASSURANCE_CASE C3 | nftables objects are bounded by a 24h element timeout | that a session's access is bounded |

Every row is true on the left and was over-read on the right. The pattern
is the same each time: an assertion about the module's own objects being
taken for an assertion about traffic. None of these tests is wrong, and
none of them had to change. What was missing was any test that put a packet
in front of a deny.

Two structural notes for future harnesses:

- A half-built ruleset in this module's shape has an accept policy and no
  deny, so a setup failure makes every BLOCK case report PASS. The first
  run of this harness did exactly that: `ip netns exec` mounts a fresh
  sysfs, which hid the cgroup2 tree, every element insert failed with
  ENOENT, and nine cases reported a clean PASS from an empty table. Setup
  failures now abort the run rather than being recorded as observations.
- The harness tripped over #105 while it was being written. Bob's jump rule
  was appended after the site deny and was silently shadowed, exactly the
  failure the issue describes. The bug is easy to hit even when you know it
  exists.

## Findings

| # | Finding | Status |
|---|---|---|
| 1 | Established flows outlive close_session (D1) | **fixed.** The ct mark gate shipped; D1's expectation flipped from PASS to BLOCK and that PASS was the bug. Pinned by D1-D4, I1-I6, U1 and integration 10.27 |
| 2 | Two of three site-deny placements silently defeat the module (E2, E3) | issue #105; the ordering half fixed by `0327f21`, pinned by E4-E9 and integration 10.26. E3 remains, unfixable by rule order |
| 3 | The ct rule does not rescue a flow conntrack was not already tracking (C3) | issue #111, precondition documented in ARCHITECTURE.txt, pinned by C1/C2/C3 |
| 4 | ARCHITECTURE.txt cites 10.12 as validating Class B survival; 10.12 validates the negative half only | corrected to cite C1/C2 |
| 5 | A rule an included fragment adds to the shared chain outlives every session and keeps denying (G4, G5) | working as designed (INTEGRATIONS 4.5/4.6); pinned by G4/G5 |
| 6 | Session close revoked flows the session never admitted: the tag rule stamped every new flow that walked the chain, and one login's logout cut another's traffic (I7, I8) | issue #123, **fixed** by the end-of-chain untag rule; falsified on the wire before the fix was written, pinned by I7/I8 and integration 10.32 (revert-flip verified) |

Finding 5 is a persistence property, not a bypass. An included file is
allowed to add rules to the shared chain (INTEGRATIONS 4.6, and
`NFT_FRAG_INCLUDED` drops the shared-chain guard for exactly this). Such a
rule lives outside the per-session chain, so close_session never had a handle
on it and it persists (INTEGRATIONS 4.5 already documents that fragment
objects outside the session chain are not cleaned up). G4/G5 pin the wire
consequence: the leftover rule keeps dropping traffic after the session ends.
INTEGRATIONS 4.5 now says so directly: rules an included file adds to the
shared chain outlive every session and keep acting on traffic, and retiring
them is the site's job.

### Correction: real finding, wrong instrument (issue #108)

The include-boundary finding was real. At the time it was found,
`nft_handler_setup` called plain `validate_fragment_buf` on the top-level
fragment only (no include recursion), so an included `flush ruleset` passed
validation and libnftables executed it at commit time. Confirmed against the
code that shipped before the fix: `git show 5baef33^:src/nft_handler.c` calls
`validate_fragment_buf(pamh, user_conf_path, ...)` with no include callback.

What was wrong was the evidence, not the conclusion. The probe ran raw
`nft -f` in a bare netns, which has no pam_authnft in front of it, so it
demonstrated libnftables' own include resolution, not the module's
validation. Correct answer, wrong instrument: had the module already
validated includes, that same probe would have been a false positive, and
the only reason it was not is that the module happened to have the bug. A
claim about what the module does has to be exercised through the module.

Fixed by `5baef33` (issue #108): `nft_handler_setup` now calls
`authnft_validate_fragment_includes`, which walks every `include` with
`validate_include`, stats each file (uid 0, not world-writable, regular file,
the bar the top-level fragment already clears), reads it, and re-runs the
verb scan on its contents, with cycle detection and depth/file caps. Verified
through the real module path by `make test-include-walk` (8 cases, all pass),
including the exact case first seen through the bad probe:

```text
included flush ruleset                  -> rejected (rc=-1)
bad verb three includes deep            -> rejected (rc=-1)
self-referential include                -> rejected (rc=-1)
world-writable / non-root-owned include -> rejected (rc=-1)
included shared-chain rule (4.6)        -> accepted (rc=0), by design
```
