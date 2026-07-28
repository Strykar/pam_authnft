# Packet-flow audit: what the wire actually does

Run: `sudo make test-packet-flow` (harness: `tests/packet_flow_matrix.sh`).
Captured run and `nft monitor trace` output: `research/packet-flow-testbed/`.
Kernel 7.1.5-arch1-1, 23 cases, every one matched its expected verdict.

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
    B1     BLOCK    BLOCK    bob's socket, only alice's session open
    B2     PASS     PASS     bob's socket once bob's own session is open
    B3     BLOCK    BLOCK    bob's port from a source in neither session's set
    C1     PASS     PASS     pre-session (Class B) flow survives, ct rule present
    C2     BLOCK    BLOCK    same flow with the ct rule deleted
    C3     BLOCK    BLOCK    flow that predates conntrack tracking, ct rule added after
    D1     PASS     PASS     flow admitted during the session, after close_session
    D2     BLOCK    BLOCK    new flow after close_session
    D3     BLOCK    BLOCK    same flow after a conntrack flush by source address
    E1     PASS     PASS     deny appended to the shared chain AFTER the jump
    E2     BLOCK    BLOCK    deny added BEFORE the jump: session chain shadowed
    E3     BLOCK    BLOCK    site deny as a separate base chain at priority filter
    F1     PASS     PASS     fragment allow rule, no site deny in play
    F2     BLOCK    BLOCK    fragment deny rule inside the session chain
    F3     PASS     PASS     fragment deny does not outlive the session
    G1     BLOCK    BLOCK    per-session chain and sets are gone after close
    G2     PASS     PASS     shared chain and its ct rule survive close (by design)
    G3     PASS     PASS     chain a fragment created survives close (INTEGRATIONS 4.5)
    G4     PASS     PASS     rule a fragment put in the shared chain survives close
    G5     BLOCK    BLOCK    leftover shared-chain fragment rule still drops after close
```

Negative cases carry arrival controls: the deny counters have to move, so a
BLOCK caused by traffic never being sent reads as a failure, not a pass.
E2 and E3 carry shadow controls that distinguish the two ways a packet can
be denied. In E2 the session counter is 0, meaning the jump was never
reached. In E3 it is 3, meaning the module accepted the packet and was
overruled afterwards. Same verdict on the wire, opposite causes.

## The traces

`nft monitor trace` is the kernel narrating the traversal, so it settles
questions that counters can only imply.

Admitted (`traces/admitted.txt`):

```
inet authnft filter rule jump session_a (verdict jump session_a)
inet authnft session_a rule socket cgroupv2 level 2 . ip saddr @session_a_v4
    tcp dport 19100 counter accept comment "sess-a" (verdict accept)
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

- **Flows already established.** Teardown removes the admission path and
  nothing else. An admitted flow keeps running to its natural end (D1).
  Conntrack is state the module never had a handle on: `grep conntrack src/`
  returns nothing. A ctnetlink flush does revoke it (D3), which is what
  authpf does and what #103 proposes.
- **Whether an accept is final.** Any base chain at a higher priority number
  on the same hook can overrule it (E3), and any earlier terminal rule in
  the shared chain can prevent the session chain from ever running (E2).
  The module has no way to detect either arrangement.
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
| 1 | Established flows outlive close_session (D1) | issue #103, docs corrected, pinned by D1/D2/D3 |
| 2 | Two of three site-deny placements silently defeat the module (E2, E3) | issue #105, pinned by E1/E2/E3 |
| 3 | The ct rule does not rescue a flow conntrack was not already tracking (C3) | undocumented precondition, pinned by C1/C2/C3, no issue filed yet |
| 4 | ARCHITECTURE.txt cites 10.12 as validating Class B survival; 10.12 validates the negative half only | corrected to cite C1/C2 |
| 5 | A rule in the shared chain outlives every session and keeps denying (G4, G5) | reachable only through `include`, see finding 6; pinned |
| 6 | Fragment content validation stops at the `include` boundary | not filed, security-adjacent, see below |

### Finding 6, in detail

`check_statement` in `src/nft_validator.c` rejects two things in a fragment:
a denylisted verb (`flush`, `delete`, `destroy`, `reset`, ...) and any
`add rule inet authnft filter ...` targeting the shared chain.
`validate_fragment_buf` only ever scans the bytes of the top-level fragment.
libnftables resolves `include` directives later, at execution, so nothing an
included file contains is scanned by either guard. INTEGRATIONS 4.6
recommends the include pattern as the way to compose shared policy, and its
worked example puts rules in the shared chain from an included file.

Both halves measured in a netns:

```
included "add rule inet authnft filter ... drop"  -> lands in the shared chain
included "flush ruleset"                          -> accepted and executed,
                                                     ruleset went 5 lines -> 0
```

A rule placed there survives every session (G4), keeps denying traffic for
sessions that no longer exist (G5), and shadows every jump rule appended
after it (E2), so it is also a way to silently disable the module.

Reachability: the module checks ownership and mode on the top-level fragment
only. Keeping included files root-owned is documented as the administrator's
job (README, ADMIN_GUIDE), so an admin who follows the convention has no
attacker path here. Where the convention is not followed, an included file
that a non-root user can write turns into arbitrary root-executed nftables
commands at the next session open, and the verb denylist that exists to stop
exactly that does not apply. The gap is that the docs present the verb scan
as a property of fragments without saying it stops at the include boundary.

Not filed as a public issue: it describes how to get around a security
control, and SECURITY.md routes that to a private advisory.
