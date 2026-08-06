#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# What actually happens to a packet? Run it here: `sudo make test-packet-flow`.
#
# The rest of the suite proves that rules MATCH. Every packet-level test in
# this repo builds a `policy accept` chain, hangs a `counter` off it, and
# asserts the counter moved or did not. None of them ever put a packet in
# front of a deny, so none of them can tell you whether a session admits
# traffic, whether teardown revokes it, or whether the ct rule the docs call
# load-bearing is load-bearing. Issue #103 and #105 both lived in that gap.
#
# This harness answers the wire question instead: for each configuration,
# does a real TCP payload round-trip, yes or no. Every case states its
# expected verdict up front and fails if the wire disagrees, so the matrix
# it prints is evidence rather than description.
#
# Everything runs in a throwaway netns, so the deny rules this needs cannot
# touch the host's connectivity. The cgroup scopes are real, on the host
# hierarchy, because cgroup and network namespaces are orthogonal and the
# module's match key is a cgroup path.
#
# Exit codes: 0 every case matched its expected verdict, 1 at least one did
# not, 77 the kernel/nft lacks `socket cgroupv2` (below the documented floor).
set -u

RED='\033[1;31m' BLUE='\033[1;34m' YELLOW='\033[1;33m' GREEN='\033[1;32m' RESET='\033[0m'

NS=authnft_flow
SVC=19100          # port the session fragment allows
ALT=19101          # port the fragment does not mention
OK_SRC=127.0.0.1   # source address in the session's set
BAD_SRC=127.0.0.2  # source address not in any set
SCOPE_A=authnft-flow-alice
SCOPE_B=authnft-flow-bob

# ---------------------------------------------------------------- outer
if [[ "${1:-}" != "--inner" ]]; then
    [[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
    # conntrack(8) is required, not optional: D4 is the only case where a
    # conntrack flush is the sole revoker (the documented fallback for a
    # session that never got an id), and ASSURANCE_CASE and CONCEPTS cite
    # the D arms as the revocation pin. Skipping it while still reporting
    # success would leave shipped docs citing an arm that never ran.
    for t in ip nft socat ss systemd-run systemctl conntrack; do
        command -v "$t" >/dev/null 2>&1 || { echo "missing required tool: $t" >&2; exit 1; }
    done
    [[ -e /sys/fs/cgroup/cgroup.controllers ]] || {
        echo "cgroupv2 unified hierarchy not mounted at /sys/fs/cgroup" >&2; exit 1; }

    # Feature probe, same contract as packet_match_headless.sh: a kernel
    # without socket-cgroupv2 support is "unsupported" (77), not a failure.
    nft add table inet authnft_flow_probe 2>/dev/null || {
        echo "cannot create nft tables (no CAP_NET_ADMIN?)" >&2; exit 1; }
    probe=1
    nft add set inet authnft_flow_probe s \
        '{ typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }' 2>/dev/null || probe=0
    nft delete table inet authnft_flow_probe 2>/dev/null
    [[ $probe -eq 1 ]] || {
        echo "kernel/nft lacks 'socket cgroupv2 level 2 . ip saddr' support" >&2; exit 77; }

    KEEPERS=()
    outer_cleanup() {
        (( ${#KEEPERS[@]} > 0 )) && kill "${KEEPERS[@]}" 2>/dev/null
        systemctl stop "$SCOPE_A.scope" "$SCOPE_B.scope" 2>/dev/null
        ip netns pids $NS 2>/dev/null | xargs -r kill 2>/dev/null
        ip netns del $NS 2>/dev/null
        return 0
    }
    trap outer_cleanup EXIT

    make_scope() { # <unit>
        systemd-run --scope --slice=authnft.slice --unit="$1" sleep 300 >/dev/null 2>&1 &
        KEEPERS+=($!)
        for _ in $(seq 1 25); do
            [[ -d "/sys/fs/cgroup/authnft.slice/$1.scope" ]] && return 0
            sleep 0.2
        done
        return 1
    }
    make_scope "$SCOPE_A" || { echo "could not create probe scope $SCOPE_A" >&2; exit 1; }
    make_scope "$SCOPE_B" || { echo "could not create probe scope $SCOPE_B" >&2; exit 1; }

    ip netns del $NS 2>/dev/null
    ip netns add $NS || exit 1
    ip -n $NS link set lo up

    printf "${BLUE}>>> PACKET-FLOW MATRIX (kernel %s)${RESET}\n" "$(uname -r)"
    ip netns exec $NS "$0" --inner
    exit $?
fi

# ---------------------------------------------------------------- inner
# `ip netns exec` unshares the mount namespace and mounts a fresh sysfs so
# /sys/class/net reflects the new netns. That hides the cgroup2 mount
# underneath it, so both the element insert (nft resolves the path) and the
# scope migration (writing cgroup.procs) fail with ENOENT. Mount cgroup2
# again: it is a single hierarchy, so this is the same tree the host sees,
# not a new one.
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
[[ -d /sys/fs/cgroup/authnft.slice ]] || {
    echo "cgroup2 not visible inside the netns; cannot run" >&2; exit 1; }

CG_A="authnft.slice/$SCOPE_A.scope"
CG_B="authnft.slice/$SCOPE_B.scope"
RC=0
ROWS=()
SRV_PIDS=()

inner_cleanup() { (( ${#SRV_PIDS[@]} > 0 )) && kill "${SRV_PIDS[@]}" 2>/dev/null; return 0; }
trap inner_cleanup EXIT

note() { printf "\n${YELLOW}%s${RESET}\n" "$*"; }

# Start an echo server on <port>, inside <cgroup path> so that
# `socket cgroupv2 level 2` sees the session scope. The cgroup write happens
# before exec, so the listening socket is allocated inside the scope: that is
# the Class A case, and PM2 already proves the alloc-time invariant it rests on.
serve() { # <port> <cgroup-relative-path>
    local port="$1" cg="$2"
    bash -c "echo \$\$ > /sys/fs/cgroup/$cg/cgroup.procs
             exec socat TCP-LISTEN:$port,reuseaddr,fork EXEC:/bin/cat" &
    SRV_PIDS+=($!)
    for _ in $(seq 1 50); do
        ss -Hltn "sport = :$port" 2>/dev/null | grep -q . && return 0
        sleep 0.1
    done
    return 1
}

# The wire observable: does a payload round-trip? Not "did a counter move",
# not "did the SYN leave". Returns 0 for PASS, 1 for BLOCK.
flow() { # <src-addr> <port>
    local out
    out=$(printf 'ping\n' | timeout 4 socat -T2 - \
          "TCP:127.0.0.1:$2,bind=$1,connect-timeout=2" 2>/dev/null)
    [[ "$out" == "ping" ]]
}

verdict() { flow "$1" "$2" && echo PASS || echo BLOCK; }

# Record a case. Fails the run when the wire disagrees with the claim.
check() { # <case-id> <expected PASS|BLOCK> <observed> <what this pins>
    local id="$1" want="$2" got="$3" desc="$4"
    if [[ "$want" == "$got" ]]; then
        printf "${GREEN}[ OK ]${RESET} %-6s %-5s  %s\n" "$id" "$got" "$desc"
        ROWS+=("$id|$want|$got|ok|$desc")
    else
        printf "${RED}[FAIL]${RESET} %-6s %-5s  %s (expected %s)\n" "$id" "$got" "$desc" "$want"
        ROWS+=("$id|$want|$got|MISMATCH|$desc")
        RC=1
    fi
}

# ---- the module's own state, built as nft_handler_setup builds it -------
# Call 1 order: table, shared chain, ct rule, per-session chain, three sets,
# element. The fragment and untag then fill the chain, and the jump lands
# last, exposing a complete chain. The trailing site deny is placement C
# from issue #105, the only one that admits traffic; every functional case
# below therefore runs on the arrangement that actually works.
# Setup failures are fatal, never observations. A half-built table has an
# accept policy and no deny, so every BLOCK case would report PASS and the
# run would look like a fleet of real findings. Die instead.
# Writes to stdout as well as stderr. The inner script runs under
# `ip netns exec`, and a die that only reached stderr came out empty at
# the caller, so the run aborted with no stated reason. A harness that
# stops without saying why is barely better than one that lies.
die() { printf "${RED}>>> SETUP FAILED: %s${RESET}\n" "$*" | tee /dev/stderr; exit 1; }

module_up() { # <session-tag> <cgroup path> <src addr>
    local tag="$1" cg="$2" src="$3"
    nft -f - <<RULES || die "could not build session state for $tag"
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
add chain inet authnft session_$tag
add set inet authnft session_${tag}_v4 { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }
add set inet authnft session_${tag}_v6 { typeof socket cgroupv2 level 2 . ip6 saddr; flags timeout; }
add set inet authnft session_${tag}_cg { typeof socket cgroupv2 level 2; flags timeout; }
add element inet authnft session_${tag}_v4 { "$cg" . $src timeout 1d }
add rule inet authnft session_$tag socket cgroupv2 level 2 . ip saddr @session_${tag}_v4 tcp dport $SVC counter accept comment "sess-$tag"
RULES
    session_built "$tag"
}

# Every object module_down will later delete has to exist now. A session
# that builds partially makes module_down's transaction fail atomically,
# which leaves the jump rule in place; the arm then measures a session that
# never closed and reports it as one that did. Cost an hour in section I.
session_built() { # <session-tag>
    local tag="$1" t
    t=$(nft list table inet authnft 2>/dev/null) || t=""
    for obj in "chain session_$tag" "set session_${tag}_v4" \
               "set session_${tag}_v6" "set session_${tag}_cg"; do
        printf '%s' "$t" | grep -q "${obj#* } " || die "session $tag: missing $obj"
    done
}

# The shared gate, as the module builds it. Two arms, not one unconditional
# accept: untagged flows (the SSH connection, anything the module does not
# govern) accept outright, tagged flows only while their id is live.
#
# The unsessioned arm keeps the comment "ct-accept" because it plays the
# same role the single rule used to, and the arms that measure Class B
# survival count it. Sections that never tag a session see no behavioural
# change from this: their flows carry mark 0 and the unsessioned arm takes
# them, exactly as the old rule did.
ct_rule() {
    # Inserted, not added, as the module does it: the chain can already
    # hold a boot-restored site deny, and an appended gate lands behind
    # it (E10). The live arm goes first in the buffer because sequential
    # inserts stack at the head in reverse.
    nft -f - <<'RULES' || die "ct gate"
add set inet authnft live_sessions { type mark; }
insert rule inet authnft filter ct state established,related ct mark and 0x00ffffff @live_sessions counter accept comment "ct-live"
insert rule inet authnft filter ct state established,related ct mark and 0x00ffffff 0x0 counter accept comment "ct-accept"
RULES
}

# Tag a session's new connections, as the module's session chain does, and
# register the id as live. Only the sections that measure revocation need
# this; elsewhere a session's flows stay untagged.
session_tag() { # <session-tag> <session-id>
    nft insert rule inet authnft "session_$1" ct state new ct mark set ct mark and 0xff000000 or "$2" \
        || die "tag rule for $1"
    # The untag, as the module's call 4 appends it: unadmitted flows leave
    # the chain with the mark they entered with (issue #123).
    nft add rule inet authnft "session_$1" ct state new ct mark set ct mark and 0xff000000 comment '"untag"' \
        || die "untag rule for $1"
    nft add element inet authnft live_sessions "{ $2 }" || die "live element for $1"
}
revoke() { nft delete element inet authnft live_sessions "{ $1 }" || die "revoke $1"; }
# Plain append. In a chain that holds only the ct rule this lands the jump
# in the same place the module puts it, which is why the sections that just
# need a working session use it. Where the placement itself is the thing
# under test, the E arms use jump_rule_after_ct and say so.
jump_rule() { nft add rule inet authnft filter jump "session_$1" || die "jump rule for $1"; }
# The placement the module actually uses: immediately after the ct rule.
# `add` alone appends, which puts a later session behind an already-placed
# site deny (E4). Positioning after the ct rule keeps every jump ahead of
# that deny while leaving the established-accept first, so established
# traffic short-circuits instead of walking every live session chain.
jump_rule_after_ct() { # <session-tag>
    local h
    h=$(nft -a list chain inet authnft filter | awk '/ct-live/{print $NF}')
    [[ -n "$h" ]] || die "no ct rule to position after (session $1)"
    [[ $(wc -w <<<"$h") -eq 1 ]] || die "ct-live matched more than one rule; refusing to guess a handle"
    nft add rule inet authnft filter position "$h" jump "session_$1" \
        || die "positioned jump for $1"
}
site_deny() { nft add rule inet authnft filter tcp dport "$1" counter drop comment "\"deny-$1\"" || die "site deny for $1"; }
table_down() { nft delete table inet authnft 2>/dev/null; return 0; }

# close_session, exactly as nft_handler_cleanup issues it.
# Teardown is one atomic transaction: if any object is missing the whole
# batch fails and the session is still up. That failed silently once and a
# revocation case passed for the wrong reason (the session had never closed),
# so this helper now proves its own postcondition instead of trusting nft's
# exit status alone. Every section inherits the check.
module_down() { # <session-tag>
    local tag="$1" h
    h=$(nft -a list chain inet authnft filter | awk "/jump session_$tag/{print \$NF}")
    [[ -n "$h" ]] || die "module_down $tag: no jump rule to delete (session was never up?)"
    [[ $(wc -w <<<"$h") -eq 1 ]] || die "module_down $tag: more than one jump rule matched; refusing to guess"
    nft -f - <<RULES || die "module_down $tag: teardown transaction failed"
delete rule inet authnft filter handle $h
flush chain inet authnft session_$tag
delete chain inet authnft session_$tag
delete set inet authnft session_${tag}_v4
delete set inet authnft session_${tag}_v6
delete set inet authnft session_${tag}_cg
RULES
    nft list chain inet authnft "session_$tag" >/dev/null 2>&1 && \
        die "module_down $tag: chain still present after teardown"
    return 0
}

# A PASS says a payload round-tripped; a BLOCK says it did not. Neither says
# which rule did it. These two tie the verdict to the counter on the rule the
# case is about, and fail the run when the number disagrees with the story.
# A printed control nobody checks is decoration.
counter_moved() { # <case-id> <rule-comment> <count-before> <what it proves>
    local id="$1" comment="$2" before="${3:-0}" why="$4" after
    after=$(cnt "$comment"); after=${after:-0}; before=${before:-0}
    if [[ "$after" -gt "$before" ]]; then
        printf "       %s control: '%s' %s -> %s (%s)\n" "$id" "$comment" "$before" "$after" "$why"
    else
        printf "${RED}[FAIL]${RESET} %s control: '%s' never moved (%s -> %s): %s\n" \
            "$id" "$comment" "$before" "$after" "$why" >&2
        RC=1
    fi
}
counter_static() { # <case-id> <rule-comment> <what it proves>
    local id="$1" comment="$2" why="$3" val
    val=$(cnt "$comment"); val=${val:-0}
    if [[ "$val" -eq 0 ]]; then
        printf "       %s control: '%s' stayed 0 (%s)\n" "$id" "$comment" "$why"
    else
        printf "${RED}[FAIL]${RESET} %s control: '%s' counted %s: %s\n" \
            "$id" "$comment" "$val" "$why" >&2
        RC=1
    fi
}
admitted_by() { counter_moved "$1" "$2" "$3" "admitted by the intended rule, not by accident"; }

# Anchored on the full comment: a bare substring match let cnt sess-a also
# hit the sess-a-deny line, with listing order deciding which one it read.
cnt() { nft list table inet authnft 2>/dev/null | grep -F "comment \"$1\"" | grep -oP 'packets \K[0-9]+' | head -1; }

# Discard anything already queued on the socket before probing it. Without
# this a reply that was in flight when the rules changed is read by the NEXT
# probe and reports a revoked flow as alive, one assertion late. Same trap as
# the nonce matching in tests/ct_mark_revocation_matrix.sh.
#
# Defined here, above section D, and not next to the other socket helpers
# further down: bash resolves a function at the point of call, so a
# definition below the first caller leaves D1, D3 and E9 running without
# the guard and printing "drain: command not found" instead.
drain() { local fd="$1" _junk; while read -r -t 0.3 -u "$fd" _junk 2>/dev/null; do :; done; return 0; }

serve "$SVC" "$CG_A" || { echo "listener on $SVC never came up" >&2; exit 1; }
serve "$ALT" "$CG_A" || { echo "listener on $ALT never came up" >&2; exit 1; }
serve 19102 "$CG_B" || { echo "listener on 19102 never came up" >&2; exit 1; }

# ======================================================================
note "A. Admission: does an open session actually let traffic through?"
# ======================================================================
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a; site_deny "$SVC"; site_deny "$ALT"
check A1 PASS  "$(verdict $OK_SRC $SVC)"  "in-session socket, allowed source, allowed port"
check A2 BLOCK "$(verdict $OK_SRC $ALT)"  "same session, port the fragment does not name"
check A3 BLOCK "$(verdict $BAD_SRC $SVC)" "allowed port, source not in the session set"

# The negative cases above must not pass vacuously: the deny counters prove
# the packets arrived and were dropped rather than never being sent.
counter_moved A2 "deny-$ALT" 0 "the A2 packets arrived and were dropped, not never sent"
counter_moved A3 "deny-$SVC" 0 "the A3 packets arrived and were dropped, not never sent"
printf "       sess-a=%s\n" "$(cnt sess-a)"

# ======================================================================
note "B. Isolation: one session's rules must not admit another's traffic"
# ======================================================================
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a; site_deny 19102
# alice's session is open; bob's listener is in a different scope and has no
# session of its own. Nothing should admit traffic to it.
check B1 BLOCK "$(verdict $OK_SRC 19102)" "bob's socket, only alice's session open"

# Now with bob's session open too. Built from scratch rather than by adding
# bob's jump to the ruleset above: an appended jump would land after the site
# deny and be shadowed, which is #105 and which this harness tripped over
# while it was being written. Session order is alice, bob, then the deny.
table_down; module_up a "$CG_A" "$OK_SRC"
nft -f - <<RULES || die "bob's session state"
add chain inet authnft session_b
add set inet authnft session_b_v4 { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }
add element inet authnft session_b_v4 { "$CG_B" . $OK_SRC timeout 1d }
add rule inet authnft session_b socket cgroupv2 level 2 . ip saddr @session_b_v4 tcp dport 19102 counter accept comment "sess-b"
RULES
ct_rule; jump_rule a; jump_rule b; site_deny 19102
check B2 PASS  "$(verdict $OK_SRC 19102)" "bob's socket once bob's own session is open"
check B3 BLOCK "$(verdict $BAD_SRC 19102)" "bob's port from a source in neither session's set"

# ======================================================================
note "C. The ct rule: the docs call it load-bearing, so prove it bears load"
# ======================================================================
# Class B, the SSH control connection: a flow that established BEFORE the
# session existed, so no session rule covers it. The ct rule has to carry it.
# The rule is in place before the flow opens, which is the real deployment
# ordering (a previous session, or the site's own stateful ruleset, put it
# there) and it matters: see C3.
table_down
nft -f - <<RULES || die "C setup"
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
add set inet authnft live_sessions { type mark; }
add rule inet authnft filter ct state established,related ct mark and 0x00ffffff 0x0 counter accept comment "ct-accept"
add rule inet authnft filter ct state established,related ct mark and 0x00ffffff @live_sessions counter accept comment "ct-live"
RULES
exec 3<>/dev/tcp/127.0.0.1/$ALT || die "could not open the pre-session flow"
printf 'one\n' >&3; read -t 3 -r _ <&3 || die "pre-session flow never worked"
module_up a "$CG_A" "$OK_SRC"; jump_rule a; site_deny "$ALT"
printf 'two\n' >&3
if read -t 3 -r _ <&3; then C1=PASS; else C1=BLOCK; fi
check C1 PASS "$C1" "pre-session (Class B) flow survives, ct rule present"

# Same flow, ct rule removed. If this still passes, the ct rule is not the
# thing carrying Class B traffic and ARCHITECTURE.txt is wrong.
# Both arms: deleting only one leaves the other carrying the flow, and the
# case would report the gate as load-bearing when half of it was still there.
for c in ct-live ct-accept; do
    H=$(nft -a list chain inet authnft filter | awk -v c="$c" '$0 ~ c {print $NF}')
    [[ -n "$H" ]] || die "no $c rule to delete"
    nft delete rule inet authnft filter handle "$H" || die "could not delete $c"
done
printf 'three\n' >&3
if read -t 3 -r _ <&3; then C2=PASS; else C2=BLOCK; fi
check C2 BLOCK "$C2" "same flow with the ct rule deleted"
exec 3<&-

# The precondition nobody wrote down. Conntrack only tracks a flow it saw
# from the start. If the module's ct rule is the first ct rule on the host,
# conntrack was not tracking when the pre-session flow opened, and adding
# the rule later does not retroactively rescue it: the entry conntrack
# creates mid-stream never satisfies `ct state established` (the accept
# counter stays at 0), so the deny takes every packet. The SSH connection
# that carried the session in is exactly such a flow.
table_down
nft -f - <<RULES || die "C3 setup"
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
RULES
exec 5<>/dev/tcp/127.0.0.1/$ALT || die "could not open the untracked flow"
printf 'one\n' >&5; read -t 3 -r _ <&5 || die "untracked flow never worked"
module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a; site_deny "$ALT"
printf 'two\n' >&5
if read -t 3 -r _ <&5; then C3=PASS; else C3=BLOCK; fi
printf 'three\n' >&5
if read -t 3 -r _ <&5; then C3=PASS; fi
check C3 BLOCK "$C3" "flow that predates conntrack tracking, ct rule added after"
# The ct counter is not zero here: conntrack picks the flow up mid-stream and
# the reply direction matches established. The client-to-server data packets
# still land in the deny.
counter_moved C3 "deny-$ALT" 0 "the data packets landed in the deny despite the ct rule"
printf "       ct-accept=%s (nonzero: conntrack picks the flow up mid-stream in the reply direction)\n" "$(cnt ct-accept)"
exec 5<&-

# ======================================================================
note "D. Teardown: what close_session does and does not revoke (#103)"
# ======================================================================
D_SID=0x000001
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule_after_ct a
session_tag a "$D_SID"; site_deny "$SVC"
exec 4<>/dev/tcp/127.0.0.1/$SVC || { echo "session flow would not open" >&2; exit 1; }
printf 'one\n' >&4; read -t 3 -r _ <&4 || { echo "session flow never worked" >&2; exit 1; }

# Close as close_session does it: revoke the id, then tear the per-session
# objects down.
revoke "$D_SID"
module_down a
drain 4; printf 'two\n' >&4
if read -t 3 -r _ <&4; then D1=PASS; else D1=BLOCK; fi
# This expectation flipped when the gate landed, and the PASS it used to
# carry was the bug: the flow kept running because the shared
# established-accept fired before any session rule and conntrack never
# heard about the teardown (#103). The gate makes the next packet of a
# revoked flow fall through to the site deny.
check D1 BLOCK "$D1" "flow admitted during the session, revoked at close_session"
check D2 BLOCK "$(verdict $OK_SRC $SVC)" "new flow after close_session"

# D3 predates the gate and is now overdetermined: by the time the flush
# runs, the gate has already revoked this flow, so this BLOCK cannot be
# credited to conntrack -D. Kept as belt-and-braces (flush after close
# leaves the flow just as dead); D4 is where the flush earns its keep.
conntrack -D -s "$OK_SRC" >/dev/null 2>&1
drain 4; printf 'three\n' >&4
if read -t 3 -r _ <&4; then D3=PASS; else D3=BLOCK; fi
check D3 BLOCK "$D3" "same flow after a conntrack flush by source address"
exec 4<&-

# D4: the fallback on its own. A session that never got an id leaves an
# untagged flow the gate's unsessioned arm carries forever; the documented
# remedy is a conntrack flush by source address (what authpf does). D1-D3
# can no longer show that: the gate revokes first. Here nothing but the
# flush ever revokes: no session, no tag, gate present before the flow
# opens (C3's precondition), deny added after it establishes.
table_down
nft -f - <<RULES || die "D4 setup"
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
RULES
ct_rule
exec 4<>/dev/tcp/127.0.0.1/$ALT || die "D4: untagged flow would not open"
printf 'one\n' >&4; read -t 3 -r _ <&4 || die "D4: untagged flow never worked"
site_deny "$ALT"
drain 4; printf 'two\n' >&4
read -t 3 -r _ <&4 || die "D4: untagged flow did not survive the deny; the gate is broken in an arrangement C1 does not cover"
conntrack -D -s "$OK_SRC" >/dev/null 2>&1
drain 4; printf 'three\n' >&4
if read -t 3 -r _ <&4; then D4=PASS; else D4=BLOCK; fi
check D4 BLOCK "$D4" "untagged flow revoked by a conntrack flush alone (the no-id fallback)"
counter_moved D4 "deny-$ALT" 0 "the post-flush packets arrived and were dropped"
exec 4<&-

# ======================================================================
note "E. Enforcement placement: where the site deny has to go (#105)"
# ======================================================================
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a; site_deny "$SVC"
check E1 PASS  "$(verdict $OK_SRC $SVC)" "deny appended to the shared chain AFTER the jump"

table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; site_deny "$SVC"; jump_rule a
check E2 BLOCK "$(verdict $OK_SRC $SVC)" "deny added BEFORE the jump: session chain shadowed"
counter_static E2 sess-a "the jump was never reached"

table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a
nft add chain inet authnft sitedeny '{ type filter hook input priority filter; policy drop; }'
nft add rule inet authnft sitedeny ct state established,related counter accept
check E3 BLOCK "$(verdict $OK_SRC $SVC)" "site deny as a separate base chain at priority filter"
counter_moved E3 sess-a 0 "the module accepted and was overruled afterwards"

# E1 is only true until the next login. The module APPENDS its jump rule, so
# a session opened after the site deny lands behind it and is never reached.
# That makes "append the deny after the jumps" unworkable as advice: it is
# correct for the sessions that already exist and silently wrong for every
# one that follows, including after a reboot when the deny is restored from
# the site ruleset before anyone logs in.
#
# The insidious part is that this is not a clean failure. alice, whose jump
# predates the deny, keeps working. bob does not. Same module, same fragment
# shape, same host, opposite outcomes decided by login order.
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a; site_deny 19102
nft -f - <<RULES || die "bob's session state for E4"
add chain inet authnft session_b
add set inet authnft session_b_v4 { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }
add element inet authnft session_b_v4 { "$CG_B" . $OK_SRC timeout 1d }
add rule inet authnft session_b socket cgroupv2 level 2 . ip saddr @session_b_v4 tcp dport 19102 counter accept comment "sess-b"
RULES
jump_rule b     # appended, so it lands AFTER the deny
check E4 BLOCK "$(verdict $OK_SRC 19102)" "session opened after the site deny: its jump is shadowed"
counter_static E4 sess-b "bob's jump was never reached"
# The control that makes E4 mean something: alice, whose jump predates the
# deny, is unaffected. Without this the run cannot tell "bob is shadowed"
# from "the whole table is broken".
check E5 PASS "$(verdict $OK_SRC $SVC)" "the session that predates the deny still works (E4 control)"

# E4 with the placement changed and nothing else: same order of
# operations, same deny already in place, same fragment. Positioning after
# the ct rule puts bob's jump ahead of the deny instead of behind it.
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule_after_ct a; site_deny 19102
nft -f - <<RULES || die "bob's session state for E6"
add chain inet authnft session_b
add set inet authnft session_b_v4 { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }
add element inet authnft session_b_v4 { "$CG_B" . $OK_SRC timeout 1d }
add rule inet authnft session_b socket cgroupv2 level 2 . ip saddr @session_b_v4 tcp dport 19102 counter accept comment "sess-b"
RULES
jump_rule_after_ct b
check E6 PASS "$(verdict $OK_SRC 19102)" "same session, jump positioned after the ct rule (#105 fix)"
counter_moved E6 sess-b 0 "bob's jump was reached this time"
# And the deny still denies: a source in nobody's set must not ride in on
# the reordering. Without this E6 could pass by breaking enforcement.
check E7 BLOCK "$(verdict $BAD_SRC 19102)" "deny still denies with the jump positioned (E6 control)"

# E2 with the jump inserted: the deny goes into a live table after the
# gate exists but before this session's jump does, and positioning still
# puts the jump ahead of it. Appending shadowed every later session. This
# is NOT the reboot case: a boot loader restores the deny before the gate
# exists at all, and this arm's gate-then-deny order cannot catch a gate
# that appends behind the deny. E10 pins that order.
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; site_deny "$SVC"; jump_rule_after_ct a
check E8 PASS "$(verdict $OK_SRC $SVC)" "deny placed BEFORE any session, jump positioned after the ct rule"
counter_moved E8 sess-a 0 "the jump ran ahead of a deny that predates it"

# Why the jump goes after the ct rule and not at the head of the chain.
# With jumps first, every packet of every established flow walks every live
# session chain before reaching the established-accept, a per-packet cost
# that grows with the number of logged-in users. This arm pins that it does
# not: once a flow is established, the ct rule takes it and the session
# chain never sees it again.
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule_after_ct a
nft insert rule inet authnft session_a counter comment '"entered-a"' || die "traversal counter"
exec 9<>/dev/tcp/127.0.0.1/$SVC || die "E9: flow would not open"
printf 'one\n' >&9; read -t 3 -r _ <&9 || die "E9: flow never worked"
E9_ENTERED=$(cnt entered-a); E9_ENTERED=${E9_ENTERED:-0}
E9_CT=$(cnt ct-accept); E9_CT=${E9_CT:-0}
for _ in 1 2 3; do drain 9; printf 'more\n' >&9; read -t 3 -r _ <&9 || true; done
E9_ENTERED2=$(cnt entered-a); E9_ENTERED2=${E9_ENTERED2:-0}
E9_CT2=$(cnt ct-accept); E9_CT2=${E9_CT2:-0}
check E9 PASS "$([[ "$E9_ENTERED2" -eq "$E9_ENTERED" && "$E9_CT2" -gt "$E9_CT" ]] && echo PASS || echo BLOCK)" \
    "established traffic short-circuits at the ct rule, never entering a session chain"
printf "       session-chain entries %s -> %s (must not move), ct-accept %s -> %s (must move)\n" \
    "$E9_ENTERED" "$E9_ENTERED2" "$E9_CT" "$E9_CT2"
exec 9<&-

# The ADMIN_GUIDE reboot case: the loader restores the site deny into the
# module's chain before any session has opened, so the deny predates the
# gate itself, not just the jump (that was E8). An appended gate lands
# behind the deny, and the jump positioned after the gate lands behind it
# too, shadowing every session on the host. Insert puts both above it.
table_down
nft -f - <<RULES || die "boot-restored deny for E10"
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
add rule inet authnft filter tcp dport $SVC counter drop comment "deny-$SVC"
RULES
module_up a "$CG_A" "$OK_SRC"
ct_rule; jump_rule_after_ct a
# Structural falsifier: the gate really sits above the deny. Without this
# E10 could pass on a deny that never matched anything.
E10_GATE=$(nft list chain inet authnft filter | grep -n 'ct-accept' | cut -d: -f1)
E10_DENY=$(nft list chain inet authnft filter | grep -n "deny-$SVC" | cut -d: -f1)
[[ -n "$E10_GATE" && -n "$E10_DENY" && "$E10_GATE" -lt "$E10_DENY" ]] \
    || die "E10: gate (line ${E10_GATE:-absent}) not above the boot-restored deny (line ${E10_DENY:-absent})"
E10_BEFORE=$(cnt sess-a); E10_BEFORE=${E10_BEFORE:-0}
check E10 PASS "$(verdict $OK_SRC $SVC)" "deny restored at boot, before the gate existed; gate and jump inserted above it"
admitted_by E10 sess-a "$E10_BEFORE"
check E11 BLOCK "$(verdict $BAD_SRC $SVC)" "the boot-restored deny still denies (E10 control)"
# Arrival control, same contract as A2/A3: a BLOCK is only evidence if the
# packet reached the deny. A connect that never sent a SYN reports BLOCK too.
counter_moved E11 "deny-$SVC" 0 "the boot-restored deny is live, not bypassed"

# ======================================================================
note "F. Complex fragments: a session chain that denies as well as allows"
# ======================================================================
# The restriction model: the fragment narrows what the session may reach.
# Denies live in the per-session chain, so they die with the session.
table_down; module_up a "$CG_A" "$OK_SRC"
nft add rule inet authnft session_a socket cgroupv2 level 2 @session_a_cg tcp dport $ALT counter drop comment '"sess-a-deny"'
nft add element inet authnft session_a_cg "{ \"$CG_A\" timeout 1d }"
ct_rule; jump_rule a
F1_BEFORE=$(cnt sess-a); F1_BEFORE=${F1_BEFORE:-0}
check F1 PASS  "$(verdict $OK_SRC $SVC)" "fragment allow rule, no site deny in play"
admitted_by F1 sess-a "$F1_BEFORE"
check F2 BLOCK "$(verdict $OK_SRC $ALT)" "fragment deny rule inside the session chain"
counter_moved F2 sess-a-deny 0 "the fragment's own deny did the dropping"

# And the same denied port once the session closes: the deny goes with it.
module_down a
# F3 passes because the deny went with the session, not because the traffic
# was never sent or the table vanished. Two controls, both in THIS table
# instance: the deny rule must be gone, and the shared chain must still be
# standing. (An earlier draft pointed at G2 for the second half, but G2 runs
# on a rebuilt table and cannot vouch for this one.)
check F3 PASS "$(verdict $OK_SRC $ALT)" "fragment deny does not outlive the session"
if [[ -n "$(cnt sess-a-deny)" ]]; then
    printf "${RED}[FAIL]${RESET} F3: the fragment deny rule is still present after close\n" >&2
    RC=1
else
    printf "       F3 control: the fragment deny rule is gone, not merely unmatched\n"
fi
if [[ -z "$(cnt ct-accept)" ]]; then
    printf "${RED}[FAIL]${RESET} F3 control: ct-accept is gone too; the whole table vanished with the session\n" >&2
    RC=1
fi

# ======================================================================
note "G. Cleanup boundary: what close_session leaves behind"
# ======================================================================
# Teardown is scoped to the four objects the module named: the jump rule,
# the per-session chain, and the three sets. Everything else a session
# touched stays. Some of that is deliberate (the shared chain is shared),
# some of it is a fragment's doing and documented as the admin's problem,
# and one of them is state the module never had a handle on at all.
table_down; module_up a "$CG_A" "$OK_SRC"
nft -f - <<RULES || die "G setup"
add chain inet authnft frag_extra
add rule inet authnft frag_extra tcp dport $ALT counter drop comment "frag-chain-deny"
add rule inet authnft session_a jump frag_extra
RULES
ct_rule; jump_rule a; site_deny "$SVC"
# A fragment rule in the SHARED chain. A top-level fragment cannot do this
# (check_statement rejects "add rule inet authnft filter ..."), but an
# included file is allowed to: NFT_FRAG_INCLUDED drops the shared-chain guard
# because INTEGRATIONS 4.6 makes the shared chain the documented target for
# included rules. The rule is validated, just not cleaned up: it lives outside
# the per-session chain, so close_session never had a handle on it (INTEGRATIONS
# 4.5). The point of the case is what that leftover rule does to traffic once
# the session ends. The harness adds it with plain nft because it is measuring
# the leftover, not the include walk (that path is covered by test-include-walk).
nft add rule inet authnft filter tcp dport 19102 counter drop comment '"frag-shared-deny"' || die "shared frag rule"

exec 6<>/dev/tcp/127.0.0.1/$SVC || die "G flow would not open"
printf 'one\n' >&6; read -t 3 -r _ <&6 || die "G flow never worked"
module_down a

leftover() { nft list table inet authnft 2>/dev/null | grep -c "$1"; }
G_CT=$(leftover 'ct-accept'); G_FRAG=$(leftover 'frag-chain-deny'); G_SHARED=$(leftover 'frag-shared-deny')
G_SESS=$(leftover 'session_a')
check G1 BLOCK "$([[ $G_SESS -eq 0 ]] && echo BLOCK || echo PASS)" "per-session chain and sets are gone after close"
check G2 PASS  "$([[ $G_CT -gt 0 ]] && echo PASS || echo BLOCK)"   "shared chain and its ct rule survive close (by design)"
check G3 PASS  "$([[ $G_FRAG -gt 0 ]] && echo PASS || echo BLOCK)" "chain a fragment created survives close (INTEGRATIONS 4.5)"
check G4 PASS  "$([[ $G_SHARED -gt 0 ]] && echo PASS || echo BLOCK)" "rule a fragment put in the shared chain survives close"
# And the wire consequence of G4: that leftover rule still denies traffic
# belonging to nobody's session, on a port the closed session never owned.
G5_BEFORE=$(cnt frag-shared-deny); G5_BEFORE=${G5_BEFORE:-0}
check G5 BLOCK "$(verdict $OK_SRC 19102)" "leftover shared-chain fragment rule still drops after close"
counter_moved G5 frag-shared-deny "$G5_BEFORE" "the leftover fragment rule did the dropping"
exec 6<&-

# ======================================================================
note "I. Conntrack revocation: the ct mark gate shipped for #103"
# ======================================================================
# The ct mark gate, isolated. The module ships this since 9c224ad (#103):
# each session tags its new connections with an id in the low 24 bits of
# ct mark, the shared established-accept is split into an unsessioned arm
# and a live-id arm, and close deletes the id so a revoked flow's next
# packet falls through to the site deny. Section D proves the module-shaped
# build revokes; these arms pin the gate's own semantics: which flows the
# close kills (I2), which it must never touch (I3), and why ids must not
# repeat (I4, I5), with a real pre-session flow standing in for the SSH
# connection because breaking that locks everyone out of the host.
SESS_MASK=0x00ffffff     # the slice a session id lives in
ADMIN_MASK=0xff000000    # bits the admin keeps
ADMIN_BITS=0xab000000    # what an admin rule puts there first
CTM_A=0x000001
CTM_B=0x000002

# Builds the gate plus one tagged session. The jump is head-inserted, which
# is the module's no-gate fallback path (nft_handler.c positions it after
# the est-live rule when it can); every verdict below is placement-
# independent, and the module's real placement is what sections D and E
# exercise.
ctmark_up() { # <session-tag> <cgroup> <src> <session-id>
    local tag="$1" cg="$2" src="$3" sid="$4"
    nft -f - <<RULES || die "ct mark gate setup for $tag"
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
add set inet authnft live_sessions { type mark; }
add chain inet authnft session_$tag
add set inet authnft session_${tag}_v4 { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }
add set inet authnft session_${tag}_v6 { typeof socket cgroupv2 level 2 . ip6 saddr; flags timeout; }
add set inet authnft session_${tag}_cg { typeof socket cgroupv2 level 2; flags timeout; }
add element inet authnft session_${tag}_v4 { "$cg" . $src timeout 1d }
add rule inet authnft session_$tag ct state new ct mark set ct mark and $ADMIN_MASK or $sid counter comment "tag-$tag"
add rule inet authnft session_$tag socket cgroupv2 level 2 . ip saddr @session_${tag}_v4 tcp dport $SVC counter accept comment "sess-$tag"
add rule inet authnft session_$tag ct state new ct mark set ct mark and $ADMIN_MASK comment "untag-$tag"
add element inet authnft live_sessions { $sid }
RULES
    session_built "$tag"
    nft insert rule inet authnft filter jump "session_$tag" || die "jump for $tag"
}

# Order matters and cost an hour: the unsessioned flow has to be opened
# before the deny exists and before the session does, because it stands in
# for the SSH connection that carried the login in. Opening it after the
# deny hangs on the TCP connect timeout rather than failing, which is why
# hold_open() bounds the connect.
hold_open() { # <fd> <port>   returns 1 rather than blocking on a dropped SYN
    local fd="$1" port="$2"
    timeout 5 bash -c "exec 9<>/dev/tcp/127.0.0.1/$port" 2>/dev/null || return 1
    eval "exec $fd<>/dev/tcp/127.0.0.1/$port" 2>/dev/null || return 1
    return 0
}

table_down
# The gate, installed before any flow exists. C3 established that a ct rule
# added after a flow opened does not rescue it, so the gate has to predate
# the connection it is meant to carry. An admin rule claims the high bits
# first, so nothing below passes by comparing against a bare zero.
nft -f - <<RULES || die "I: gate setup"
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
add set inet authnft live_sessions { type mark; }
add chain inet authnft adminmark { type filter hook input priority filter - 10; policy accept; }
add rule inet authnft adminmark ct state new ct mark set ct mark or $ADMIN_BITS counter comment "admin-mark"
add rule inet authnft filter ct state established,related ct mark and $SESS_MASK 0x0 counter accept comment "est-unsessioned"
add rule inet authnft filter ct state established,related ct mark and $SESS_MASK @live_sessions counter accept comment "est-live"
RULES

# The SSH connection. Established before the session and before the deny,
# never tagged. If this arm ever fails, the change locks the operator out.
hold_open 7 "$ALT" || die "I: could not open the unsessioned flow"
printf 'one\n' >&7; read -t 3 -r _ <&7 || die "I: unsessioned flow never worked"

ctmark_up a "$CG_A" "$OK_SRC" "$CTM_A"
site_deny "$SVC"; site_deny "$ALT"

hold_open 8 "$SVC" || die "I: session flow would not open"
printf 'one\n' >&8; read -t 3 -r _ <&8 || die "I: session flow never worked"
# The observation is the hold_open and exchange above: both die on failure,
# so reaching this line IS the pass. Recorded so the matrix counts it.
check I1 PASS "PASS" "session flow admitted while the session is live (control)"
# Earlier sections leave a dozen conntrack entries on this port in TIME_WAIT
# and SYN_SENT. Filtering to the single ESTABLISHED one is what makes this
# reproducible; head -1 over all of them returned a different mark per run.
# UNREPLIED is filtered too: a socket closed while a deny held its port is
# orphaned with unacked data and retransmits for minutes, and each
# retransmit after a conntrack flush re-seeds a mid-stream entry whose TCP
# state reads ESTABLISHED despite never seeing a reply. D4's flush put one
# of those ghosts in this reader's window. The real flow always has replies.
flow_mark() { # <port>
    local rows n
    rows=$(conntrack -L -p tcp --dport "$1" --state ESTABLISHED 2>/dev/null | grep -v UNREPLIED) || rows=""
    n=$(printf '%s' "$rows" | grep -c 'mark=') || n=0
    if [[ "$n" -ne 1 ]]; then echo "AMBIGUOUS:$n"; return 0; fi
    printf '0x%08x' "$(printf '%s' "$rows" | grep -oP 'mark=\K[0-9]+' | head -1)"
}
CTM_LIVE=$(flow_mark "$SVC")
printf "       session entry mark: %s (want %s | %s)\n" "$CTM_LIVE" "$ADMIN_BITS" "$CTM_A"

# Close, exactly as close_session would: drop the live-sessions element,
# then tear the per-session objects down.
nft delete element inet authnft live_sessions "{ $CTM_A }" || die "I: could not revoke"
module_down a

printf "       jumps left after close: %s (0 proves the teardown transaction committed)\n" \
    "$(nft list chain inet authnft filter 2>/dev/null | grep -c 'jump session_' || true)"
drain 8; printf 'two\n' >&8
if read -t 3 -r _ <&8; then I2=PASS; else I2=BLOCK; fi
check I2 BLOCK "$I2" "flow admitted during the session, after close (D1 fixed)"

I3_BEFORE=$(cnt est-unsessioned); I3_BEFORE=${I3_BEFORE:-0}
drain 7; printf 'two\n' >&7
if read -t 3 -r _ <&7; then I3=PASS; else I3=BLOCK; fi
check I3 PASS "$I3" "untagged flow survives the same close (the SSH connection)"
admitted_by I3 est-unsessioned "$I3_BEFORE"
printf "       est-unsessioned=%s est-live=%s\n" "$(cnt est-unsessioned)" "$(cnt est-live)"

# Id reuse. The stale entry still carries the old id, so a new session handed
# the same id resurrects a flow that was revoked. This is the constraint any
# implementation must solve, and the arm exists so it cannot be forgotten.
nft add element inet authnft live_sessions "{ $CTM_A }" || die "I: could not re-add"
drain 8; printf 'three\n' >&8
if read -t 3 -r _ <&8; then I4=PASS; else I4=BLOCK; fi
check I4 PASS "$I4" "reusing a session id resurrects the revoked flow (why ids must not repeat)"

nft delete element inet authnft live_sessions "{ $CTM_A }" || die "I: could not re-revoke"
nft add element inet authnft live_sessions "{ $CTM_B }" || die "I: could not add a fresh id"
drain 8; printf 'four\n' >&8
if read -t 3 -r _ <&8; then I5=PASS; else I5=BLOCK; fi
check I5 BLOCK "$I5" "a fresh id does not resurrect it (I4 control)"

# The tag is written once, at connection setup, so the reading taken while
# the session was live is what answers this.
if [[ "$CTM_LIVE" == AMBIGUOUS:* ]]; then
    check I6 PASS BLOCK "admin mark bits preserved (could not isolate the flow: $CTM_LIVE)"
else
    CTM_ADMIN=$(printf '0x%08x' $(( CTM_LIVE & 0xff000000 )))
    check I6 PASS "$([[ "$CTM_ADMIN" == "$ADMIN_BITS" ]] && echo PASS || echo BLOCK)" \
        "the session tag preserved the admin's mark bits ($CTM_LIVE, admin slice $CTM_ADMIN)"
fi
exec 7<&-; exec 8<&-

# I7: the bystander. The jump into a session chain is unconditional and the
# tag rule stamps every new flow the chain sees, admitted or not. A flow the
# SITE admits with the stateful-new idiom (ct state new accept + trailing
# deny) then depends entirely on the gate for its established packets. If
# the stamp sticks, this session's close revokes a flow it never admitted.
# PASS is the contract; BLOCK here is the pollution bug on the wire, and
# the mark control catches the stamp even where a site idiom would mask it.
table_down
nft -f - <<RULES || die "I7: gate setup"
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
add set inet authnft live_sessions { type mark; }
add rule inet authnft filter ct state established,related ct mark and $SESS_MASK 0x0 counter accept comment "est-unsessioned"
add rule inet authnft filter ct state established,related ct mark and $SESS_MASK @live_sessions counter accept comment "est-live"
RULES
ctmark_up a "$CG_A" "$OK_SRC" "$CTM_A"
nft add rule inet authnft filter ct state new tcp dport 19102 accept comment '"site-new-19102"' || die "I7: site accept"
site_deny 19102
hold_open 7 19102 || die "I7: bystander flow would not open"
printf 'one\n' >&7; read -t 3 -r _ <&7 || die "I7: bystander flow never worked"
I7_MARK=$(flow_mark 19102)
printf "       bystander mark: %s (sid bits must be 0; the session's id is %s)\n" "$I7_MARK" "$CTM_A"
if [[ "$I7_MARK" != AMBIGUOUS:* ]] && (( (I7_MARK & SESS_MASK) != 0 )); then
    printf "${RED}[FAIL]${RESET} I7 mark control: bystander carries session id bits 0x%06x\n" \
        $(( I7_MARK & SESS_MASK )) >&2
    RC=1
fi
revoke "$CTM_A"
module_down a
drain 7; printf 'two\n' >&7
if read -t 3 -r _ <&7; then I7=PASS; else I7=BLOCK; fi
check I7 PASS "$I7" "bystander flow survives the session's close (it was never the session's to revoke)"
counter_moved I7 est-unsessioned 0 "the unsessioned arm carried it after close"
exec 7<&-

# I8: the same stamp across sessions. With two sessions live, an unadmitted
# new flow walks both chains and keeps the LAST chain's id (head-inserted
# jumps walk newest-first, so the last is the oldest session). Closing that
# session must not end a flow the other session's era established.
table_down
nft -f - <<RULES || die "I8: gate setup"
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
add set inet authnft live_sessions { type mark; }
add rule inet authnft filter ct state established,related ct mark and $SESS_MASK 0x0 counter accept comment "est-unsessioned"
add rule inet authnft filter ct state established,related ct mark and $SESS_MASK @live_sessions counter accept comment "est-live"
RULES
ctmark_up a "$CG_A" "$OK_SRC" "$CTM_A"
ctmark_up b "$CG_B" "$OK_SRC" "$CTM_B"
nft add rule inet authnft filter ct state new tcp dport 19102 accept comment '"site-new-19102"' || die "I8: site accept"
site_deny 19102
hold_open 7 19102 || die "I8: bystander flow would not open"
printf 'one\n' >&7; read -t 3 -r _ <&7 || die "I8: bystander flow never worked"
printf "       bystander mark: %s (walked b then a; a's id is %s)\n" "$(flow_mark 19102)" "$CTM_A"
revoke "$CTM_A"
module_down a
drain 7; printf 'two\n' >&7
if read -t 3 -r _ <&7; then I8=PASS; else I8=BLOCK; fi
check I8 PASS "$I8" "one session's close does not revoke a flow it never admitted (two sessions live)"
revoke "$CTM_B"; module_down b
exec 7<&-

# ======================================================================
note "H. Packet traces: the kernel's own account of the traversal"
# ======================================================================
# Counters say a rule matched. A trace says which chains the packet walked,
# in order, and what verdict ended it. `nft monitor trace` is the kernel
# telling us directly, so it is the strongest evidence in this file.
TRACE_DIR="${AUTHNFT_TRACE_DIR:-}"
trace_case() { # <slug> <label> <src> <port>
    local slug="$1" label="$2" src="$3" port="$4" out
    out=$(mktemp)
    nft add chain inet authnft trace_hook \
        '{ type filter hook prerouting priority raw - 1; policy accept; }' 2>/dev/null
    nft add rule inet authnft trace_hook tcp dport "$port" meta nftrace set 1 2>/dev/null
    timeout 6 nft monitor trace > "$out" 2>/dev/null &
    local mon=$!
    sleep 0.4
    flow "$src" "$port" >/dev/null 2>&1
    sleep 0.4
    kill $mon 2>/dev/null; wait $mon 2>/dev/null
    printf "\n    ${YELLOW}%s${RESET}\n" "$label"
    # First packet of the flow only: the SYN decides admission, and the
    # retransmits that follow a drop are the same story repeated.
    # trace_hook's own "meta nftrace set 1" lines are plumbing, not story,
    # and they ate the 8-line budget: the archived foreign-chain trace lost
    # its verdict line to them.
    grep -E 'rule|verdict|policy' "$out" | grep -v trace_hook | head -8 | sed 's/^/      /'
    [[ -n "$TRACE_DIR" ]] && cp "$out" "$TRACE_DIR/$slug.txt"
    rm -f "$out"
    nft delete chain inet authnft trace_hook 2>/dev/null
}

if nft monitor trace >/dev/null 2>&1 & sleep 0.2; kill $! 2>/dev/null; then
    table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a; site_deny "$SVC"; site_deny "$ALT"
    trace_case admitted "admitted: session rule accepts" "$OK_SRC" "$SVC"
    trace_case denied-by-site "denied: port the session does not own" "$OK_SRC" "$ALT"
    table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a
    nft add chain inet authnft sitedeny '{ type filter hook input priority filter; policy drop; }'
    trace_case denied-by-foreign-chain \
        "denied by a separate chain the module cannot see (#105)" "$OK_SRC" "$SVC"
else
    printf "    ${YELLOW}[SKIP]${RESET} nft monitor trace unavailable\n"
fi

# ======================================================================
printf "\n${BLUE}>>> MATRIX${RESET}\n"
printf "    %-6s %-8s %-8s %s\n" CASE EXPECTED OBSERVED PINS
for row in "${ROWS[@]}"; do
    IFS='|' read -r id want got st desc <<< "$row"
    printf "    %-6s %-8s %-8s %s%s\n" "$id" "$want" "$got" "$desc" \
        "$([[ $st == MISMATCH ]] && echo '   <-- MISMATCH')"
done

# A section that dies quietly, or an arm that is edited out, shows up here
# as a short matrix rather than as a clean pass. This is the D3 class the
# codex bot found: the run reported success for cases it never executed.
EXPECTED_CASES=40
if [[ ${#ROWS[@]} -ne $EXPECTED_CASES ]]; then
    printf "\n${RED}>>> %d cases recorded, expected %d. A section did not run.${RESET}\n" \
        "${#ROWS[@]}" "$EXPECTED_CASES"
    RC=1
fi

if [[ $RC -eq 0 ]]; then
    printf "\n${BLUE}>>> EVERY CASE MATCHED THE WIRE (kernel %s)${RESET}\n" "$(uname -r)"
else
    printf "\n${RED}>>> PACKET-FLOW MATRIX FAILED (kernel %s)${RESET}\n" "$(uname -r)"
fi
exit $RC
