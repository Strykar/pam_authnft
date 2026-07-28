#!/bin/bash
# Can a per-session conntrack mark carry revocation, and what does it cost?
#
# Issue #103: flows admitted during a session keep passing after close,
# because the shared `ct state established,related accept` runs ahead of
# every session jump and conntrack never hears about the teardown. Two
# shapes need a mark:
#
#   flush   tag nothing, `conntrack -D -s <addr>` at close (authpf's shape)
#   gate    tag at open, gate the shared established-accept on a
#           live-sessions set, delete the element at close
#
# `gate` is the interesting one: it needs no ctnetlink and no exec of
# conntrack(8), so it adds nothing to the seccomp allowlist. It is only
# worth building if all four of these hold.
#
#   1  `ct mark set` from a chain at `priority filter - 1` tags the entry
#      on the connection's first packet
#   2  the reply direction carries the mark
#   3  the gate still admits a flow that predates the session (Class A/B in
#      ARCHITECTURE.txt, the SSH connection itself, pinned by integration
#      10.12)
#   4  a reused session id does NOT resurrect a previous session's flow
#
# 4 is the hazard #103 does not name: it is the PID-recycle problem one
# layer down, and it bites the flush shape too.
#
# The mark is also admin-shared, so every arm runs with an admin rule
# already setting the high bits, and the module claims only the low 16.
# `ct mark 0x0` is therefore never a safe test for "not session-admitted";
# the rules below mask before comparing.
#
# Two throwaway netns joined by a veth, so conntrack in the server ns sees
# one direction per hook and nothing touches the host. The site deny sits
# where tests/accept_priority_matrix.sh found it has to sit, appended to
# the shared chain after the jumps, so these arms measure revocation and
# not placement.
#
# Run as root.
set -euo pipefail

C=authnft-ctm-c
S=authnft-ctm-s
CLI_IP=10.99.0.1
SRV_IP=10.99.0.2
SESS_PORT=19099          # reached only through a session chain
OPEN_PORT=19098          # always open, models sshd's own listener
SESS_MASK=0x0000ffff     # the slice the module would claim
ADMIN_MASK=0xffff0000    # bits the module must not touch
ADMIN_BITS=0xabcd0000    # what an admin rule puts there first
SID1=0x00000001
SID2=0x00000002

[[ $(id -u) -eq 0 ]] || { echo "needs root"; exit 1; }

RUN=$(mktemp -d)
CTL=$RUN/ctl
RES=$RUN/res
mkfifo "$CTL" "$RES"

cleanup() {
    exec 8>&- 2>/dev/null || true
    exec 9<&- 2>/dev/null || true
    for n in "$C" "$S"; do
        ip netns pids "$n" 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del "$n" 2>/dev/null || true
    done
    rm -rf "$RUN"
}
trap cleanup EXIT

for n in "$C" "$S"; do ip netns del "$n" 2>/dev/null || true; done
ip netns add "$C"
ip netns add "$S"
ip link add veth-c netns "$C" type veth peer name veth-s netns "$S"
ip -n "$C" addr add $CLI_IP/24 dev veth-c
ip -n "$S" addr add $SRV_IP/24 dev veth-s
ip -n "$C" link set veth-c up; ip -n "$C" link set lo up
ip -n "$S" link set veth-s up; ip -n "$S" link set lo up

nft_s() { ip netns exec "$S" nft "$@"; }
ct_s()  { ip netns exec "$S" conntrack "$@" 2>/dev/null; }

ip netns exec "$S" socat TCP-LISTEN:$SESS_PORT,reuseaddr,fork EXEC:/bin/cat >/dev/null 2>&1 &
ip netns exec "$S" socat TCP-LISTEN:$OPEN_PORT,reuseaddr,fork EXEC:/bin/cat >/dev/null 2>&1 &
for _ in $(seq 50); do
    n=$(ip netns exec "$S" ss -ltn 2>/dev/null | grep -cE ":($SESS_PORT|$OPEN_PORT)") || n=0
    [[ $n -eq 2 ]] && break
    sleep 0.1
done
[[ ${n:-0} -eq 2 ]] || { echo "listeners never came up"; exit 1; }

# Client agent: holds connections open across ruleset changes, so liveness
# is measured on an established flow and not on a fresh handshake.
#
# Each ping carries a nonce and only its own echo counts. Without that, a
# reply still in flight when the rules changed gets read by the *next*
# ping and reports a blocked flow as alive, one test late.
export CTL RES SRV_IP
ip netns exec "$C" bash >"$RES" 2>/dev/null <<'AGENT' &
set -u
declare -A FD
while IFS=' ' read -r cmd tag port; do
    case $cmd in
    open)
        if exec {f}<>/dev/tcp/"$SRV_IP"/"$port"; then FD[$tag]=$f; echo opened
        else echo refused; fi ;;
    ping)
        f=${FD[$tag]:-}
        if [[ -z $f ]]; then echo nofd; continue; fi
        nonce="n$RANDOM$RANDOM"
        if ! printf '%s\n' "$nonce" >&"$f" 2>/dev/null; then echo dead; continue; fi
        got=""; deadline=$((SECONDS + 4))
        while [[ $SECONDS -lt $deadline ]]; do
            if read -r -t 1 -u "$f" line 2>/dev/null; then
                [[ $line == "$nonce" ]] && { got=1; break; }
            fi
        done
        [[ -n $got ]] && echo alive || echo dead ;;
    quit) break ;;
    esac
done < "$CTL"
AGENT

exec 8<>"$CTL"
exec 9<>"$RES"
say() { echo "$*" >&8; local l; read -r -t 15 l <&9 || l=TIMEOUT; echo "$l"; }

mark_of() {  # mark on the conntrack entry for a given dport, or "none"
    local m
    m=$(ct_s -L -p tcp --dport "$1" 2>/dev/null | grep -oP 'mark=\K[0-9]+' | head -1) || m=""
    if [[ -n $m ]]; then printf '0x%08x\n' "$m"; else echo none; fi
}
ctr() {
    local v
    v=$(nft_s list table inet authnft | grep -F "\"$1\"" | grep -oP 'packets \K[0-9]+' | head -1) || v=""
    echo "${v:-NORULE}"
}

# Every novel construct the gate shape needs, tried in isolation, so an
# unsupported one is a named answer rather than a failed build.
echo "### capability"
echo "    nft:       $(nft_s --version)"
echo "    conntrack: $(ct_s --version | head -1)"
cap() {
    local name=$1; shift
    if nft_s -f - >/dev/null 2>&1 <<<"$*"; then echo "    $name: yes"
    else echo "    $name: NO"; fi
    nft_s delete table inet cap >/dev/null 2>&1 || true
}
cap "set of type mark        " "add table inet cap
add set inet cap s { type mark; }"
cap "ct mark set masked      " "add table inet cap
add chain inet cap c
add rule inet cap c ct mark set ct mark and $ADMIN_MASK or $SID1"
cap "set lookup on ct mark   " "add table inet cap
add set inet cap s { type mark; }
add chain inet cap c
add rule inet cap c ct mark @s accept"
cap "set lookup masked       " "add table inet cap
add set inet cap s { type mark; }
add chain inet cap c
add rule inet cap c ct mark and $SESS_MASK @s accept"

# The gate shape, built as nft_handler_setup would build it.
nft_s delete table inet authnft >/dev/null 2>&1 || true
nft_s -f - <<RULES
add table inet authnft
add set inet authnft live_sessions { type mark; }
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
add chain inet authnft reply { type filter hook output priority filter - 1; policy accept; }
add chain inet authnft session_a
add rule inet authnft filter tcp dport $SESS_PORT ct state new ct mark set ct mark or $ADMIN_BITS counter comment "admin-mark"
add rule inet authnft filter ct state established,related ct mark and $SESS_MASK 0x0 counter accept comment "est-unsessioned"
add rule inet authnft filter ct state established,related ct mark and $SESS_MASK @live_sessions counter accept comment "est-live"
add rule inet authnft filter ct state established,related counter comment "est-orphan"
add rule inet authnft filter tcp dport $OPEN_PORT ct state new counter accept comment "site-open"
add rule inet authnft filter jump session_a
add rule inet authnft filter counter drop comment "site-deny"
add rule inet authnft session_a ip saddr $CLI_IP tcp dport $SESS_PORT ct state new ct mark set ct mark and $ADMIN_MASK or $SID1 counter accept comment "sess-new"
add rule inet authnft reply ct mark and $SESS_MASK != 0x0 counter comment "reply-tagged"
add rule inet authnft reply ct mark and $SESS_MASK 0x0 counter comment "reply-untagged"
RULES
echo "    full ruleset: built"

echo
echo "### control: with the session live, does the session port admit at all?"
nft_s add element inet authnft live_sessions "{ $SID1 }"
echo "    open sess -> $(say open sess $SESS_PORT)"
echo "    ping sess -> $(say ping sess)   (must be alive, or the whole run is vacuous)"

echo
echo "### 1  does ct mark set at priority filter - 1 tag the entry?"
echo "    entry mark:       $(mark_of $SESS_PORT)   (want $ADMIN_BITS | $SID1 = 0xabcd0001)"
echo "    sess-new counter: $(ctr sess-new) packets   (1 means the SYN alone tagged it)"
echo "    raw: $(ct_s -L -p tcp --dport $SESS_PORT 2>/dev/null | head -1)"

echo
echo "### 2  does the reply direction carry the mark?"
echo "    reply-tagged:   $(ctr reply-tagged) packets"
echo "    reply-untagged: $(ctr reply-untagged) packets"

echo
echo "### 3  does the gate still admit a flow that predates the session?"
echo "    open pre  -> $(say open pre $OPEN_PORT)   (untagged, models the SSH connection)"
echo "    ping pre  -> $(say ping pre)"
echo "    ping sess -> $(say ping sess)"
echo "    pre-flow entry mark: $(mark_of $OPEN_PORT)"
echo "    -- close the session: delete the element, flush the chain --"
nft_s delete element inet authnft live_sessions "{ $SID1 }"
nft_s flush chain inet authnft session_a
echo "    ping pre  -> $(say ping pre)   (want alive: unsessioned flows must survive)"
echo "    ping sess -> $(say ping sess)   (want dead: the session's flow must not)"
echo "    est-unsessioned=$(ctr est-unsessioned) est-live=$(ctr est-live) est-orphan=$(ctr est-orphan)"

echo
echo "### 4  does a reused session id resurrect the closed session's flow?"
echo "    stale conntrack entry: $(mark_of $SESS_PORT)"
echo "    a new session is allocated the same id and adds it back"
nft_s add element inet authnft live_sessions "{ $SID1 }"
echo "    ping sess -> $(say ping sess)   (alive here means id reuse aliases old flows)"
echo "    same test with a fresh id instead:"
nft_s delete element inet authnft live_sessions "{ $SID1 }"
nft_s add element inet authnft live_sessions "{ $SID2 }"
echo "    ping sess -> $(say ping sess)   (want dead)"

echo
echo "### admin bits: did the module's masked set preserve them?"
m=$(mark_of $SESS_PORT)
if [[ $m == none ]]; then echo "    no entry"
else echo "    entry $m, admin slice $(printf '0x%08x\n' $(( m & ADMIN_MASK ))), want $ADMIN_BITS"; fi

echo
echo "### final ruleset"
nft_s list table inet authnft | sed 's/^/    /'
say quit >/dev/null
