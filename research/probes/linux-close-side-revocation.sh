#!/bin/bash
# Does a connection admitted by a session's rules keep passing after
# close_session tears those rules down? (issue #103)
#
# Replicates the chain shape nft_handler_setup commits and the exact
# teardown nft_handler_cleanup runs, then measures a live TCP flow across
# the teardown. The per-session match key here is `ip saddr` rather than
# `socket cgroupv2 level 2 . ip saddr`: the conntrack question is
# independent of the match key, and cgroup matching needs a real scope.
#
# Also answers the prerequisite question the docs never state: does an
# accept in the module's chain (priority filter - 1) survive a separate
# default-deny base chain at priority filter?
#
# Run as root. Everything happens in a throwaway netns.
set -u

NS=authnft-rev
PORT=19099
T=authnft

[[ $(id -u) -eq 0 ]] || { echo "needs root"; exit 1; }

ip netns del $NS 2>/dev/null
ip netns add $NS || exit 1
trap 'ip netns pids '$NS' 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del '$NS' 2>/dev/null' EXIT
ip -n $NS link set lo up

ip netns exec $NS bash -s <<EOF
set -u
PORT=$PORT
T=$T

r() { echo "    \$*"; }

# echo server
socat TCP-LISTEN:\$PORT,reuseaddr,fork EXEC:/bin/cat &
SRV=\$!
for i in \$(seq 50); do
    ss -ltn 2>/dev/null | grep -q ":\$PORT" && break
    sleep 0.1
done

# The ruleset the module commits, plus the site deny it needs to mean
# anything. Order is the one the module produces: ct rule first (call 1),
# session jump appended after (call 2). The trailing drop stands in for the
# admin's default-deny for this port.
nft -f - <<'RULES'
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
add set inet authnft session_test_v4 { type ipv4_addr; flags timeout; }
add chain inet authnft session_test
add rule inet authnft filter ct state established,related counter accept comment "ct-accept"
add rule inet authnft filter jump session_test
add rule inet authnft filter tcp dport 19099 counter drop comment "site-deny"
add rule inet authnft session_test ip saddr @session_test_v4 tcp dport 19099 counter accept comment "session-accept"
add element inet authnft session_test_v4 { 127.0.0.1 timeout 1d }
RULES

HANDLE=\$(nft -a list chain inet authnft filter | awk '/jump session_test/{print \$NF}')

echo "### phase 1: session open — connection admitted by the session chain"
exec 3<>/dev/tcp/127.0.0.1/\$PORT || { echo "    FAILED to connect"; exit 1; }
echo "one" >&3
read -t 3 -r line <&3 && r "echo back: '\$line'  -> flow established" || r "no echo (unexpected)"
r "conntrack: \$(conntrack -L 2>/dev/null | grep -c "dport=\$PORT") entry/entries for port \$PORT"

echo
echo "### phase 2: close_session teardown (exact nft_handler_cleanup sequence)"
nft -f - <<RULES2
delete rule inet authnft filter handle \$HANDLE
flush chain inet authnft session_test
delete chain inet authnft session_test
delete set inet authnft session_test_v4
RULES2
r "chain/set/jump gone: \$(nft list table inet authnft | grep -c 'session_test') references remain"
r "conntrack after teardown: \$(conntrack -L 2>/dev/null | grep -c "dport=\$PORT") entry/entries"

echo
echo "### phase 3: does the already-open connection still pass?"
echo "two" >&3
if read -t 3 -r line <&3; then
    r "echo back: '\$line'  -> FLOW SURVIVES TEARDOWN"
else
    r "no echo -> flow was revoked"
fi

echo
echo "### phase 4: can a NEW connection still get in?"
if timeout 3 bash -c "exec 4<>/dev/tcp/127.0.0.1/\$PORT" 2>/dev/null; then
    r "new connection ESTABLISHED -> new flows not revoked"
else
    r "new connection refused/timed out -> new flows correctly revoked"
fi

echo
echo "### phase 5: the proposed fix — flush conntrack by source address"
conntrack -D -s 127.0.0.1 2>&1 | tail -1 | sed 's/^/    /'
echo "three" >&3
if read -t 3 -r line <&3; then
    r "echo back: '\$line'  -> flow STILL passing after ct flush"
else
    r "no echo -> ct flush revoked the established flow"
fi
r "conntrack now: \$(conntrack -L 2>/dev/null | grep -c "dport=\$PORT") entry/entries for port \$PORT"
exec 3<&- 2>/dev/null

echo
echo "### phase 6: does an accept at priority filter-1 survive a deny chain at priority filter?"
nft add element inet authnft session2_v4 '{ 127.0.0.1 }' 2>/dev/null
nft -f - <<'RULES3'
add chain inet authnft session2
add set inet authnft session2_v4 { type ipv4_addr; }
add rule inet authnft filter jump session2
add rule inet authnft session2 ip saddr @session2_v4 tcp dport 19099 counter accept comment "session2-accept"
add chain inet authnft sitedeny { type filter hook input priority filter; policy drop; }
add rule inet authnft sitedeny ct state established,related counter accept
RULES3
nft add element inet authnft session2_v4 '{ 127.0.0.1 }'
# The trailing site-deny rule in the authnft chain would mask this; drop it
# so the only deny left is the separate base chain at priority filter.
DH=\$(nft -a list chain inet authnft filter | awk '/site-deny/{print \$NF}')
nft delete rule inet authnft filter handle \$DH
if timeout 3 bash -c "exec 5<>/dev/tcp/127.0.0.1/\$PORT" 2>/dev/null; then
    r "connection ESTABLISHED -> the module's accept carried past the deny chain"
else
    r "connection BLOCKED -> accept at filter-1 does NOT override a drop-policy chain at filter"
fi

echo
echo "### counters"
nft list table inet authnft | grep -E 'counter|comment' | sed 's/^/    /'
kill \$SRV 2>/dev/null
EOF
