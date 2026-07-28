#!/bin/bash
# Can the module's accept actually admit anything?
#
# pam_authnft only ever adds accept rules, into a chain at
# `priority filter - 1` whose policy is accept. Whatever denies traffic
# therefore lives outside the module, and the docs never say where. This
# measures the three placements an admin could plausibly pick.
#
#   A  site default-deny as a separate base chain at priority filter
#   B  deny as a rule in the shared chain, added BEFORE the session jump
#   C  deny as a rule in the shared chain, added AFTER the session jump
#
# C is also the positive control: if C cannot admit traffic, A and B pass
# vacuously and the run means nothing.
#
# The match key is `ip saddr` rather than `socket cgroupv2 level 2 . ip
# saddr`; rule ordering and chain traversal are independent of the key.
#
# Run as root. Everything happens in a throwaway netns.
set -u

NS=authnft-prio
PORT=19099

[[ $(id -u) -eq 0 ]] || { echo "needs root"; exit 1; }

ip netns del $NS 2>/dev/null
ip netns add $NS || exit 1
trap 'ip netns pids '$NS' 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del '$NS' 2>/dev/null' EXIT
ip -n $NS link set lo up

ip netns exec $NS bash -s <<'EOF'
set -u
PORT=19099
r() { echo "    $*"; }

socat TCP-LISTEN:$PORT,reuseaddr,fork EXEC:/bin/cat &
SRV=$!
for i in $(seq 50); do
    ss -ltn 2>/dev/null | grep -q ":$PORT" && break
    sleep 0.1
done

# The module's own objects, built exactly as nft_handler_setup does:
# shared chain at priority filter - 1 with policy accept, ct rule first,
# per-session chain reached by an appended jump.
module_state() {
    nft delete table inet authnft 2>/dev/null
    nft -f - <<'RULES'
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
add set inet authnft session_v4 { type ipv4_addr; flags timeout; }
add chain inet authnft session_test
add rule inet authnft filter ct state established,related counter accept comment "ct-accept"
add rule inet authnft session_test ip saddr @session_v4 tcp dport 19099 counter accept comment "session-accept"
add element inet authnft session_v4 { 127.0.0.1 timeout 1d }
RULES
}

sess_pkts() { nft list chain inet authnft session_test | grep session-accept | grep -oP 'packets \K[0-9]+'; }
deny_pkts() { nft list table inet authnft | grep site-deny | grep -oP 'packets \K[0-9]+'; }

try() { timeout 3 bash -c "exec 9<>/dev/tcp/127.0.0.1/$PORT" 2>/dev/null; }

echo "### C (control): deny appended to the shared chain AFTER the session jump"
module_state
nft add rule inet authnft filter jump session_test
nft add rule inet authnft filter tcp dport $PORT counter drop comment '"site-deny"'
if try; then r "ESTABLISHED  (session-accept=$(sess_pkts), site-deny=$(deny_pkts))"
else        r "BLOCKED      (session-accept=$(sess_pkts), site-deny=$(deny_pkts))  <-- control failed, rest of run is vacuous"; fi

echo
echo "### B: deny added to the shared chain BEFORE the session jump"
module_state
nft add rule inet authnft filter tcp dport $PORT counter drop comment '"site-deny"'
nft add rule inet authnft filter jump session_test   # module appends, lands after the drop
r "chain order: $(nft list chain inet authnft filter | grep -cE 'drop|jump') rules; drop precedes jump"
if try; then r "ESTABLISHED  (session-accept=$(sess_pkts), site-deny=$(deny_pkts))"
else        r "BLOCKED      (session-accept=$(sess_pkts), site-deny=$(deny_pkts))"; fi

echo
echo "### A: site default-deny as a separate base chain at priority filter"
module_state
nft add rule inet authnft filter jump session_test
nft -f - <<'RULES'
add chain inet authnft sitedeny { type filter hook input priority filter; policy drop; }
add rule inet authnft sitedeny ct state established,related counter accept comment "site-ct"
RULES
if try; then r "ESTABLISHED  (session-accept=$(sess_pkts))"
else        r "BLOCKED      (session-accept=$(sess_pkts))  <-- module accepted, deny chain dropped it anyway"; fi

echo
echo "### final ruleset"
nft list table inet authnft | sed 's/^/    /'
kill $SRV 2>/dev/null
EOF
