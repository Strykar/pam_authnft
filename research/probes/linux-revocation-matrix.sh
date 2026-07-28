#!/bin/bash
# Does revocation need a state kill on Linux?
# pf: a matching state entry skips rule evaluation, so authpf must run
# `pfctl -k <ip>` or live flows survive deauthorization.
# nftables: the ruleset is evaluated per packet. Test three rulesets against
# the same live TCP flow. A/B/C with a negative control in each arm.
p() { printf 'PROBE:%s:%s\n' "$1" "$2"; }
delay() { timeout "$1" tail -f /dev/null; }

ip link set lo up
ncat -l -k 9999 --sh-exec /bin/cat >/dev/null 2>&1 &
NCAT=$!
delay 1

talk() {
	if ! echo "$1" >&3 2>/dev/null; then echo "WRITE-FAIL"; return; fi
	if read -t 3 -u 3 reply 2>/dev/null; then echo "got:$reply"; else echo "TIMEOUT"; fi
}

run_arm() { # $1=arm name  $2=accept rule text
	arm=$1; rule=$2
	nft delete table ip gate 2>/dev/null
	nft -f - <<EOF
table ip gate {
	set allow { type ipv4_addr; flags timeout; }
	chain input {
		type filter hook input priority 0; policy drop;
		$rule
	}
}
EOF
	if [ $? -ne 0 ]; then p "$arm" "RULESET REJECTED"; return; fi
	nft add element ip gate allow '{ 127.0.0.1 }'
	exec 3<>/dev/tcp/127.0.0.1/9999 2>/dev/null || { p "$arm" "connect failed"; return; }
	BEFORE=$(talk hello)                       # positive control: authorized
	nft delete element ip gate allow '{ 127.0.0.1 }'
	AFTER=$(talk world)                        # the revocation test
	nft add element ip gate allow '{ 127.0.0.1 }'
	REAUTH=$(talk again)                       # does it come back?
	exec 3<&- 2>/dev/null
	p "$arm" "authorized=[$BEFORE] after_revoke=[$AFTER] after_reauth=[$REAUTH]"
	echo "    rule: $rule"
}

echo "### arm A: the authpf-shaped ruleset (established bypass first)"
run_arm A-established-bypass 'ct state established,related accept
		ip saddr @allow ct state new accept'

echo
echo "### arm B: no bypass, authorization checked on every packet"
run_arm B-per-packet-saddr 'ip saddr @allow accept'

echo
echo "### arm C: match the conntrack tuple's original source, both directions"
run_arm C-ct-original-saddr 'ct original ip saddr @allow accept'

echo
echo "### arm D: C plus the established fast path, ordered after the check"
run_arm D-ct-original-then-est 'ct original ip saddr @allow accept
		ct state established,related accept'

kill $NCAT 2>/dev/null

echo
echo "### mid-stream pickup: what state does a flow with no ct entry get?"
for loose in 1 0; do
	nft delete table ip gate 2>/dev/null
	nft delete table ip probe 2>/dev/null
	echo $loose > /proc/sys/net/netfilter/nf_conntrack_tcp_loose 2>/dev/null
	ncat -l -k 9998 --sh-exec /bin/cat >/dev/null 2>&1 &
	N2=$!
	delay 1
	# phase 1: no ct-using rule anywhere, so this netns is not tracking
	exec 4<>/dev/tcp/127.0.0.1/9998 2>/dev/null || { echo "connect failed"; kill $N2; continue; }
	echo pre >&4; read -t 3 -u 4 r1
	# phase 2: introduce conntrack mid-flow. Existing flow has no entry, so its
	# next packet is exactly what a post-flush packet looks like.
	nft -f - <<'EOF'
table ip probe {
	chain input {
		type filter hook input priority 0; policy accept;
		ct state new counter comment "new"
		ct state established counter comment "est"
		ct state invalid counter comment "invalid"
	}
}
EOF
	echo mid >&4; read -t 3 -u 4 r2
	COUNTS=$(nft -j list table ip probe | grep -o '"packets": [0-9]*' | tr -d '\n')
	p midstream-loose-$loose "reply1=[$r1] reply2=[$r2] counters(new,est,invalid)=[$COUNTS]"
	nft list chain ip probe input | grep counter | sed 's/^/      /'
	exec 4<&- 2>/dev/null
	kill $N2 2>/dev/null
done

echo
echo "### dynamic set GC: does it emit a netlink event where a plain one does not?"
nft add table ip m
nft add set ip m plainset '{ type ipv4_addr; flags timeout; }'
nft add set ip m dynset '{ type ipv4_addr; flags dynamic,timeout; }' 2>&1 | sed 's/^/    /'
( timeout -s INT 9 stdbuf -oL nft monitor > /tmp/mon4.out 2>&1 ) &
delay 1
nft add element ip m plainset '{ 203.0.113.1 timeout 2s }'
nft add element ip m dynset   '{ 203.0.113.2 timeout 2s }'
wait
p gc-event-plainset "$(grep -c 'delete element ip m plainset' /tmp/mon4.out)"
p gc-event-dynset   "$(grep -c 'delete element ip m dynset' /tmp/mon4.out)"
sed 's/^/    mon: /' /tmp/mon4.out
