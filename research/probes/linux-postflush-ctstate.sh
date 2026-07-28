#!/bin/bash
# After `conntrack -D`, which ct state does the flow's next packet carry?
#
# This decides *why* a flush revokes access. If the packet is `new`, it is
# re-gated on the authorization set and revocation is a consequence of the
# ruleset. If it is `invalid`, revocation is a consequence of the policy
# dropping invalid traffic. The deauth arms in linux-owner-and-flush.sh cannot
# tell these apart, because neither state increments a counter that is guarded
# by the set.
#
# Policy is accept here and no rule consults a set, so the counters report the
# state and nothing else.
p() { printf 'PROBE:%s:%s\n' "$1" "$2"; }
delay() { timeout "$1" tail -f /dev/null; }

ip link set lo up

for loose in 1 0; do
	nft delete table ip s 2>/dev/null
	echo $loose > /proc/sys/net/netfilter/nf_conntrack_tcp_loose
	nft -f - <<'EOF'
table ip s {
	chain input {
		type filter hook input priority 0; policy accept;
		ct state new counter comment "new"
		ct state established counter comment "established"
		ct state related counter comment "related"
		ct state invalid counter comment "invalid"
	}
}
EOF
	ncat -l -k 9996 --sh-exec /bin/cat >/dev/null 2>&1 &
	N=$!
	delay 1
	exec 3<>/dev/tcp/127.0.0.1/9996 2>/dev/null || { p loose-$loose "connect failed"; kill $N; continue; }
	echo one >&3; read -t 3 -u 3 r1

	# Note: `nft reset counters` only touches named counter objects, so it does
	# nothing to the anonymous rule counters above. The totals below are
	# cumulative for the whole arm, which is still readable: the pre-flush
	# traffic accounts for one `new` (the SYN) and the rest `established`, so
	# any additional `new` or any `invalid` is post-flush.
	DEL=$(conntrack -D -s 127.0.0.1 2>&1 | tail -1)

	echo two >&3
	if read -t 3 -u 3 r2; then reply=got:$r2; else reply=TIMEOUT; fi

	STATES=$(nft -j list chain ip s input |
		 grep -oE '"comment": "[a-z]+"|"packets": [0-9]+' |
		 paste - - 2>/dev/null | tr -d '"' | tr '\n' ' ')
	p loose-$loose "pre_flush=[$r1] post_flush=[$reply]"
	p loose-$loose-delete "$DEL"
	nft list chain ip s input | grep counter | sed 's/^/      /'

	exec 3<&- 2>/dev/null
	kill $N 2>/dev/null
	delay 1
done
echo 1 > /proc/sys/net/netfilter/nf_conntrack_tcp_loose
