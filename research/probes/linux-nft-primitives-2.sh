#!/bin/sh
# Round 2. Reserved-word-free chain names. Delay without sleep(1).
p() { printf 'PROBE:%s:%s\n' "$1" "$2"; }
delay() { timeout "$1" tail -f /dev/null; }

ip link set lo up

echo "### 5b. concatenated ip saddr . ether saddr set in the forward hook"
if nft -f - 2>/tmp/concat.err <<'EOF'
table inet t2 {
	set authorized {
		typeof ip saddr . ether saddr
		flags timeout
		elements = { 192.0.2.5 . 02:00:00:00:00:01 timeout 1h }
	}
	chain forwarding {
		type filter hook forward priority 0; policy drop;
		ip saddr . ether saddr @authorized accept
	}
}
EOF
then
	p concat-ip-mac-forward "OK"
	nft list set inet t2 authorized | tr -s ' \n' ' ' | sed 's/^/    /'; echo
else
	p concat-ip-mac-forward "FAILED ($(tr -d '\n' </tmp/concat.err))"
fi

echo
echo "### 6b. socket cgroupv2 in forward vs input"
for hook in forward input; do
	if nft -f - 2>/tmp/sock.err <<EOF
table inet t3_$hook {
	chain c {
		type filter hook $hook priority 0; policy accept;
		socket cgroupv2 level 1 "user.slice" accept
	}
}
EOF
	then p socket-cgroupv2-$hook "ACCEPTED"
	else p socket-cgroupv2-$hook "REJECTED ($(tr -d '\n' </tmp/sock.err | head -c 160))"
	fi
done

echo
echo "### 9. THE LOAD-BEARING ONE: does an expired element still authorize traffic?"
nft -f - <<'EOF'
table ip gate {
	set allow {
		type ipv4_addr
		flags timeout
	}
	chain input {
		type filter hook input priority 0; policy drop;
		ip saddr @allow counter accept
	}
}
EOF
nft add element ip gate allow '{ 127.0.0.1 timeout 3s }'
ping -c1 -W1 127.0.0.1 >/dev/null 2>&1 && p gate-before-expiry "PASS (traffic allowed)" || p gate-before-expiry "FAIL (blocked while element live)"
delay 5
STILL=$(nft -j list set ip gate allow | grep -c '127.0.0.1')
EXPIRES=$(nft -j list set ip gate allow | grep -o '"expires":[^,}]*' | head -1)
ping -c1 -W1 127.0.0.1 >/dev/null 2>&1 && AFTER="ALLOWED" || AFTER="BLOCKED"
p gate-after-expiry "traffic=$AFTER  element_still_listed=$STILL  $EXPIRES"
nft list set ip gate allow | tr -s ' \n' ' ' | sed 's/^/    /'; echo

echo
echo "### 10. when does GC actually reap, and does monitor report it?"
( timeout 25 nft monitor >/tmp/mon.out 2>&1 ) &
MON=$!
nft add element ip gate allow '{ 198.51.100.7 timeout 2s }'
i=0
while [ $i -lt 24 ]; do
	if ! nft list set ip gate allow 2>/dev/null | grep -q 198.51.100.7; then
		p gc-reap-latency "reaped after ~${i}s (timeout was 2s)"
		break
	fi
	delay 1
	i=$((i+1))
done
[ $i -ge 24 ] && p gc-reap-latency "NOT reaped within 24s (timeout was 2s)"
wait $MON
if grep -qi "delete element" /tmp/mon.out; then
	p gc-monitor-event "YES: $(grep -i 'delete element' /tmp/mon.out | head -1 | tr -s ' ')"
else
	p gc-monitor-event "NO event ($(wc -l </tmp/mon.out) monitor lines total)"
fi
sed 's/^/    mon: /' /tmp/mon.out | head -8

echo
echo "### 11. owner-flagged table: can a foreign socket write to it while the owner lives?"
# nft -i keeps one libnftables context (and its netlink socket) across commands.
( printf 'add table inet owned { flags owner; }\nlist tables\n'; delay 8; ) | nft -i >/tmp/owner_i.out 2>&1 &
delay 2
p owner-alive-listing "$(grep -c owned /tmp/owner_i.out) hit(s) in the owner's own view"
nft list tables 2>&1 | sed 's/^/    foreign view: /'
if nft add chain inet owned c2 2>/tmp/foreign.err; then
	p owner-foreign-write-live "ALLOWED"
else
	p owner-foreign-write-live "DENIED ($(tr -d '\n' </tmp/foreign.err | head -c 120))"
fi
if nft delete table inet owned 2>/tmp/foreign2.err; then
	p owner-foreign-delete-live "ALLOWED"
else
	p owner-foreign-delete-live "DENIED ($(tr -d '\n' </tmp/foreign2.err | head -c 120))"
fi
wait
p owner-after-exit "$(nft list tables | grep -c owned) owned table(s) remain after the holder exited"
