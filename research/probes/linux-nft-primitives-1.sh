#!/bin/sh
# Probe the nftables primitives an authnft would rely on.
# Runs entirely inside an unprivileged user+net namespace: the host ruleset
# is never touched. Every check prints PROBE:<name>:<result>.

p() { printf 'PROBE:%s:%s\n' "$1" "$2"; }

echo "### 1. owner flag: is the table released when the netlink socket closes?"
# each nft invocation is its own process, hence its own netlink socket.
nft add table inet own_a '{ flags owner; }'
if nft list tables | grep -q own_a; then
	p owner-destroy-on-close "NO (table survived socket close)"
else
	p owner-destroy-on-close "YES (table gone after creating process exited)"
fi

nft add table inet own_b '{ flags owner,persist; }'
if nft list tables | grep -q own_b; then
	p owner-persist "YES (persist keeps it after socket close)"
else
	p owner-persist "NO"
fi
nft delete table inet own_b 2>/dev/null

echo
echo "### 2. can a second socket write into another socket's owned table?"
# hold an owned table open on fd 3 via nft -i is awkward; instead check the
# error surface: recreate as owner from process A, then have process B add a
# chain to it. If A's table is already gone (per probe 1) this is moot, so
# use persist+owner: owned by A's portID but surviving A's exit.
nft add table inet own_c '{ flags owner,persist; }'
if nft add chain inet own_c c 2>/tmp/own_c.err; then
	p owned-table-foreign-write "ALLOWED"
else
	p owned-table-foreign-write "DENIED ($(tr -d '\n' </tmp/own_c.err))"
fi
nft delete table inet own_c 2>/dev/null

echo
echo "### 3. cross-table verdict: is accept in one table authoritative?"
ip link set lo up
nft -f - <<'EOF'
table ip early {
	chain in {
		type filter hook input priority -100; policy accept;
		ip protocol icmp counter accept
	}
}
table ip late {
	chain in {
		type filter hook input priority 100; policy accept;
		ip protocol icmp counter drop
	}
}
EOF
ping -c1 -W1 127.0.0.1 >/dev/null 2>&1 && PING=up || PING=down
EARLY=$(nft -j list table ip early | grep -o '"packets": [0-9]*' | head -1)
LATE=$(nft -j list table ip late | grep -o '"packets": [0-9]*' | head -1)
p cross-table-accept "ping=$PING early_counter=[$EARLY] late_counter=[$LATE]"
nft delete table ip early; nft delete table ip late

echo
echo "### 4. does 'create element' fail on a duplicate (kernel-side uniqueness)?"
nft add table inet t
nft add set inet t s '{ type ipv4_addr; flags timeout; }'
nft create element inet t s '{ 192.0.2.1 }'
if nft create element inet t s '{ 192.0.2.1 }' 2>/tmp/dup.err; then
	p create-elem-eexist "NO (duplicate accepted)"
else
	p create-elem-eexist "YES ($(tr -d '\n' </tmp/dup.err))"
fi
if nft add element inet t s '{ 192.0.2.1 }' 2>/dev/null; then
	p add-elem-idempotent "YES (add overwrites silently)"
else
	p add-elem-idempotent "NO"
fi

echo
echo "### 5. concatenated ip saddr . ether saddr set, usable in forward?"
if nft -f - 2>/tmp/concat.err <<'EOF'
table inet t2 {
	set authorized {
		typeof ip saddr . ether saddr
		flags timeout
		elements = { 192.0.2.5 . 02:00:00:00:00:01 timeout 1h }
	}
	chain fwd {
		type filter hook forward priority 0; policy drop;
		ip saddr . ether saddr @authorized accept
	}
}
EOF
then
	p concat-ip-mac-forward "OK"
else
	p concat-ip-mac-forward "FAILED ($(tr -d '\n' </tmp/concat.err))"
fi

echo
echo "### 6. socket cgroupv2 in the forward hook?"
if nft -f - 2>/tmp/sock.err <<'EOF'
table inet t3 {
	chain fwd {
		type filter hook forward priority 0; policy accept;
		socket cgroupv2 level 1 "user.slice" accept
	}
}
EOF
then
	p socket-cgroupv2-forward "ACCEPTED BY KERNEL"
else
	p socket-cgroupv2-forward "REJECTED ($(tr -d '\n' </tmp/sock.err))"
fi

echo
echo "### 7. element expiry: does the kernel emit a netlink event on GC?"
nft add set inet t exp '{ type ipv4_addr; flags timeout; timeout 1s; }'
( timeout 6 nft monitor sets elements >/tmp/mon.out 2>&1 ) &
MON=$!
nft add element inet t exp '{ 198.51.100.7 }'
wait $MON
if grep -qi "delete element" /tmp/mon.out; then
	p elem-expiry-event "YES ($(grep -i 'delete element' /tmp/mon.out | head -1 | tr -s ' '))"
else
	p elem-expiry-event "NO EVENT SEEN (monitor output: $(tr -d '\n' </tmp/mon.out | head -c 200))"
fi
nft list set inet t exp | grep -q 198.51.100.7 && p elem-expired-gone "NO (still present)" || p elem-expired-gone "YES (element removed)"

echo
echo "### 8. per-element timeout refresh from userspace, and remaining time"
nft add element inet t exp '{ 203.0.113.9 timeout 10s }'
nft -j list set inet t exp | grep -o '"expires":[^,}]*' | head -2 | sed 's/^/    /'
p elem-timeout-visible "see expires above"
