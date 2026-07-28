#!/bin/bash
# Does removing the authorization actually cut a live connection?
# authpf runs `pfctl -k <ip>` at logout precisely because removing the rule
# does not. Test the Linux equivalent end to end. Runs in a dedicated netns.
p() { printf 'PROBE:%s:%s\n' "$1" "$2"; }
delay() { timeout "$1" tail -f /dev/null; }

ip link set lo up

nft -f - <<'EOF'
table ip gate {
	set allow {
		type ipv4_addr
		flags timeout
	}
	chain input {
		type filter hook input priority 0; policy drop;
		ct state established,related counter accept
		ip saddr @allow ct state new counter accept
	}
}
EOF
nft add element ip gate allow '{ 127.0.0.1 }'

ncat -l -k 9999 --sh-exec /bin/cat >/dev/null 2>&1 &
NCAT=$!
delay 1

talk() { # $1 = word to send; echoes what came back, or "TIMEOUT"
	if ! echo "$1" >&3 2>/dev/null; then echo "WRITE-FAIL"; return; fi
	if read -t 3 -u 3 reply 2>/dev/null; then echo "$reply"; else echo "TIMEOUT"; fi
}

if ! exec 3<>/dev/tcp/127.0.0.1/9999 2>/dev/null; then
	p connect "FAILED to establish - aborting"; kill $NCAT; exit 1
fi
p connect-while-authorized "echo returned: $(talk one)"

echo "--- conntrack entry for the session ---"
conntrack -L 2>/dev/null | grep 9999 | sed 's/^/    /'
p tcp_loose "$(cat /proc/sys/net/netfilter/nf_conntrack_tcp_loose)"

echo
echo "### deauth step 1: remove the set element only (no state kill)"
nft delete element ip gate allow '{ 127.0.0.1 }'
p after-element-removed "echo returned: $(talk two)"

echo
echo "### deauth step 2: kill the conntrack states (the pfctl -k equivalent)"
conntrack -D -s 127.0.0.1 2>&1 | tail -2 | sed 's/^/    /'
conntrack -L 2>/dev/null | grep -c 9999 | sed 's/^/    remaining ct entries for port 9999: /'
p after-ct-flush "echo returned: $(talk three)"

echo
echo "### deauth step 3: same, with loose mid-stream pickup disabled"
echo 0 > /proc/sys/net/netfilter/nf_conntrack_tcp_loose
conntrack -D -s 127.0.0.1 >/dev/null 2>&1
p after-ct-flush-strict "echo returned: $(talk four)"
conntrack -L 2>/dev/null | grep 9999 | sed 's/^/    ct now: /'
nft -j list table ip gate | grep -o '"packets": [0-9]*' | sed 's/^/    counter: /'

exec 3<&- 2>/dev/null
kill $NCAT 2>/dev/null

echo
echo "### B. does a foreign 'nft flush ruleset' destroy an owner-flagged table?"
( printf 'add table inet sess { flags owner; }\nadd chain inet sess c\n'; delay 6 ) | nft -i >/dev/null 2>&1 &
delay 2
nft list tables | sed 's/^/    before: /'
if nft flush ruleset 2>/tmp/flush.err; then
	p foreign-flush-ruleset "SUCCEEDED"
else
	p foreign-flush-ruleset "REFUSED ($(tr -d '\n' </tmp/flush.err | head -c 120))"
fi
nft list tables | sed 's/^/    after:  /'
wait

echo
echo "### C. does the kernel tell userspace when an element is GC'd?"
nft add table ip m
nft add set ip m s '{ type ipv4_addr; flags timeout; }'
( timeout 8 stdbuf -oL nft monitor >/tmp/mon.out 2>&1 ) &
MON=$!
delay 1
nft add element ip m s '{ 198.51.100.7 timeout 2s }'
wait $MON
p gc-netlink-event "$(grep -ci 'delete element' /tmp/mon.out) delete-element event(s) seen"
sed 's/^/    mon: /' /tmp/mon.out | head -6

echo
echo "### E. cgroupv2-keyed elements: does delete need the path to still resolve?"
nft add set ip m cg '{ typeof socket cgroupv2 level 0; flags timeout; }' 2>/tmp/cg.err \
	&& p cgroup-set-create "OK" || p cgroup-set-create "FAILED ($(tr -d '\n' </tmp/cg.err | head -c 120))"
if nft add element ip m cg '{ "user.slice" }' 2>/tmp/cg2.err; then
	p cgroup-elem-add-existing-path "OK"
	nft list set ip m cg | tr -s ' \n' ' ' | sed 's/^/    /'; echo
	nft delete element ip m cg '{ "user.slice" }' 2>&1 | sed 's/^/    delete: /'
else
	p cgroup-elem-add-existing-path "FAILED ($(tr -d '\n' </tmp/cg2.err | head -c 160))"
fi
if nft add element ip m cg '{ "user.slice/never-existed-42.scope" }' 2>/tmp/cg3.err; then
	p cgroup-elem-add-missing-path "ACCEPTED (path not resolved at insert)"
else
	p cgroup-elem-add-missing-path "REJECTED ($(tr -d '\n' </tmp/cg3.err | head -c 150))"
fi
if nft delete element ip m cg '{ "user.slice/never-existed-42.scope" }' 2>/tmp/cg4.err; then
	p cgroup-elem-delete-missing-path "ACCEPTED"
else
	p cgroup-elem-delete-missing-path "REJECTED ($(tr -d '\n' </tmp/cg4.err | head -c 150))"
fi
