#!/bin/bash
# Host probes. Uses one throwaway table with NO base chains, so nothing this
# script does can affect a packet. Removes the table at the end.
p() { printf 'PROBE:%s:%s\n' "$1" "$2"; }
delay() { timeout "$1" tail -f /dev/null; }
T=authnft_probe

echo "### 0. is ctnetlink (conntrack(8)'s transport) even available?"
zgrep -h "NF_CT_NETLINK\|NF_CONNTRACK_EVENTS\|NF_CONNTRACK_TIMEOUT" /proc/config.gz 2>/dev/null ||
	grep -h "NF_CT_NETLINK\|NF_CONNTRACK_EVENTS" /boot/config-$(uname -r) 2>/dev/null ||
	echo "  (kernel config not exposed)"
grep -c "nf_conntrack_netlink" /lib/modules/$(uname -r)/modules.builtin 2>/dev/null | sed 's/^/  builtin match count: /'
ls /lib/modules/$(uname -r)/kernel/net/netfilter/nf_conntrack_netlink.ko* 2>&1 | sed 's/^/  module file: /'

echo
echo "### 1. did the expired element get reaped, and was the GC silent?"
nft list set ip $T s 2>/dev/null | tr -s ' \n' ' ' | sed 's/^/  /'; echo
nft list set ip $T s 2>/dev/null | grep -q 198.51.100.9 && p prior-elem "STILL PRESENT" || p prior-elem "REAPED (and no delete event was captured earlier)"

echo
echo "### 2. GC events: plain 'flags timeout' set vs 'flags dynamic,timeout' set"
nft add set ip $T plain   '{ type ipv4_addr; flags timeout; }'
nft add set ip $T dynamic '{ type ipv4_addr; flags dynamic,timeout; }'
( timeout -s INT 9 stdbuf -oL nft monitor > /tmp/mon3.out 2>&1 ) &
delay 1
nft add element ip $T plain   '{ 203.0.113.1 timeout 2s }'
nft add element ip $T dynamic '{ 203.0.113.2 timeout 2s }'
wait
p gc-event-plain   "$(grep -c 'delete element ip '"$T"' plain' /tmp/mon3.out) event(s)"
p gc-event-dynamic "$(grep -c 'delete element ip '"$T"' dynamic' /tmp/mon3.out) event(s)"
echo "  --- all monitor lines ---"; sed 's/^/  mon: /' /tmp/mon3.out
nft list set ip $T plain   | grep -q 203.0.113.1 && p plain-reaped "NO" || p plain-reaped "YES"
nft list set ip $T dynamic | grep -q 203.0.113.2 && p dynamic-reaped "NO" || p dynamic-reaped "YES"

echo
echo "### 3. THE K2 GAP: a cgroup-keyed element whose cgroup is gone"
CG=/sys/fs/cgroup/authnft_probe_scope
mkdir -p $CG && p cgroup-created "$CG inode $(stat -c %i $CG)"
nft add set ip $T cg '{ typeof socket cgroupv2 level 0; flags timeout; }'
if nft add element ip $T cg '{ "authnft_probe_scope" }' 2>/tmp/e1.err; then
	p cgroup-elem-add "OK"
	nft list set ip $T cg | tr -s ' \n' ' ' | sed 's/^/  /'; echo
else
	p cgroup-elem-add "FAILED ($(tr -d '\n' </tmp/e1.err | head -c 200))"
fi
rmdir $CG && p cgroup-destroyed "yes (simulating a reaped session scope)"
nft list set ip $T cg | tr -s ' \n' ' ' | sed 's/^/  element still in set: /'; echo
if nft delete element ip $T cg '{ "authnft_probe_scope" }' 2>/tmp/e2.err; then
	p delete-by-path-after-reap "SUCCEEDED"
else
	p delete-by-path-after-reap "FAILED ($(tr -d '\n' </tmp/e2.err | head -c 200))"
fi
if nft destroy element ip $T cg '{ "authnft_probe_scope" }' 2>/tmp/e3.err; then
	p destroy-by-path-after-reap "SUCCEEDED"
else
	p destroy-by-path-after-reap "FAILED ($(tr -d '\n' </tmp/e3.err | head -c 200))"
fi
# the escape hatches that need no key resolution
if nft flush set ip $T cg 2>/tmp/e4.err; then
	p flush-set-after-reap "SUCCEEDED (whole-set flush needs no key resolution)"
	nft list set ip $T cg | tr -s ' \n' ' ' | sed 's/^/  after flush: /'; echo
else
	p flush-set-after-reap "FAILED ($(tr -d '\n' </tmp/e4.err | head -c 200))"
fi

echo
echo "### 4. can the raw cgroup id be used instead of the path?"
nft add set ip $T cgnum '{ typeof socket cgroupv2 level 0; }' 2>/dev/null
nft add element ip $T cgnum '{ 12345 }' 2>/tmp/e5.err \
	&& p cgroup-elem-by-inode "ACCEPTED (numeric key works, no path resolution)" \
	|| p cgroup-elem-by-inode "REJECTED ($(tr -d '\n' </tmp/e5.err | head -c 200))"

echo
echo "### cleanup"
nft delete table ip $T && echo "  table $T deleted"
rmdir $CG 2>/dev/null
nft list tables | sed 's/^/  remaining: /'
