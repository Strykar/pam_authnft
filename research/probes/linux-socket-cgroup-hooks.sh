#!/bin/bash
# Can `socket cgroupv2` match a forwarded packet?
#
# linux-kernel-integration.md asserted "a forwarded packet has no local socket, so it cannot"
# from reasoning alone, because two earlier probes died on cgroup path
# resolution instead of on the hook. This settles it by execution.
#
# Run as root on the HOST, not under `ip netns exec`: that remounts /sys and
# cgroup paths stop resolving. This script does its own netns work with
# `nsenter --net`, which leaves mounts alone.
#
#   client(A) --- veth --- (R) router --- veth --- (B) server
#
# Negative arm: R's forward chain tries to match a cgroup. Nothing forwarded
# through R belongs to a local socket, so it must never match, while a bare
# counter beside it must.
# Positive control: the same expression in R's input hook against a real local
# socket created inside the cgroup. It must match, otherwise the negative arm
# proves nothing about the hook.

set -u
p() { printf 'PROBE:%s:%s\n' "$1" "$2"; }
delay() { timeout "$1" tail -f /dev/null; }

# Precondition. Without nft_socket the kernel cannot resolve the `socket`
# expression and every rule add returns ENOENT, which looks exactly like a hook
# rejection. A running kernel whose /lib/modules tree was removed by a package
# upgrade cannot autoload it, so check before measuring anything.
if ! lsmod | grep -q '^nft_socket' && ! modprobe nft_socket 2>/dev/null; then
	p PRECONDITION "FAILED: nft_socket unavailable (running $(uname -r), modules present: $(ls -d /lib/modules/*/ | xargs -n1 basename | tr '\n' ' '))"
	echo "Reboot onto a kernel whose module tree exists, then re-run. Every"
	echo "result below would otherwise be an artefact."
	exit 1
fi
p PRECONDITION "nft_socket available"

CG=/sys/fs/cgroup/authnft_hookprobe
NS_A=anp_a NS_R=anp_r NS_B=anp_b
inA() { nsenter --net=/run/netns/$NS_A "$@"; }
inR() { nsenter --net=/run/netns/$NS_R "$@"; }
inB() { nsenter --net=/run/netns/$NS_B "$@"; }

cleanup() {
	for n in $NS_A $NS_R $NS_B; do ip netns delete $n 2>/dev/null; done
	[ -d $CG ] && rmdir $CG 2>/dev/null
}
trap cleanup EXIT

echo "### setup"
cleanup
for n in $NS_A $NS_R $NS_B; do ip netns add $n; done

# A <-> R
ip link add va type veth peer name vra
ip link set va netns $NS_A
ip link set vra netns $NS_R
# B <-> R
ip link add vb type veth peer name vrb
ip link set vb netns $NS_B
ip link set vrb netns $NS_R

inA ip addr add 10.10.1.2/24 dev va
inA ip link set va up
inA ip link set lo up
inA ip route add default via 10.10.1.1

inB ip addr add 10.10.2.2/24 dev vb
inB ip link set vb up
inB ip link set lo up
inB ip route add default via 10.10.2.1

inR ip addr add 10.10.1.1/24 dev vra
inR ip addr add 10.10.2.1/24 dev vrb
inR ip link set vra up
inR ip link set vrb up
inR ip link set lo up
inR sysctl -qw net.ipv4.ip_forward=1
p forwarding "$(inR sysctl -n net.ipv4.ip_forward)"

mkdir -p $CG || { p cgroup "FAILED to create $CG"; exit 1; }
CGID=$(stat -c %i $CG)
p cgroup "$CG inode $CGID"

echo
echo "### does the kernel even accept the expression in each hook?"
for hook in forward input output prerouting; do
	prio=0; [ $hook = prerouting ] && prio=-150
	if inR nft -f - 2>/tmp/h.err <<EOF
table inet h_$hook {
	chain c {
		type filter hook $hook priority $prio; policy accept;
		socket cgroupv2 level 1 "authnft_hookprobe" counter
	}
}
EOF
	then p accepted-in-$hook "YES"
	else p accepted-in-$hook "NO ($(tr -d '\n' </tmp/h.err | head -c 110))"
	fi
	inR nft delete table inet h_$hook 2>/dev/null
done

echo
echo "### negative arm: forwarded traffic through R"
inR nft -f - <<EOF
table inet fwdtest {
	chain c {
		type filter hook forward priority 0; policy accept;
		socket cgroupv2 level 1 "authnft_hookprobe" counter comment "cgmatch"
		meta l4proto tcp counter comment "control"
	}
}
EOF
inB timeout 20 ncat -l -k 9999 --sh-exec /bin/cat >/dev/null 2>&1 &
delay 1
FWD=$(inA timeout 5 bash -c 'exec 3<>/dev/tcp/10.10.2.2/9999 && echo ping >&3 && head -c 4 <&3' 2>/dev/null)
p forwarded-roundtrip "[$FWD]"
inR nft list chain inet fwdtest c | grep counter | sed 's/^/    /'
CGM=$(inR nft -j list chain inet fwdtest c | grep -o '"packets": [0-9]*' | head -1 | grep -o '[0-9]*')
CTL=$(inR nft -j list chain inet fwdtest c | grep -o '"packets": [0-9]*' | tail -1 | grep -o '[0-9]*')
p forward-cgroup-match "cgmatch=$CGM control=$CTL"

echo
echo "### positive control: a local socket inside that cgroup, input hook on R"
inR nft -f - <<EOF
table inet inp {
	chain c {
		type filter hook input priority 0; policy accept;
		tcp dport 9998 socket cgroupv2 level 1 "authnft_hookprobe" counter comment "cgmatch"
		tcp dport 9998 counter comment "control"
	}
}
EOF
# put the listener's shell into the cgroup, then start it there, so the
# listening socket is created by a task inside $CG
(
	echo $BASHPID > $CG/cgroup.procs 2>/dev/null || exit 1
	exec nsenter --net=/run/netns/$NS_R timeout 20 ncat -l -k 9998 --sh-exec /bin/cat
) >/dev/null 2>&1 &
LPID=$!
delay 1
p listener-cgroup "$(cat /proc/$LPID/cgroup 2>/dev/null | head -1)"
LOC=$(inA timeout 5 bash -c 'exec 3<>/dev/tcp/10.10.1.1/9998 && echo ping >&3 && head -c 4 <&3' 2>/dev/null)
p local-roundtrip "[$LOC]"
inR nft list chain inet inp c | grep counter | sed 's/^/    /'
ICGM=$(inR nft -j list chain inet inp c | grep -o '"packets": [0-9]*' | head -1 | grep -o '[0-9]*')
ICTL=$(inR nft -j list chain inet inp c | grep -o '"packets": [0-9]*' | tail -1 | grep -o '[0-9]*')
p input-cgroup-match "cgmatch=$ICGM control=$ICTL"

kill $LPID 2>/dev/null
echo
echo "### verdict"
if [ "${ICGM:-0}" -gt 0 ] && [ "${CGM:-0}" -eq 0 ] && [ "${CTL:-0}" -gt 0 ]; then
	p VERDICT "expression works on a local socket and never matches forwarded traffic"
elif [ "${ICGM:-0}" -eq 0 ]; then
	p VERDICT "INCONCLUSIVE: positive control did not match, so the negative arm proves nothing"
else
	p VERDICT "UNEXPECTED: cgmatch=$CGM control=$CTL input_cgmatch=$ICGM"
fi
