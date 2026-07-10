#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Local root-capable audit harness — tier 2 (real-kernel microVM).
#
# Runs audit/run-audit.sh inside a virtme-ng microVM that boots a real
# kernel under KVM, with systemd as init so the systemd-run scope and
# pamtester lifecycle work. The container tier (tier 1) shares the host
# kernel and runs the cgroup/socket stages under a nested cgroup
# namespace; this tier boots a real kernel with a real cgroup hierarchy,
# and can sweep a kernel matrix to catch nft/netfilter behaviour that is
# kernel-version specific.
#
# Two things run per kernel:
#   1. tests/packet_match_headless.sh — the socket-cgroupv2 packet-match
#      invariants (allowed/disallowed match, alloc-time invariant, per-
#      session isolation). This is the kernel-version-specific behaviour,
#      decoupled from the PAM/pamtester integration suite so it survives a
#      headless microVM run. Exit 77 = the guest kernel lacks the feature
#      (noted, not a failure).
#   2. audit/run-all.sh — Parts A + C (unit + seccomp + fault matrix), with
#      Part B (integration) opt-in via AUDIT_RUN_INTEGRATION.
#
# Guest writes are ephemeral (virtme-ng overlays the host rootfs), so the
# audit's groupadd/useradd/nft/etc. mutate nothing on the host. The host
# must carry the build + test deps (gcc, make, nft, pamtester, valgrind)
# because the guest uses the host rootfs; on this project's dev host they
# are all present.
#
# Kernel matrix:
#   KERNELS="host"             # default: boot the host's running kernel
#   KERNELS="host v6.8 latest" # also boot precompiled upstream kernels
#                              # (virtme-ng downloads Ubuntu mainline
#                              # builds on demand; needs dpkg on the host)
# The special name "latest" resolves to the newest tagged mainline build
# with an amd64 image, tracking Linus's tree at tag granularity.
#
# Tunables: VNG_CPUS (default 4), VNG_MEM (default 4G).
set -uo pipefail

cd "$(dirname "$0")/.."
REPO="$(pwd)"

KERNELS="${KERNELS:-host}"
CPUS="${VNG_CPUS:-4}"
MEM="${VNG_MEM:-4G}"

command -v vng >/dev/null || { echo "virtme-ng (vng) not installed" >&2; exit 1; }
test -e /dev/kvm || echo "WARNING: /dev/kvm absent — vng will be slow (TCG)" >&2

# Resolve the "latest" pseudo-kernel to the newest tagged mainline build
# that actually published an amd64 image (rc builds occasionally fail to
# build; step back through the newest tags until one has binaries).
# `-rc` tags are mapped to `~rc` for the version sort so a final release
# outranks its own release candidates.
resolve_latest() {
    local tags t
    tags=$(curl -fsSL https://kernel.ubuntu.com/mainline/ \
        | grep -oP 'href="v[0-9][^"/]*/"' | grep -oP 'v[0-9][^"/]*' \
        | sed 's/-rc/~rc/' | sort -uV | sed 's/~rc/-rc/' | tail -5 | tac)
    [ -n "$tags" ] || return 1
    for t in $tags; do
        if curl -fsSL "https://kernel.ubuntu.com/mainline/$t/" 2>/dev/null \
                | grep -q 'amd64.*linux-image'; then
            echo "$t"
            return 0
        fi
    done
    return 1
}

overall=0
for k in $KERNELS; do
    if [ "$k" = latest ]; then
        if ! k=$(resolve_latest); then
            echo "=== kernel latest: FAIL (could not resolve a mainline build) ==="
            overall=1
            continue
        fi
        echo "(latest resolved to mainline $k)"
    fi
    echo "=================================================================="
    echo "=== tier-2 under kernel: $k ==="
    echo "=================================================================="
    if [ "$k" = host ]; then
        runspec=(-r)
    else
        runspec=(-r "$k")
    fi
    # --systemd: systemd as init so systemd-run --scope works.
    # --user root: both the harness and the audit need root for nft/cgroup/pam.
    # vng propagates the guest command's exit code out to us.
    kfail=0

    # Packet-match invariants — the kernel-version-specific proof.
    echo "--- packet-match invariants ---"
    vng "${runspec[@]}" --user root --systemd -p "$CPUS" -m "$MEM" \
        --exec "cd '$REPO' && ./tests/packet_match_headless.sh"
    pm=$?
    if [ "$pm" -eq 0 ]; then
        echo "=== kernel $k packet-match: PASS ==="
    elif [ "$pm" -eq 77 ]; then
        echo "=== kernel $k packet-match: SKIP (kernel lacks socket-cgroupv2) ==="
    else
        echo "=== kernel $k packet-match: FAIL ==="; kfail=1
    fi

    # Reliable A+C audit (unit/seccomp + fault matrix). The integration
    # suite (Part B) stays opt-in and disabled by default: it has host-
    # environment coupling that does not survive headless execution (see
    # run-all.sh and docs/CI_LOCAL.md). Set AUDIT_RUN_INTEGRATION=1 to try
    # it; the value is forwarded into the guest exec so run-all.sh sees it.
    echo "--- audit (unit + seccomp + fault matrix) ---"
    vng "${runspec[@]}" --user root --systemd -p "$CPUS" -m "$MEM" \
        --exec "cd '$REPO' && AUDIT_RUN_INTEGRATION=${AUDIT_RUN_INTEGRATION:-0} ./audit/run-all.sh"
    au=$?
    if [ "$au" -eq 0 ]; then
        echo "=== kernel $k audit: PASS ==="
    else
        echo "=== kernel $k audit: FAIL ==="; kfail=1
    fi

    if [ "$kfail" -eq 0 ]; then
        echo "=== kernel $k: PASS ==="
    else
        echo "=== kernel $k: FAIL ==="
        overall=1
    fi
done

echo
echo "=== tier-2 overall: $([ "$overall" -eq 0 ] && echo PASS || echo FAIL) ==="
exit "$overall"
