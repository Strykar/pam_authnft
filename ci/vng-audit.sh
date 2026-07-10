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
# Guest writes are ephemeral (virtme-ng overlays the host rootfs), so the
# audit's groupadd/useradd/nft/etc. mutate nothing on the host. The host
# must carry the build + test deps (gcc, make, nft, pamtester, valgrind)
# because the guest uses the host rootfs; on this project's dev host they
# are all present.
#
# Kernel matrix:
#   KERNELS="host"            # default: boot the host's running kernel
#   KERNELS="host v6.12 v6.6" # also boot precompiled upstream kernels
#                             # (virtme-ng downloads them on demand)
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

overall=0
for k in $KERNELS; do
    echo "=================================================================="
    echo "=== tier-2 audit under kernel: $k ==="
    echo "=================================================================="
    if [ "$k" = host ]; then
        runspec=(-r)
    else
        runspec=(-r "$k")
    fi
    # --systemd: systemd as init so systemd-run --scope + pamtester work.
    # --user root: the audit needs root for nft/group/pam.
    # The guest runs the same audit/run-audit.sh; its verdict (exit code)
    # is propagated out by vng.
    # Runs the reliable A+C audit (unit/seccomp + fault matrix) under a real
    # kernel. The integration suite (Part B) is opt-in and disabled by
    # default: it has host-environment coupling that does not survive
    # headless execution in either audit substrate (see run-all.sh and
    # docs/CI_LOCAL.md). Set AUDIT_RUN_INTEGRATION=1 to try it; the value is
    # forwarded into the guest exec below so run-all.sh sees it.
    if vng "${runspec[@]}" --user root --systemd -p "$CPUS" -m "$MEM" \
            --exec "cd '$REPO' && AUDIT_RUN_INTEGRATION=${AUDIT_RUN_INTEGRATION:-0} ./audit/run-all.sh"; then
        echo "=== kernel $k: PASS ==="
    else
        echo "=== kernel $k: FAIL ==="
        overall=1
    fi
done

echo
echo "=== tier-2 overall: $([ "$overall" -eq 0 ] && echo PASS || echo FAIL) ==="
exit "$overall"
