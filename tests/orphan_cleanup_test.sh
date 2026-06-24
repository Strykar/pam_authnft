#!/bin/bash
# Verifies nft_handler_cleanup_orphan: the parent's reaper for a sandboxed
# setup child that was SIGSYS-killed after committing per-session nft state but
# before reporting the jump-rule handle.
#
# Stages the exact state nft_handler_setup commits (per-session chain, three
# sets, a jump rule in the shared chain), then calls the orphan cleanup with
# the names but no handle, and asserts every object is gone.
#
# Host-safe: runs only when no live authnft table is present, so it never
# disturbs real sessions; it owns and removes the table it creates.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
DRIVER="$REPO/tests/.orphan_cleanup_driver"
CHAIN="session_orphantest_$$"
V4="${CHAIN}_v4"; V6="${CHAIN}_v6"; CG="${CHAIN}_cg"
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO=sudo

cleanup(){ $SUDO nft delete table inet authnft 2>/dev/null; rm -f "$DRIVER"; }
trap cleanup EXIT

if [ -z "${AUTHNFT_TEST_FORCE:-}" ] && $SUDO nft list table inet authnft >/dev/null 2>&1; then
    echo "SKIP: a live 'authnft' table is present; not exercising orphan cleanup on it"
    echo "      (set AUTHNFT_TEST_FORCE=1 to override in an isolated environment)"
    exit 0
fi

( cd "$REPO" && cc -O2 -Wall -Iinclude -D_GNU_SOURCE -o "$DRIVER" \
    tests/orphan_cleanup_driver.c src/*.c \
    $(pkg-config --cflags --libs libnftables libseccomp libsystemd pam libcap audit) ) \
    || { echo "FAIL: driver build"; exit 1; }

$SUDO nft -f - <<NFT || { echo "FAIL: could not stage orphaned nft state"; exit 1; }
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
add chain inet authnft $CHAIN
add set inet authnft $V4 { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }
add set inet authnft $V6 { typeof socket cgroupv2 level 2 . ip6 saddr; flags timeout; }
add set inet authnft $CG { typeof socket cgroupv2 level 2; flags timeout; }
add rule inet authnft filter jump $CHAIN
NFT

before=$($SUDO nft list table inet authnft 2>/dev/null | grep -c "$CHAIN" || true)
echo "staged: $before lines reference $CHAIN (chain + 3 sets + jump rule)"

$SUDO "$DRIVER" "$CHAIN" "$V4" "$V6" "$CG"

after=$($SUDO nft list table inet authnft 2>/dev/null | grep -c "$CHAIN" || true)
echo "after orphan cleanup: $after lines reference $CHAIN"

if [ "$before" -gt 0 ] && [ "$after" -eq 0 ]; then
    echo "RESULT: PASS (orphan cleanup reaped the chain, three sets, and jump rule by name)"
    exit 0
fi
echo "RESULT: FAIL ($after references remain)"
$SUDO nft list table inet authnft 2>/dev/null | grep "$CHAIN"
exit 1
