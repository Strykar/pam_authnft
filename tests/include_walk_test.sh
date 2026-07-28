#!/bin/bash
# Fixtures and namespace for tests/include_walk_driver.c (issue #108).
#
# The validator only accepts include paths under /etc/authnft/, so the
# fixtures have to live there. A private mount namespace with a tmpfs bound
# over /etc/authnft gives real paths under the real prefix while leaving the
# host's /etc/authnft alone. Needs root for the bind mount; nothing else.
#
# Fixtures are built as root so the ownership checks see uid 0, except the
# two that deliberately fail them.
set -euo pipefail

[[ $(id -u) -eq 0 ]] || { echo "needs root (bind mount)"; exit 1; }

HERE=$(cd "$(dirname "$0")/.." && pwd)
DRIVER=$HERE/tests/include_walk_driver

[[ -x $DRIVER ]] || { echo "build it first: make test-include-walk"; exit 1; }

FIX=$(mktemp -d)
trap 'rm -rf "$FIX"' EXIT
mkdir -p "$FIX/groups"

# the defect: a denylisted verb behind an include
printf 'flush ruleset\n' > "$FIX/groups/evil.nft"

# 4.6's documented pattern: included rules target the shared chain
printf 'add rule inet authnft filter ct state new tcp dport 22 accept\n' \
    > "$FIX/groups/good.nft"

# depth chain, bad verb only at the bottom
printf 'include "/etc/authnft/groups/d2.nft"\n' > "$FIX/groups/d1.nft"
printf 'include "/etc/authnft/groups/d3.nft"\n' > "$FIX/groups/d2.nft"
printf 'delete table inet authnft\n'            > "$FIX/groups/d3.nft"

# self-reference
printf 'include "/etc/authnft/groups/loop.nft"\n' > "$FIX/groups/loop.nft"

# permission failures
printf 'add rule inet authnft filter accept\n' > "$FIX/groups/worldwrite.nft"
printf 'add rule inet authnft filter accept\n' > "$FIX/groups/nonroot.nft"

chown -R 0:0 "$FIX"
chmod 644 "$FIX"/groups/*.nft
chmod 666 "$FIX/groups/worldwrite.nft"
chown 65534:65534 "$FIX/groups/nonroot.nft"

mkdir -p /etc/authnft
unshare -m --propagation private bash -c "
    mount --bind '$FIX' /etc/authnft
    '$DRIVER'
"
