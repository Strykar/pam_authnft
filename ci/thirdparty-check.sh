#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# THIRD_PARTY.md drift gate. Dependabot watches only the github-actions
# ecosystem; the C libraries the .so links against are inventoried by hand in
# docs/THIRD_PARTY.md (min versions and CVE feeds are curated, not mechanically
# derivable). This does the one part that IS mechanical: assert that every
# library the shipped .so actually links (DT_NEEDED) has an entry in the doc,
# so a new dependency cannot be added without updating the inventory. It does
# NOT check versions or feeds — those stay a manual review.
set -euo pipefail
cd "$(dirname "$0")/.."

SO=pam_authnft.so
DOC=docs/THIRD_PARTY.md
[ -f "$SO" ] || make all >/dev/null

# Sonames the toolchain and libc always pull in; not project dependencies.
BASELINE='^(libc|ld-linux.*|libgcc_s|libm|libpthread|libdl|librt)(\.|$)'

fail=0
while read -r lib; do
    [ -z "$lib" ] && continue
    echo "$lib" | grep -qE "$BASELINE" && continue
    base=$(echo "$lib" | sed -E 's/^lib//; s/\.so.*//')   # libnftables.so.1 -> nftables
    if grep -qiE "(lib)?${base}[^a-z]" "$DOC"; then
        printf '  ok    %-20s documented\n' "$lib"
    else
        printf '  DRIFT %-20s linked but absent from %s\n' "$lib" "$DOC"
        fail=1
    fi
done < <(readelf -d "$SO" | awk -F'[][]' '/NEEDED/{print $2}')

if [ "$fail" -eq 0 ]; then
    echo "THIRD_PARTY.md covers every linked library."
else
    echo "THIRD_PARTY.md is missing a linked library above; add it (version floor + CVE feed)."
fi
exit "$fail"
