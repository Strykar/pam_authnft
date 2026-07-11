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

# Read DT_NEEDED up front. Under `set -o pipefail`, a readelf failure (tool
# missing, unreadable/malformed .so) fails this assignment and aborts the
# gate. The previous `done < <(readelf ...)` process substitution swallowed
# that failure and fed an empty loop, which passed vacuously.
needed=$(readelf -d "$SO" | awk -F'[][]' '/NEEDED/{print $2}')
[ -n "$needed" ] || {
    echo "no DT_NEEDED entries in $SO — readelf failed or the .so is malformed" >&2
    exit 1
}

while read -r lib; do
    [ -z "$lib" ] && continue
    echo "$lib" | grep -qE "$BASELINE" && continue
    # Require an inventory ROW, not a prose mention: the soname stem
    # (libnftables.so.1 -> libnftables) must appear, word-bounded, on a table
    # row (line starting with '|'). Deleting the row removes the only match so
    # the gate fails; a stray mention in a sentence (which never starts with
    # '|') no longer satisfies it.
    stem=$(echo "$lib" | sed -E 's/\.so.*//')             # libnftables.so.1 -> libnftables
    if grep -qE "^\|.*[^a-zA-Z]${stem}([^a-zA-Z]|\$)" "$DOC"; then
        printf '  ok    %-20s documented\n' "$lib"
    else
        printf '  DRIFT %-20s linked but absent from %s\n' "$lib" "$DOC"
        fail=1
    fi
done <<< "$needed"

if [ "$fail" -eq 0 ]; then
    echo "THIRD_PARTY.md covers every linked library."
else
    echo "THIRD_PARTY.md is missing a linked library above; add it (version floor + CVE feed)."
fi
exit "$fail"
