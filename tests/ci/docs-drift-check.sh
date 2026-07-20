#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Docs-drift gate. Docs rot in ways that are mechanically detectable, and this
# project has now shipped that rot twice: a README that told operators to
# uncomment systemd sandboxing that a .slice silently ignores, and a whole CI
# tier (audit-vm / vng-audit.sh) deleted while the docs still referenced it.
# Both were greppable. So: grep, in CI.
#
# This does NOT check whether prose is *true* — only that it does not point at
# things which no longer exist. Behavioural claims still need a human or a test.
# The point is to stop the cheap failures cheaply.
#
# It is deliberately quiet: a gate that cries wolf gets ignored, which is worse
# than no gate. Hence the narrow matching (code spans only for `make`, known
# extensions only for links) and the archival exclusions below.
#
# Checks:
#   1. `make <target>` in a doc must be a real Makefile target.
#   2. In-tree paths named in a doc must exist.
#   3. Relative markdown links must resolve.
set -uo pipefail
cd "$(dirname "$0")/../.."

fail=0
note() { printf '  %-6s %s\n' "$1" "$2"; }

# Living docs. The investigation records are snapshots of a moment — they cite
# throwaway branches and temporary workflows on purpose, and rewriting them to
# match today's tree would destroy the evidence they exist to preserve. They are
# excluded, not exempt: if one is ever promoted to a living doc, drop it here.
ARCHIVAL='docs/MUTATION_ASAN_EXPERIMENT.md|docs/MUTATION_ASAN_INVESTIGATION_2.md|docs/NFT_VALIDATOR_SURVIVOR_AUDIT.md'

DOCS=()
for f in README.md SECURITY.md .github/CODE_OF_CONDUCT.md; do [ -f "$f" ] && DOCS+=("$f"); done
while IFS= read -r f; do
    [[ "$f" =~ ^($ARCHIVAL)$ ]] && continue
    DOCS+=("$f")
done < <(git ls-files 'docs/*.md' 'docs/*.txt')

# Strip trailing sentence punctuation a prose writer leaves on a path.
strip_punct() { sed -E 's/[.,;:)]+$//'; }

# --- 1. `make <target>` must resolve --------------------------------------
# Only inside code spans/blocks. Bare prose is a minefield: the README quotes a
# kernel commit titled "make cgroup match work in input too", which is not a
# request to run `make cgroup`.
mapfile -t REAL_TARGETS < <(
    { grep -oE '^[a-zA-Z][a-zA-Z0-9_-]*:' Makefile | tr -d ':'
      sed -n '/^\.PHONY:/,/[^\\]$/p' Makefile | tr ' \\' '\n\n' \
        | grep -E '^[a-zA-Z][a-zA-Z0-9_-]+$' | grep -v '^\.PHONY'
    } | sort -u
)
is_target() { local t; for t in "${REAL_TARGETS[@]}"; do [ "$t" = "$1" ] && return 0; done; return 1; }

echo "== make targets referenced in docs =="
for f in "${DOCS[@]}"; do
    # code spans: `make foo` ; fenced blocks: lines beginning (sudo) make foo
    { grep -oE '`(sudo +)?make +[a-z][a-z0-9_-]*`' "$f" | tr -d '`'
      grep -oE '^[[:space:]]*(sudo +)?make +[a-z][a-z0-9_-]*' "$f"
    } 2>/dev/null | sed -E 's/.*make +//' | sort -u | while read -r t; do
        [ -n "$t" ] || continue
        if ! is_target "$t"; then
            note DRIFT "$f references 'make $t' — no such target"
            echo x >> /tmp/.docsdrift.$$
        fi
    done
done

# --- 2. in-tree paths must exist ------------------------------------------
echo "== in-tree paths referenced in docs =="
PATH_RE='(\.github/workflows/[A-Za-z0-9_.-]+\.yml|tests/[A-Za-z0-9_./-]+\.(sh|py|c|so)|src/[A-Za-z0-9_.-]+\.(c|map)|include/[A-Za-z0-9_.-]+\.h|data/[A-Za-z0-9_.-]+)'
for f in "${DOCS[@]}"; do
    for p in $(grep -oE "$PATH_RE" "$f" | strip_punct | sort -u); do
        # A .so is a BUILD ARTIFACT, absent from a clean checkout. Docs name
        # them (audit/malloc_fail.so is LD_PRELOADed by name), so check that the
        # SOURCE that produces it exists instead. Checking for the .so itself
        # passes only on a dirty tree that happens to have been built — which is
        # precisely how this gate first shipped green locally and red in CI.
        case "$p" in
            *.so) [ -e "${p%.so}.c" ] && continue
                  note DRIFT "$f references '$p' — no ${p%.so}.c to build it from"
                  echo x >> /tmp/.docsdrift.$$
                  continue ;;
        esac
        [ -e "$p" ] && continue
        note DRIFT "$f references '$p' — no such file"
        echo x >> /tmp/.docsdrift.$$
    done
done

# --- 3. relative markdown links must resolve ------------------------------
# Only links that name a file we can check. `../../actions/runs/N` and
# `../../../pull/47` are GitHub-relative UI links, valid in the rendered page
# and meaningless on disk — skip anything without a known extension.
echo "== relative links in markdown =="
for f in "${DOCS[@]}"; do
    [[ "$f" == *.md ]] || continue
    base="$(dirname "$f")"
    for l in $(grep -oE '\]\([^)]+\.(md|txt|c|h|sh|py|svg|yml)\)' "$f" \
               | sed -E 's/^\]\(//; s/\)$//; s/#.*$//' | sort -u); do
        case "$l" in http*|mailto:*) continue ;; esac
        [ -e "$l" ] || [ -e "$base/$l" ] && continue
        note DEAD "$f -> $l"
        echo x >> /tmp/.docsdrift.$$
    done
done

[ -s /tmp/.docsdrift.$$ ] && fail=1
rm -f /tmp/.docsdrift.$$

echo
if [ "$fail" -eq 0 ]; then
    echo "docs-drift: docs reference nothing that has been deleted."
else
    echo "docs-drift: a doc points at something that no longer exists (above)."
fi
exit "$fail"
