#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Avinash H. Duduskar
#
# Union statement coverage across gcov contexts. Each test binary is its
# own gcov context (own gcda set, own executable-line view of a source),
# and the same source line counts as covered if ANY context executed it.
# Naive per-context percentages undercount for exactly the reason this
# project splits its suites: the validator binaries cover nft_validator
# while the main suite covers peer_lookup, and neither number alone is
# the suite's coverage.
#
# Usage: coverage-union.py <dir> [<dir>...]
#   Each dir is scanned recursively for *.gcov text files. Per source
#   file under src/, executable and executed line sets are unioned.
#   Prints a per-file table and the total; exits 1 if --min PCT is
#   given and the total falls below it.

import argparse
import glob
import os
import sys
from collections import defaultdict

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dirs', nargs='+')
    ap.add_argument('--min', type=float, default=None,
                    help='fail if total statement coverage is below this percent')
    args = ap.parse_args()

    executable = defaultdict(set)
    covered = defaultdict(set)

    gcovs = []
    for d in args.dirs:
        gcovs += glob.glob(os.path.join(d, '**', '*.gcov'), recursive=True)
    if not gcovs:
        print(f'coverage-union: no .gcov files under {args.dirs}', file=sys.stderr)
        return 1

    for path in gcovs:
        src = None
        lines = open(path, errors='replace').read().splitlines()
        for ln in lines:
            if ':Source:' in ln:
                src = ln.split(':Source:', 1)[1]
                break
        if src is None:
            continue
        # Normalise container paths like /build/src/foo.c to src/foo.c.
        idx = src.find('src/')
        if idx < 0 or not src.endswith('.c'):
            continue
        src = src[idx:]
        for ln in lines:
            parts = ln.split(':', 2)
            if len(parts) < 3:
                continue
            count, num = parts[0].strip(), parts[1].strip()
            if not num.isdigit() or int(num) == 0 or count == '-':
                continue
            executable[src].add(int(num))
            if count not in ('#####', '====='):
                covered[src].add(int(num))

    total = total_cov = 0
    for src in sorted(executable):
        n, c = len(executable[src]), len(covered[src])
        total += n
        total_cov += c
        print(f'{src:30} {c / n * 100:6.1f}%  ({c}/{n})')
    pct = total_cov / total * 100 if total else 0.0
    print(f'\nTOTAL statement coverage (union of {len(gcovs)} gcov files): '
          f'{pct:.1f}% ({total_cov}/{total})')
    if args.min is not None and pct < args.min:
        print(f'coverage-union: below the {args.min}% floor', file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
