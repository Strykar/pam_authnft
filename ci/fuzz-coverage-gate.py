#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Deterministic per-function fuzz-coverage gate. Enforces the >=90% region
# bar that docs/FUZZ_SURFACE.md documents for the fuzzed functions, so a
# change that drops a fuzzed function below the bar fails CI instead of
# silently regressing the row.
#
# Determinism: coverage is measured by replaying ONLY the committed corpus
# (`-runs=0`), never by a timed fuzz run, so the number does not depend on a
# lucky mutation. Keeping the committed seed/regression corpus rich enough to
# hold the bar is the maintenance contract.
#
# Exclusions: stock llvm-cov does not honor LLVM_COV_EXCL_* comment markers,
# so this gate honors them itself — regions whose start line falls inside a
# `LLVM_COV_EXCL_START`..`LLVM_COV_EXCL_STOP` block are dropped from the
# per-function count. Used only for provably-unreachable defensive branches
# (see the substitute_placeholders ratio guards in src/nft_validator.c).
import json, subprocess, glob, os, sys

THRESHOLD = 90.0
COV = "fuzz/coverage"
# The fuzzed functions the FUZZ_SURFACE status legend applies to.
TARGETS = {
    "util_is_valid_username", "util_normalize_ip", "validate_cgroup_path",
    "validate_fragment_buf", "validate_fragment_content",
    "substitute_placeholders", "peer_parse_diag_chunk", "parse_socket_inode",
    "keyring_sanitize", "corr_sanitize_copy",
}


def excl_ranges():
    """Map abspath -> [(start_line, stop_line), ...] from EXCL markers."""
    out = {}
    for f in glob.glob("src/*.c"):
        ranges, start = [], None
        with open(f, encoding="utf-8") as fp:
            for i, line in enumerate(fp, 1):
                if "LLVM_COV_EXCL_START" in line:
                    start = i
                elif "LLVM_COV_EXCL_STOP" in line and start is not None:
                    ranges.append((start, i)); start = None
        if ranges:
            out[os.path.abspath(f)] = ranges
    return out


LIBS = "libnftables libseccomp libsystemd pam libcap audit".split()
COV_CFLAGS = ("-g -O1 -Iinclude -D_GNU_SOURCE -DFUZZ_BUILD -fsanitize=address "
              "-fno-omit-frame-pointer -fprofile-instr-generate "
              "-fcoverage-mapping").split()


def build_harnesses():
    """Compile the coverage-instrumented fuzz harnesses. Kept in step with the
    fuzz-coverage recipe in the Makefile (same flags), but self-contained so
    the gate needs no timed fuzz run or HTML regeneration."""
    pkgc = subprocess.check_output(["pkg-config", "--cflags"] + LIBS).decode().split()
    pkgl = subprocess.check_output(["pkg-config", "--libs"] + LIBS).decode().split()
    os.makedirs(f"{COV}/obj", exist_ok=True)
    objs = []
    for src in sorted(glob.glob("src/*.c")):
        obj = f"{COV}/obj/{os.path.basename(src)[:-2]}.o"
        subprocess.run(["clang"] + COV_CFLAGS + pkgc + ["-c", src, "-o", obj], check=True)
        objs.append(obj)
    for hsrc in sorted(glob.glob("fuzz/fuzz_*.c")):
        out = f"{COV}/{os.path.basename(hsrc)[:-2]}"
        subprocess.run(["clang"] + COV_CFLAGS + ["-fsanitize=fuzzer"] + pkgc
                       + [hsrc] + objs + pkgl + ["-o", out], check=True)


def main():
    build_harnesses()
    bins = sorted(b for b in glob.glob(f"{COV}/fuzz_*") if os.access(b, os.X_OK))
    if not bins:
        sys.exit(f"no coverage harnesses in {COV}/")

    for f in glob.glob(f"{COV}/gate-*.profraw"):
        os.remove(f)
    for b in bins:
        h = os.path.basename(b)
        corpus = f"fuzz/corpus/{h[len('fuzz_'):]}"
        cmd = [b, "-runs=0"] + ([corpus] if os.path.isdir(corpus) else [])
        subprocess.run(cmd, env={**os.environ, "LLVM_PROFILE_FILE": f"{COV}/gate-{h}.profraw"},
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    prof = f"{COV}/gate.profdata"
    subprocess.run(f"llvm-profdata merge -sparse {COV}/gate-*.profraw -o {prof}",
                   shell=True, check=True)
    data = json.loads(subprocess.check_output(
        ["llvm-cov", "export", bins[0], "-instr-profile", prof] + glob.glob("src/*.c")))

    excl = excl_ranges()

    def excluded(path, line):
        return any(a <= line <= b for a, b in excl.get(path, []))

    results = {}
    for fdata in data["data"]:
        for fn in fdata["functions"]:
            if fn["name"] not in TARGETS:
                continue
            path = fn["filenames"][0]
            total = covered = 0
            for r in fn["regions"]:
                line_start, _, _, _, count, _, _, kind = r
                if kind != 0 or excluded(path, line_start):   # kind 0 == CodeRegion
                    continue
                total += 1
                covered += 1 if count > 0 else 0
            results[fn["name"]] = (100.0 * covered / total) if total else 0.0

    missing = TARGETS - set(results)
    failed = False
    print(f"per-function region coverage (corpus-only), bar = {THRESHOLD:.0f}%")
    for name in sorted(results):
        pct = results[name]
        ok = pct >= THRESHOLD
        failed |= not ok
        print(f"  {'OK  ' if ok else 'FAIL'} {name:28s} {pct:6.2f}%")
    for name in sorted(missing):
        failed = True
        print(f"  FAIL {name:28s} not found in coverage export")
    if failed:
        sys.exit("fuzz-coverage gate: a fuzzed function is below the bar")
    print("fuzz-coverage gate: all fuzzed functions meet the bar")


if __name__ == "__main__":
    main()
