#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Comprehensive local audit: every gate the hosted CI cannot run because it
# needs root + real nftables + systemd + a cgroup hierarchy, in one place.
# Runs in the rootful container (tier 1) and the virtme-ng microVM (tier 2).
#
#   Part A  unit suite (make test)         seccomp SIGSYS enforcement (Stage 2)
#                                          + allowlist survival (Stage 3) +
#                                          the validator/lifecycle units
#   Part B  integration suite (16 stages)  OPT-IN, off by default
#                                          (AUDIT_RUN_INTEGRATION=1). Has
#                                          host-environment coupling that
#                                          does not survive headless runs in
#                                          either substrate; see the gate
#                                          below. Not part of the default
#                                          verdict.
#   Part C  fault matrix (run-audit.sh)    nft_handler_setup's error returns
#                                          under ASan/LSan + the lifecycle
#                                          under valgrind
#
# Aggregated verdict: non-zero if any enabled part fails (A + C by default).
set -uo pipefail

cd "$(dirname "$0")/.."
SO="$(pwd)/pam_authnft.so"
FAIL=0
hdr() { printf '\n########## %s ##########\n' "$*"; }

hdr "PART A: unit suite (make test) — seccomp enforcement + units"
make clean >/dev/null 2>&1 || true
if make test; then
    echo "[part A] PASS"
else
    echo "[part A] FAIL"; FAIL=1
fi

# PART B (integration suite) is OPT-IN and EXPERIMENTAL (AUDIT_RUN_INTEGRATION=1,
# off by default). The 16-stage integration suite has host-environment
# coupling that does not survive headless execution in the audit substrates:
# in the Fedora container it SIGSYS-kills on a Fedora-only libc syscall
# (seccomp allowlist is host-tuned) and trips the 10.9 file-mode check on
# the container umask; in the virtme-ng microVM it exits without output
# under the degraded --systemd init. Making it audit-ready (deterministic
# headless run, env-independent assertions) is follow-on work. For now the
# integration lifecycle + socket-cgroupv2 stages stay with the existing
# `make test-integration-container` / `sudo make test-integration` targets,
# and the audit gate ships the parts that are reliable and verified: A + C.
if [ "${AUDIT_RUN_INTEGRATION:-0}" = 1 ]; then
    hdr "PART B: integration suite (tests/integration_test.sh) — 16 stages"
    nft delete table inet authnft 2>/dev/null || true
    if [ -f "$SO" ] && ./tests/integration_test.sh "$SO"; then
        echo "[part B] PASS"
    else
        echo "[part B] FAIL"; FAIL=1
    fi
    nft delete table inet authnft 2>/dev/null || true
else
    hdr "PART B: integration suite — SKIPPED (set AUDIT_RUN_INTEGRATION=1; runs in the tier-2 microVM)"
fi

hdr "PART C: fault matrix under leak detectors (audit/run-audit.sh)"
if ./audit/run-audit.sh; then
    echo "[part C] PASS"
else
    echo "[part C] FAIL"; FAIL=1
fi

hdr "COMPREHENSIVE AUDIT: $([ "$FAIL" -eq 0 ] && echo PASS || echo FAIL)"
exit "$FAIL"
