#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Python re-implementation of pam_authnft's small parsers, used as a
# differential-testing oracle. Reads one input per stdin line, emits
# one result line in the same format as tests/oracle/oracle_runner.c.
#
# DO NOT make this a verbatim port of the C — the whole point of a
# differential oracle is that the two implementations are written
# independently from the spec, so a bug in one is unlikely to be a
# bug in the other. Rules of thumb here:
#   - prefer Python stdlib primitives (re, ipaddress) over hand-rolling
#   - match C semantics exactly for input acceptance/rejection
#   - match C output verbatim where C preserves the input (don't
#     canonicalize), but use Python's parsers as the truth for
#     branch decisions

import ipaddress
import re
import sys

# pam_authnft constants — kept in sync with include/authnft.h. If
# they drift, the oracle harness will start disagreeing with C.
MAX_USER_LEN = 32
IP_STR_MAX = 64
CGROUP_PATH_MAX = 192
CLAIMS_TAG_MAX = 192
CORRELATION_ID_MAX = 64
USERNAME_RE = re.compile(r"\A[A-Za-z0-9._-]+\Z")

# keyring_sanitize allowlist (mirrors is_safe() in src/keyring.c).
# Anything outside this set is replaced with '_'. Output ends up in
# nftables comment fields, so quotes / backslashes / control chars
# must never make it through.
KEYRING_SAFE = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "_=,.:;/-"
)

# corr_sanitize_copy allowlist (mirrors is_corr_safe() in src/event.c).
# Narrower than the keyring tag class — these are opaque IDs, not
# human-readable labels, so no ';', '/', ',' etc.
CORR_SAFE = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "_-.:"
)


def is_valid_username(u: str) -> int:
    """Mirrors util_is_valid_username (src/pam_entry.c)."""
    if not u:
        return 0
    if len(u) > MAX_USER_LEN:
        return 0
    if u[0] == "-" or u[0] == ".":
        return 0
    return 1 if USERNAME_RE.fullmatch(u) else 0


def normalize_ip(s: str):
    """Mirrors util_normalize_ip. Returns the normalized string on
    success, None on rejection. Preserves input form for non-mapped
    addresses; extracts canonical IPv4 from IPv6 v4-mapped addresses
    (::ffff:a.b.c.d -> a.b.c.d)."""
    if not s:
        return None

    pct = s.find("%")
    core = s[:pct] if pct >= 0 else s
    if not core or len(core) >= IP_STR_MAX:
        return None

    # Try IPv4 first — this matches the C ordering (inet_pton AF_INET
    # then AF_INET6). Python's ipaddress doesn't have a "try ipv4
    # only" mode, but ipv4 addresses also parse as ipv4.
    try:
        ipaddress.IPv4Address(core)
        # IPv4 path: return the input form verbatim (no canonicalization).
        return core
    except ValueError:
        pass

    try:
        a6 = ipaddress.IPv6Address(core)
        # v4-mapped v6: extract IPv4 in canonical form.
        if a6.ipv4_mapped is not None:
            return str(a6.ipv4_mapped)
        # Other IPv6: return input form verbatim.
        return core
    except ValueError:
        return None


def validate_cgroup_path(s: str):
    """Mirrors validate_cgroup_path (src/bus_handler.c).

    Returns the leading-slash-stripped path on accept, or None on
    reject. A valid path is exactly `/authnft.slice/<name>.scope`
    with no further slashes in `<name>`.
    """
    if not s or not s.startswith("/"):
        return None
    p = s[1:]
    slash = p.find("/")
    if slash < 0:
        return None
    first, second = p[:slash], p[slash + 1:]
    if first != "authnft.slice":
        return None
    if not second:
        return None
    if "/" in second:
        return None
    if len(second) < 7 or not second.endswith(".scope"):
        return None
    if len(p) >= CGROUP_PATH_MAX:
        return None
    return p


def keyring_sanitize(in_bytes: bytes) -> bytes:
    """Mirrors keyring_sanitize (src/keyring.c).

    Bytes outside KEYRING_SAFE become '_'. Output is clamped to
    CLAIMS_TAG_MAX. Stops at the first NUL.
    """
    out = bytearray()
    for b in in_bytes:
        if len(out) >= CLAIMS_TAG_MAX:
            break
        if b == 0:
            break
        ch = chr(b)
        out.append(b if ch in KEYRING_SAFE else ord("_"))
    return bytes(out)


def corr_sanitize_copy(s: str) -> str:
    """Mirrors corr_sanitize_copy (src/event.c).

    Bytes outside CORR_SAFE are DROPPED (not substituted). Output
    is clamped to CORRELATION_ID_MAX - 1 chars + NUL.
    """
    out = []
    cap = CORRELATION_ID_MAX - 1  # leave room for NUL
    for c in s:
        if len(out) >= cap:
            break
        if c in CORR_SAFE:
            out.append(c)
    return "".join(out)


def emit_username():
    for line in sys.stdin:
        line = line.rstrip("\n")
        sys.stdout.write(f"{is_valid_username(line)}\n")


def emit_normalize_ip():
    for line in sys.stdin:
        line = line.rstrip("\n")
        result = normalize_ip(line)
        if result is None:
            sys.stdout.write("0|\n")
        else:
            sys.stdout.write(f"1|{result}\n")


def emit_cgroup_path():
    for line in sys.stdin:
        line = line.rstrip("\n")
        result = validate_cgroup_path(line)
        if result is None:
            sys.stdout.write("-1|\n")
        else:
            sys.stdout.write(f"0|{result}\n")


def emit_keyring_sanitize():
    # Read raw bytes so embedded high-bit characters round-trip.
    for line in sys.stdin.buffer:
        # Strip trailing '\n' but keep everything before it.
        if line.endswith(b"\n"):
            line = line[:-1]
        out = keyring_sanitize(line)
        sys.stdout.buffer.write(f"{len(out)}|".encode("utf-8"))
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.write(b"\n")


def emit_correlation_capture():
    for line in sys.stdin:
        line = line.rstrip("\n")
        out = corr_sanitize_copy(line)
        sys.stdout.write(f"{len(out)}|{out}\n")


def main():
    if len(sys.argv) < 2:
        sys.stderr.write(
            f"usage: {sys.argv[0]} {{username|normalize_ip|cgroup_path|"
            f"keyring_sanitize|correlation_capture}}\n"
        )
        sys.exit(2)
    fn = sys.argv[1]
    dispatchers = {
        "username":            emit_username,
        "normalize_ip":        emit_normalize_ip,
        "cgroup_path":         emit_cgroup_path,
        "keyring_sanitize":    emit_keyring_sanitize,
        "correlation_capture": emit_correlation_capture,
    }
    if fn not in dispatchers:
        sys.stderr.write(f"unknown function: {fn}\n")
        sys.exit(2)
    dispatchers[fn]()


if __name__ == "__main__":
    main()
