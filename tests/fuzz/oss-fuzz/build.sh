#!/bin/bash -eu
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# OSS-Fuzz build script for pam_authnft.
#
# Environment variables provided by the OSS-Fuzz base-builder image:
#   CC, CXX        — compiler (clang); use $CC for all C compilation
#   CFLAGS         — sanitizer + fuzzer flags set by the build infrastructure
#   LIB_FUZZING_ENGINE — -fsanitize=fuzzer or equivalent
#   OUT            — destination for final fuzz-target binaries
#   SRC            — source root; pam_authnft is at $SRC/pam_authnft
#   WORK           — scratch space for build artefacts

cd "$SRC/pam_authnft"

COMMON="-Iinclude -D_GNU_SOURCE -DFUZZ_BUILD"
PKGCF="$(pkg-config --cflags libnftables libseccomp libsystemd pam libcap audit)"
PKGLD="$(pkg-config --libs   libnftables libseccomp libsystemd pam libcap audit)"

mkdir -p "$WORK/obj"

# Compile every source file with the OSS-Fuzz-supplied CFLAGS (which include
# the chosen sanitizer) and -DFUZZ_BUILD so validate_fragment_content is
# visible to the fuzz_fragment harness.
for f in src/*.c; do
    $CC $CFLAGS $COMMON $PKGCF \
        -fPIC -c "$f" -o "$WORK/obj/$(basename "${f%.c}").o"
done

# fuzz_username: exercises util_is_valid_username and util_normalize_ip.
# Both functions accept arbitrary strings with no I/O or PAM context.
$CC $CFLAGS $COMMON $PKGCF \
    tests/fuzz/fuzz_username.c "$WORK"/obj/*.o \
    $LIB_FUZZING_ENGINE $PKGLD \
    -o "$OUT/fuzz_username"

# fuzz_fragment: exercises validate_fragment_content (verb/include scanner).
# Uses memfd_create to present fuzz bytes as a file path without disk writes.
$CC $CFLAGS $COMMON $PKGCF \
    tests/fuzz/fuzz_fragment.c "$WORK"/obj/*.o \
    $LIB_FUZZING_ENGINE $PKGLD \
    -o "$OUT/fuzz_fragment"

# fuzz_substitute_placeholders: exercises substitute_placeholders, the
# token-aware @session_* expander with comment/quote state machine and
# malloc(src_len*2+1) sizing budget. Carries a property assertion on
# the output-length invariant (see tests/fuzz/fuzz_substitute_placeholders.c).
$CC $CFLAGS $COMMON $PKGCF \
    tests/fuzz/fuzz_substitute_placeholders.c "$WORK"/obj/*.o \
    $LIB_FUZZING_ENGINE $PKGLD \
    -o "$OUT/fuzz_substitute_placeholders"

# fuzz_netlink_diag: exercises peer_parse_diag_chunk, the
# NETLINK_SOCK_DIAG response walker (NLMSG_OK / inet_diag_msg cast).
# Highest attacker-reachable parser in the module — kernel-supplied
# bytes flow into hand-rolled length arithmetic.
$CC $CFLAGS $COMMON $PKGCF \
    tests/fuzz/fuzz_netlink_diag.c "$WORK"/obj/*.o \
    $LIB_FUZZING_ENGINE $PKGLD \
    -o "$OUT/fuzz_netlink_diag"

# fuzz_keyring_sanitize: printable-ASCII filter that scrubs a
# kernel-keyring payload before it lands in an nftables comment field.
$CC $CFLAGS $COMMON $PKGCF \
    tests/fuzz/fuzz_keyring_sanitize.c "$WORK"/obj/*.o \
    $LIB_FUZZING_ENGINE $PKGLD \
    -o "$OUT/fuzz_keyring_sanitize"

# fuzz_correlation_capture: AUTHNFT_CORRELATION PAM env sanitizer.
$CC $CFLAGS $COMMON $PKGCF \
    tests/fuzz/fuzz_correlation_capture.c "$WORK"/obj/*.o \
    $LIB_FUZZING_ENGINE $PKGLD \
    -o "$OUT/fuzz_correlation_capture"

# fuzz_cgroup_path: depth-invariant validator for cgroup paths returned
# by sd_pid_get_cgroup. Pure string parser; off-by-one bugs here either
# silently deny every authnft session or accept malformed paths.
$CC $CFLAGS $COMMON $PKGCF \
    tests/fuzz/fuzz_cgroup_path.c "$WORK"/obj/*.o \
    $LIB_FUZZING_ENGINE $PKGLD \
    -o "$OUT/fuzz_cgroup_path"

# fuzz_socket_inode: parse_socket_inode (regression guard for a thin
# sscanf wrapper used during /proc/<pid>/fd traversal).
$CC $CFLAGS $COMMON $PKGCF \
    tests/fuzz/fuzz_socket_inode.c "$WORK"/obj/*.o \
    $LIB_FUZZING_ENGINE $PKGLD \
    -o "$OUT/fuzz_socket_inode"
