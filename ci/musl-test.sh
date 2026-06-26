#!/bin/sh
# musl (Alpine) build + unit-suite tier.
#
# The seccomp allowlist in src/sandbox.c was derived from glibc syscall traces.
# musl routes several libc operations through different syscalls (open(2) vs
# openat, readv/writev vs read/write), so a glibc-only CI cannot catch an
# allowlist gap that would SIGSYS-kill a session on a musl host. This tier
# builds pam_authnft against musl and runs the unit suite, whose Stage 13
# exercises the setup-path syscall classes under the sandbox.
#
# Uses apk inside a throwaway Alpine container — a separate package ecosystem
# from the host's pacman. Run: ci/musl-test.sh [repo-dir]
set -e
REPO="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
IMG="${MUSL_IMAGE:-docker.io/library/alpine:3.21}"

exec "${CONTAINER_ENGINE:-podman}" run --rm \
    --cap-add=NET_ADMIN --security-opt seccomp=unconfined \
    -v "$REPO:/src:ro" "$IMG" sh -c '
    set -e
    apk add --no-cache build-base pkgconf nftables-dev libseccomp-dev \
        linux-pam-dev libcap-dev audit-dev elogind-dev >/dev/null
    cp -a /src /build && cd /build && make clean >/dev/null
    make authnft_test >/dev/null
    echo "=== musl unit suite ==="
    ./authnft_test
'
