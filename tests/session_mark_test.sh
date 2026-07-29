#!/bin/bash
# Namespace for tests/test_session_mark.c.
#
# session_mark_alloc uses a fixed path under /run/authnft, so the tests need
# that path to exist and must not touch the host's real counter: consuming
# ids there, or leaving the file at the exhaustion value, would affect live
# sessions. A private mount namespace with a tmpfs over /run/authnft gives
# the real path with throwaway contents.
#
# Needs root for the mount and nothing else.
set -euo pipefail

[[ $(id -u) -eq 0 ]] || { echo "needs root (tmpfs mount)"; exit 1; }

HERE=$(cd "$(dirname "$0")/.." && pwd)
BIN=$HERE/tests/test_session_mark

[[ -x $BIN ]] || { echo "build it first: make test-session-mark"; exit 1; }

mkdir -p /run/authnft
unshare -m --propagation private bash -c "
    mount -t tmpfs -o mode=0755 tmpfs /run/authnft
    '$BIN'
"
