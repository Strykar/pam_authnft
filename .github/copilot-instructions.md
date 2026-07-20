# Code review instructions for pam_authnft

pam_authnft is a root-privileged PAM session module that binds per-session
nftables rules to a systemd transient scope (cgroupv2). It runs inside
sshd's privsep monitor. Review with that threat model in mind.

## What to prioritize

- Memory safety in `src/*.c`: buffer bounds, integer overflow in size
  arithmetic, use-after-free, leaks on error returns. Every parser of
  attacker-influenced bytes (usernames, PAM_RHOST, cgroup paths, netlink
  responses, keyring payloads) is security-critical.
- Fail-closed semantics: a failed session setup must return a PAM error
  and roll back all state (nft chain/sets, transient scope, session file).
  Flag any path that can fail open or leak state.
- Injection: user-controlled strings reaching nft command buffers or shell
  contexts. The fragment validator (`src/nft_validator.c`) is the gate;
  changes there deserve the deepest scrutiny.
- Sandbox boundaries: the setup child applies a seccomp allowlist
  (`src/sandbox.c`). New libc calls in the child's path can SIGSYS-kill
  the session on some libcs (glibc vs musl route different syscalls).
- Test validity: would the test actually fail if the guarded behavior
  broke? Vacuous assertions and tests that pass without exercising the
  claim are bugs.

## Project conventions (do not flag)

- C style is kernel-ish: tabs, K&R braces, `goto` cleanup labels,
  `snake_case`. SPDX `GPL-2.0-or-later` headers on every file.
- Comments are sparse and explain why, not what.
- Bash tests use `set -euo pipefail`, explicit `[PASS]`/`[FAIL]` output,
  and cleanup traps; scaffolding follows `tests/integration_test.sh`.
- Defensive branches that are provably unreachable under fuzzing are
  marked `LLVM_COV_EXCL_START/STOP` and excluded by
  `tests/ci/fuzz-coverage-gate.py`; the markers are intentional, not dead code
  to delete.

## CI context

Workflows are hash-pinned and least-privilege (`permissions: contents:
read`). The fuzz-coverage gate replays only the committed corpus; corpus
files under `tests/fuzz/corpus/*/seed_*` are deterministic fixtures, not noise.
`tests/packet_match_headless.sh` (via `make test-packet-match`) is how an
admin verifies their kernel really matches `socket cgroupv2` on INPUT; it is
run by hand on the target host, not in CI.
