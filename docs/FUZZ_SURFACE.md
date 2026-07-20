# Fuzz coverage surface

Single source of truth for what's fuzzed in pam_authnft and what isn't.
Every parser, sanitizer, and byte-handler in the codebase appears here.
Update on every harness addition or non-trivial source change.

This document is deliberately blunt about gaps. A green checkmark is
earned, not assumed.

---

## Status legend

| Mark | Meaning |
|---|---|
| ✅ | Harness exists, property assertions in place, run by CIFuzz on every PR |
| 🟡 | Harness exists but lacks property assertions, OR `make fuzz-coverage` shows the harness reaches < 90% of the targeted function |
| 🟠 | Function is `static` and needs the `#ifndef FUZZ_BUILD / static / #endif` guard before a harness can target it directly |
| ❌ | No harness. Listed with priority (High/Med/Low) by attacker reachability |

Property assertions matter. Without them, a harness only catches crashes;
with them, it catches behavior outside spec, which is where the real
bugs hide.

---

## Inventory

### Direct attacker-controlled inputs

| Function | Source | Trust | Status | Harness | Notes |
|---|---|---|---|---|---|
| `util_is_valid_username` | `PAM_USER` (sshd) | hostile | ✅ | `fuzz_username` | 100% region / line, 95% branch. Pure crash-only harness; adequate given the simple validator semantics |
| `util_normalize_ip` | `PAM_RHOST` (sshd, possibly via DNS or proxy) | hostile | ✅ | `fuzz_username` (combined) | 93.02% region, 96.15% line, 91.30% branch. Seed corpus covers v4-mapped / IPv4 / IPv6 / zone-suffix paths; harness explicitly calls with NULL/zero-size args to cover the early-out guards. Defensive `inet_ntop` failure on v4-mapped extraction (line 72) is unreachable by design — IP_STR_MAX is always large enough for an IPv4 literal |

### Kernel-supplied bytes

| Function | Source | Trust | Status | Harness | Notes |
|---|---|---|---|---|---|
| `peer_parse_diag_chunk` (extracted from `peer_lookup_tcp`) | `NETLINK_SOCK_DIAG` reply | semi-hostile (any CAP_NET_ADMIN process) | ✅ | `fuzz_netlink_diag` | 100% region / 100% line, 95.65% branch. Hand-rolled walk over `nlmsghdr` headers + `inet_diag_msg` cast. **Found a heap-buffer-overflow on first run** — see "Bugs found" |
| `parse_socket_inode` (extracted from `collect_socket_inodes`) | `/proc/<pid>/fd/N` symlink | trusted | ✅ | `fuzz_socket_inode` | 100% region / line / branch. Thin sscanf wrapper; harness exists as a regression guard for any future hand-rolled replacement |
| `keyring_sanitize` (extracted from `keyring_read_serial`) | `keyctl(KEYCTL_READ)` payload | semi-trusted (producer trusted, consumer must defend) | ✅ | `fuzz_keyring_sanitize` | 100% region / line / branch. Property assertions on output character class, length cap, NUL termination |
| `validate_cgroup_path` (extracted from `util_get_cgroup_path`) | `sd_pid_get_cgroup` return | trusted | ✅ | `fuzz_cgroup_path` | 95.45% region / 100% line / 100% branch. **Found a latent bug by inspection** during refactor — see "Bugs found" |

### Admin-controlled inputs (root-owned files / PAM env)

| Function | Source | Trust | Status | Harness | Notes |
|---|---|---|---|---|---|
| `validate_fragment_content` | `/etc/authnft/users/<user>` | admin | ✅ | `fuzz_fragment` | 100% region / line / branch. Seed corpus covers all rejection paths (relative include, outside-/etc/authnft/, glob characters); harness exercises both the memfd success path and a forced fopen-failure path |
| `substitute_placeholders` | fragment content after validation | admin | ✅ | `fuzz_substitute_placeholders` | State machine + malloc sizing; sizing-invariant property assertion. **Found two heap-buffer-overflow bugs on first run** — see "Bugs found" below |
| `read_file` size cap | fragment file size | admin | ❌ Low | — | Trivially correct (`fseek` + `ftell` + bound check); no harness planned |
| `corr_sanitize_copy` (extracted from `event_correlation_capture`) | PAM env `AUTHNFT_CORRELATION` | semi-trusted (upstream PAM module) | ✅ | `fuzz_correlation_capture` | 100% region / line / branch. Drops bytes outside the journal-field-safe character class |
| PAM module arg parser (`rhost_policy=…`, `claims_env=…`) | PAM config | admin | ❌ Low | — | Tiny |

### Composed nft command stream

| Function | Source | Trust | Status | Harness | Notes |
|---|---|---|---|---|---|
| `nft_handler_setup` `snprintf` chain | composed from validated user/IP/cg_path/scope_unit | n/a (composed) | ❌ Med | — | Injection / truncation risk if composer trusts inputs incorrectly |
| nft handle parser (echo output → `uint64_t`) | libnftables echo buffer | trusted | ❌ Low | — | |

### Out of scope

- libnftables internals — their fuzz farm
- libsystemd internals — their fuzz farm
- libpam internals — their fuzz farm
- Seccomp filter itself — static config, not a parser
- Session JSON emitter — composed from validated input, output-only
- nftables fragment after `include` resolution — libnftables's responsibility once validated

---

## What fuzz cannot find here

Honest disclosure. These bug classes will not surface from any harness
in this document, regardless of duration:

- **Kernel/protocol semantic bugs.** K1 (wrong nft expression family on
  cgroupv2), K2 (delete-by-path race after scope reap), K10 (Class A/B
  socket-scope semantic gap). These are kernel-API-contract bugs.
  Defense: kernel-feature audit, integration tests that exercise the
  actual semantics, K-numbered findings tracked in HANDOFF.
- **Distributed/multi-host bugs.** N/A while pam_authnft is per-host.
- **Cgroupfs TOCTOU races.** K2 lives here. Best caught by
  crash-and-recover integration tests, not unit fuzz.
- **PAM stack ordering bugs across distros.** Caught by integration
  tests on each distro target.
- **Logic bugs that don't violate stated invariants.** A function that
  returns wrong-but-plausible answers will pass property-assertion
  fuzz forever. Defense: differential testing against an oracle —
  see "Differential oracles" below.

---

## Differential oracles

Every parser whose semantics can be re-implemented in Python with
stdlib primitives gets a second implementation under
`tests/oracle/oracle.py`. The C runner at
`tests/oracle/oracle_runner.c` reads inputs from stdin, calls the C
function, and prints results in a parser-agnostic format. The Python
oracle reads the same inputs and prints results in the same format.
`tests/oracle/run.sh` (driven by `make test-oracle`, also wired into
`make test`) feeds a curated input set through both and diffs.

Disagreement = logic bug. The two implementations are written
independently from the spec — a bug in one is unlikely to be the
same bug in the other.

### Oracle status

| Function | Oracle | Inputs | Status |
|---|---|---|---|
| `util_is_valid_username` | regex on `[A-Za-z0-9._-]` + length cap | 48 | ✅ |
| `util_normalize_ip` | `ipaddress` module + verbatim-form preservation | 88 | ✅ |
| `validate_cgroup_path` | depth-invariant path parser (split + suffix check) | 43 | ✅ |
| `keyring_sanitize` | bytewise filter against `[A-Za-z0-9_=,.:;/-]`; `_` substitution; `CLAIMS_TAG_MAX` cap; NUL terminates | 59 | ✅ |
| `corr_sanitize_copy` | charwise filter against `[A-Za-z0-9_-.:]`; drop (not substitute); `CORRELATION_ID_MAX-1` cap | 48 | ✅ |

### What this catches that fuzz does not

- Wrong-but-plausible accept/reject decisions on edge inputs that
  don't trigger memory-safety errors.
- Algorithmic divergences between parsers (e.g., `inet_pton` vs
  Python's `ipaddress` module): if either accepts a form the other
  rejects, the oracle flags it.
- Forms preserved verbatim by C but normalized by Python (or
  vice-versa) — caught when the oracle's verbatim-preservation
  policy disagrees with C's actual behavior.

### Property-based extension (Phase 4.2)

`tests/oracle/properties.py` runs after the differential pass and
checks **per-function invariants** on both implementations:

| Function | Property |
|---|---|
| `util_normalize_ip` | idempotence — `f(f(x).out) == f(x).out` |
| `validate_cgroup_path` | round-trip — re-prefixing the leading-slash-stripped output makes the function accept and produce the same output |
| `keyring_sanitize` | idempotence — sanitizing already-sanitized output is a no-op |
| `corr_sanitize_copy` | idempotence |

The property tests run separately on C and on Python (8
function × runner pairs total). Where the differential oracle
catches "C and Python disagree on a single input", the property
tests catch "the function disagrees with itself" — a canonical
form that drifts on re-application, or output that the function
rejects when fed back as input.

Both pass cleanly on the current 286-input corpus.

### What this does NOT catch

- Bugs in functions too large or too stateful to re-implement
  (e.g., the netlink walker, fragment loader). Those rely on
  property-assertion fuzz instead.
- Bugs that BOTH implementations get wrong the same way — possible
  if both are written from the same flawed spec text. Mitigation:
  read the C against the spec, write Python from the spec, don't
  cross-reference.

---

## Coverage measurement

`make fuzz-coverage` builds the harnesses with `-fprofile-instr-generate
-fcoverage-mapping` (in addition to ASan + libFuzzer), runs each harness
for ~10s, merges profdata, generates an HTML report at
`docs/fuzz-coverage/index.html` and a text summary on stderr.

**Run after every harness addition.** Without coverage measurement, "we
have a harness for X" is a claim, not a fact. The coverage report is the
mechanism that promotes a row from 🟡 to ✅.

The 90% threshold is the bar for ✅. Below that, the row stays 🟡 and
the gap is documented in this file.

---

## Bugs found

A running record of bugs each harness has caught. The point is to make
the case for fuzzing self-evident.

| Harness | Bug | Severity | Fixed in |
|---|---|---|---|
| `fuzz_substitute_placeholders` | 1-byte heap-buffer-overflow at `nft_handler.c:208` (terminator write). Triggered when a placeholder expansion pushes `wi` to `max_expand-1` and is followed by an unmatched byte; the unmatched-byte path had no bounds check, advancing `wi` to `max_expand` and the post-loop `out[wi]='\0'` wrote 1 byte past the allocation. Found ~200k iterations after harness was wired in. | Med (fragment trust model is admin-only, so triggering is admin-self-foot-shot, but ASan-detectable OOB is a memory-safety bug regardless). Caused by replacement strings whose total expansion approaches `2*src_len`. | this PR |
| `fuzz_substitute_placeholders` | Same OOB pattern at `nft_handler.c:163` (comment/quote pass-through write). Three write paths in the function, only the matched-placeholder path had a bounds check. Found seconds after the first fix. | Med (same trust model) | this PR |
| `fuzz_netlink_diag` | Heap-buffer-overflow at `peer_lookup.c:134` (then-existing `NLMSG_OK` walk). Root cause: `NLMSG_NEXT` advances by `NLMSG_ALIGN(nlmsg_len)` (4-byte aligned) but `NLMSG_OK` only validates `nlmsg_len <= remaining` (without alignment). A crafted `nlmsg_len` whose 4-byte-aligned size exceeds `remaining` slips past `NLMSG_OK`, then `len -= align(nlmsg_len)` underflows the size_t, and the next iteration dereferences `nlh` past the buffer. Found within ~1k iterations of the harness being wired in. Fix: hand-rolled walk that validates alignment before advancing. | **High** — kernel-supplied bytes (any `CAP_NET_ADMIN` process can post crafted netlink replies); classic netlink-parser CVE pattern. Latent in the codebase since `peer_lookup_tcp` was introduced. | this PR |
| `validate_cgroup_path` (found by inspection during refactor for `fuzz_cgroup_path`, not by fuzzing) | Off-by-one in length check: `if (first_len != 14 \|\| memcmp(p, "authnft.slice", 14) != 0)`. The string `"authnft.slice"` is 13 characters, so the check rejected every valid input. Latent bug — production never called the function (the K1 fix migrated `pam_entry.c` to deterministic `snprintf` construction of the cgroup path), and the unit test only verifies that the function REJECTS non-authnft.slice inputs (it expects rejection by design, so universal-rejection looked correct). Fixed: change `14` to `13` in both the length check and the `memcmp` length. | Low — dead code in production. Logic-bug class that `make fuzz-coverage` would not have caught alone, but the refactor-to-fuzz-it process surfaced it. | this PR |

Regression inputs preserved at:
- `tests/fuzz/corpus/substitute_placeholders/regression_oob_terminator`
- `tests/fuzz/corpus/substitute_placeholders/regression_oob_unmatched_path`
- `tests/fuzz/corpus/netlink_diag/regression_oob_alignment_underflow`

CIFuzz re-runs these on every PR.

## Current coverage (per `make fuzz-coverage-gate`)

Per-function region coverage on the **fuzzed** functions (the only ones the
status legend applies to), measured the way the gate enforces it: replaying
only the committed corpus, on the CI toolchain. Region is the gate metric;
the exact figure drifts a point or two with the clang version, which is why
the committed corpus holds every function a few points above the bar.

| Function | Region (committed corpus) | Status |
|---|---|---|
| `util_is_valid_username` | 92.59% | ✅ |
| `util_normalize_ip` | 93.33% | ✅ |
| `validate_fragment_content` | 100.00% | ✅ |
| `validate_fragment_buf` | 98.36% | ✅ |
| `substitute_placeholders` | 95.24% †| ✅ |
| `peer_parse_diag_chunk` | 92.54% | ✅ |
| `parse_socket_inode` | 100.00% | ✅ |
| `keyring_sanitize` | 100.00% | ✅ |
| `corr_sanitize_copy` | 100.00% | ✅ |
| `validate_cgroup_path` | 100.00% | ✅ |

The `≥90%` region bar is now enforced deterministically by
`make fuzz-coverage-gate` (workflow: `fuzz-coverage.yml`), which replays only
the committed corpus (`-runs=0`) — no timed fuzz run — so the number is
reproducible and a regression fails CI. Keeping each function's committed
corpus rich enough to hold the bar is the maintenance contract. The
`seed_cover_*` inputs were picked by greedy region set-cover over the local
fuzz corpus — the minimal set that holds each function's regions — and
`seed_tgt_*` are hand-written boundary cases (for `validate_cgroup_path`, a
13-char wrong first component, a missing second slash, a truncating `out_sz`).
`keyring_sanitize` and `corr_sanitize_copy` reach 100% from their seed inputs
this way.

† `substitute_placeholders`'s defensive guards that the fuzz harness cannot
reach are marked `LLVM_COV_EXCL_START/STOP` and dropped by the gate. Stock
llvm-cov ignores those markers, so `tests/ci/fuzz-coverage-gate.py` honors them
itself. Six guards are excluded: the three in-loop
`if (wi ... >= max_expand) { free(); return NULL; }` overflow checks,
unreachable because the `max_expand` ratio bound budgets `ratio` per source
byte (`>=` that byte's worst-case expansion, so no write can exceed the
allocation); the empty-placeholder check, which never fires because the harness
passes the production placeholder strings; the `src_len * ratio` overflow
guard, unreachable because a fuzz input cannot be `SIZE_MAX`-scale; and the
malloc-failure guard, which libFuzzer does not exercise (tests/audit/malloc_fail.so
can drive it by hand, but that tool is manual and no gate runs it, so this
guard is untested rather than covered). What remains is the reachable state
machine and matcher, which the committed corpus drives above the bar.

Per-source-file region coverage (illustrating how much codebase is
*untouched* by any harness):

| File | Region cover | Why |
|---|---|---|
| `nft_handler.c` | 35.12% | covered: `validate_fragment_content`, `substitute_placeholders`. uncovered: `nft_handler_setup` cmd assembler, libnftables call sites, `nft_handler_cleanup`, `read_file` |
| `pam_entry.c` | 29.41% | covered: `util_is_valid_username`, `util_normalize_ip`. uncovered: PAM entry points, arg parser, `is_debug_bypass_requested`, `free_pam_data` |
| `peer_lookup.c` | 48.15% | covered: `peer_parse_diag_chunk`. uncovered: `peer_lookup_tcp`, `collect_socket_inodes`, `send_diag_request`, `scan_diag_reply` (I/O wrappers) |
| `keyring.c` | ≈40% | covered: `keyring_sanitize`, `is_safe`. uncovered: `keyring_read_serial`, `keyring_fetch_tag`, `keyctl_syscall` (require live kernel keyring + PAM context) |
| `event.c` | small | covered: `corr_sanitize_copy`, `is_corr_safe`. uncovered: `event_correlation_capture` (clock + getrandom + getpid synthesis path), `event_open_emit`, `event_close_emit` (require live sd-bus journal socket) |
| `bus_handler.c` | 0% | no harness; sd-bus surface mostly out-of-scope |
| `sandbox.c` | 0% | static config, not a parser; no harness planned |
| `session_file.c` | 0% | output-only JSON emitter; low priority |
| **TOTAL** | **22.23%** | The bar is per-function ≥90% for ✅, not aggregate; aggregate goes up by adding harnesses, not by fuzzing the same surface harder |

## Mutation testing (Phase 4.3)

`make mutation-report` runs **mull** (https://github.com/mull-project/mull)
against an LLVM-bitcode-instrumented build of `authnft_test`. Mull
mutates the bitcode in process (~30 mutation operators across
arithmetic, boolean, comparison, and constant-replacement classes)
and re-runs the test binary per mutation. Output: a list of
mutations classified as KILLED (some test failed) or SURVIVED (every
test passed).

A surviving mutation = a line whose change wasn't caught by any
test. Two interpretations:

- **Coverage gap** — add a test that catches the change.
- **Dead code** — the line has no observable effect, even when
  changed; a reader can simplify or delete it.

Mull is in the same toolchain family as `make fuzz` (clang + LLVM),
so it doesn't introduce a new dependency class. The Makefile target
needs `mull-runner` and `clang-N` for the LLVM major you've installed;
the workflow installs both from the upstream PackageCloud DEB repo.

CI: `.github/workflows/mutation.yml` runs weekly (Sunday 06:43 UTC)
and publishes the report as a workflow artefact + a GitHub Step
Summary. Workflow run time: ~30 min for the full mutation set.

### What this catches that fuzz / oracle / property tests do not

- **Boring-helper coverage gaps** — initialization paths, error
  logs, defensive null checks. Code that fuzz harnesses never reach
  because it's not parser-class, but which a mutation in should
  still produce SOME test signal.
- **Dead lines that look like decisions.** A line `if (X)` whose
  body has no observable effect shows up as both branches'
  mutations surviving.

### What it does NOT catch

- Complex semantic bugs — mutation operators are local; a wrong
  algorithm needs differential testing or property-based checks.
- Bugs introduced by INTERACTIONS between functions — mutation is
  per-line; cross-function effects need integration tests.
- Anything in test code itself — mull operates on the test
  binary's bitcode, but the tests themselves are the oracle, not
  the subject.

---

## Sustained-fuzz channel

| Channel | Status | Duration | Trigger |
|---|---|---|---|
| CIFuzz per-PR | live | 60 s × harness | every pull request |
| Nightly cron (`.github/workflows/fuzz-nightly.yml`) | live | 30 min × harness | daily, 03:17 UTC + manual dispatch |
| OSS-Fuzz registration (deferred) | submission staged | continuous | once project age threshold met |
| Self-hosted fuzz farm (optional) | not implemented | always-on | continuous |

The free GitHub Actions tier covers the nightly run for public
repos; rationale and cost notes are in the workflow header.

---

## How to add a new harness

1. **Refactor**: if the target function is `static`, wrap with
   `#ifndef FUZZ_BUILD / static / #endif`. The non-fuzz build is
   bit-identical because `FUZZ_BUILD` is undefined.
2. **Write the harness** in `tests/fuzz/fuzz_<name>.c`. Include
   property assertions (`__builtin_trap()` on invariant violation),
   not just `LLVMFuzzerTestOneInput` returning 0.
3. **Add to `Makefile`**: append to `FUZZ_TARGETS`.
4. **Add to `tests/fuzz/oss-fuzz/build.sh`**: one extra `$CC` invocation.
5. **Add to `.github/workflows/cifuzz.yml`**: one extra step running
   the new binary with `-max_total_time=60`.
6. **Run `make fuzz-coverage`**: verify the harness reaches the
   targeted code paths. If not, fix the harness or split into
   smaller harnesses.
7. **Update this document**: change the status mark, set the harness
   name, note any property assertions in place.
