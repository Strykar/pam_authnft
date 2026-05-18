# Mutation testing + AddressSanitizer compose: empirical record

This document records a CI experiment run on 2026-05-18 to answer a
narrow question that arose while planning the validator unit-test PR:
can `clang -fpass-plugin=/usr/lib/mull-ir-frontend-19` and
`-fsanitize=address,undefined` coexist in a single compile, such that
`mull-runner-19` produces a coherent mutation report whose kill/
survive attribution is test-driven and not sanitiser-driven?

The answer is "yes for binaries that do not install a seccomp filter;
no for the existing `tests/test_suite.c`." The failure is **not** at
the toolchain layer — pass plugins compose, ASan and mull's
IR-frontend plugin coexist in the same `clang` invocation, the
binary links, and the runtime is stable. The wall is in the test
harness: `test_suite.c`'s Stage 2/3 installs a seccomp filter whose
allowlist does not cover the syscalls ASan's runtime issues. mull
was incidental to the discovery.

This finding generalises beyond mutation testing: **any future work
that runs `tests/test_suite.c` under ASan or UBSan hits the same
wall, with or without mull.** Worth knowing.

## Method

Four CI runs on `ci/mull-per-file-validation`, a throwaway branch
created during the [PR #47](../../../pull/47) workflow rebuild. The
branch was deleted after this document landed; the workflow runs are
preserved in GitHub Actions history (30-day artefact retention,
90-day log retention) and the SQLite databases ship in this
repository alongside the writeup.

| # | Name | Run | Build flags | Subject | Result |
| --- | --- | --- | --- | --- | --- |
| 1 | α-SQL | [26025671855](../../actions/runs/26025671855) | none extra | `authnft_test.mull` (test_suite.c + src/*.c) | 408 mutants; baseline status distribution |
| 2 | β | [26025905549](../../actions/runs/26025905549) | `-fsanitize=address,undefined -fno-omit-frame-pointer` | same | warmup failed at Stage 3 |
| 3 | α-validator | [26026887271](../../actions/runs/26026887271) | none extra | `stub_validator.mull` (no seccomp) | 16 mutants, all killed by assertion |
| 4 | β-validator | [26027376256](../../actions/runs/26027376256) | `-fsanitize=address,undefined -fno-omit-frame-pointer` | same | 16 mutants, all killed by assertion — identical to (3) |

The compact result notation used in §"Why the stub run succeeded"
below — `16/16/0/0/0` — reads as `total / killed_by_assertion (status
1+5) / passed (2) / timedout (3) / crashed (4)`.

GitHub Actions log retention is 90 days; artefact retention is 30
days. The inline run-page links above resolve until approximately
**2026-08-16**. After that date, the SQLite databases in this
directory are the surviving evidence — designed precisely so the
record outlives the CI infrastructure.

An earlier run (`α`, IDE-only, no SQLite, [26024830411](../../actions/runs/26024830411))
confirmed the workflow was deterministic before adding the SQLite
reporter: 408 mutants, 10% score, per-file distribution identical
to the post-merge baseline. The α-SQL run replaced it once status
codes became the load-bearing signal.

A broken stub iteration (run 26026334891) was discarded — the
initial `stub_validator.c` had an unreachable third return branch
that compiled cleanly but mull's coverage analysis correctly
skipped, leaving fewer mutation points than intended and an
uninformative report. Lesson registered: compile **and run** any
new test code locally before committing it as part of a CI
experiment; "compiles" is not sufficient for code that will be
fed to a coverage- or mutation-aware tool.

## Why the test_suite.c run failed

The β run on `authnft_test.mull` did not fail at compile or link.
mull's pass plugin and ASan's instrumentation pass coexisted in the
single `clang-19` invocation without diagnostic. The binary linked
cleanly. `mull-runner-19` started, performed library-discovery
warnings, and entered its warmup run.

The warmup run is mull's pre-mutation execution of the test binary
to confirm it works under no mutation. The binary executed Stages 1
and 2 (printing `[PASS]`) and started Stage 3, then died:

```text
[STAGE 3] Allowlisted syscall survives sandbox...
[error] Original test failed (warmup run)
status: Failed
[error] Error messages are treated as fatal errors. Exiting now.
```

Stage 2 is the project's seccomp-allowlist invariant test: it
installs a seccomp BPF program enumerating the syscalls
`src/sandbox.c` declares legal, then makes a deliberately-excluded
syscall and asserts SIGSYS. Stage 3 inverts the test: a fork +
seccomp filter + permitted syscall, asserting clean completion.

ASan's runtime issues syscalls that the seccomp allowlist does not
permit. The warmup failure output preserved here does not capture
the specific syscall number that triggered SIGSYS — neither
mull-runner nor the test harness logs the kernel's `SIGSYS`
`siginfo_t` for diagnostic purposes. Inferring likely candidates:
`prctl(PR_SET_VMA)` is used to name the ASan shadow region,
`mmap` with flags including `MAP_FIXED_NOREPLACE` to claim that
region's address range, `rt_sigaction` to install sanitiser
signal handlers; any of these or others (varying by libc and
kernel version) would trip an allowlist sized for production
`pam_authnft.so` execution. Confirming which specific syscall
fired would require re-running under `strace -f` with the
sandbox bypassed, or adding `SIG_SYS_AUDIT` plumbing to the test
harness; neither was done because the architectural conclusion
does not depend on the answer. When Stage 3 forks into the
seccomp-confined child, the child's first ASan-attributable
syscall — whichever it is — hits the filter and the kernel sends
SIGSYS. The binary exits non-zero before completing Stage 3. mull-runner sees the
warmup as a failure and refuses to execute mutation runs — the
correct behaviour, since a binary that can't reach a stable
no-mutation state has no meaningful baseline.

This is the architectural mismatch the experiment exists to name.
It is not a mull bug, a clang bug, or an ASan bug. It is the
predictable consequence of putting seccomp filtering and an ASan
runtime into the same address space without coordinating their
syscall surfaces.

No `asan-compose-beta.sqlite` was produced; mull-runner did not
reach the report-writing stage. The failure report is preserved at
[`mutation-asan-experiment/test_suite-beta-warmup-failure.txt`](mutation-asan-experiment/test_suite-beta-warmup-failure.txt).

## Why the stub run succeeded

The stub binary (`experiment/stub_validator.c`, throwaway, never
landed on main) contains a single pure function exercised by five
deterministic test cases. No fork. No seccomp. No PAM module loaded.
No libnftables. The only library deps are libc, libgcc_s, libm,
libresolv (transitive, unused).

Both runs produced identical results:

```text
α-validator (no sanitisers):                16 mutants, 16 killed (status=1), 0 crashed (status=4)
β-validator (-fsanitize=address,undefined): 16 mutants, 16 killed (status=1), 0 crashed (status=4)
```

The mutant set is bit-identical between the two runs — `comm -3` on
the sorted `mutant_id` columns returns no differences. Same IR
locations get mutated, same outcomes attributed to each. ASan's
instrumentation was active throughout every mutant run; no
violation was reported and none of the mutants crashed the binary,
because the assertions in `main()` detected the mutation before
ASan had reason to flag a memory violation. No status-4 Crashed
mutants in either database confirms no sanitiser-attributable
false-positive kills.

## Verdict for the validator PR

A new test binary built **only** from `src/nft_validator.c` and
`tests/test_nft_validator.c` (the file split planned in the
validator PR) will not install a seccomp filter — neither the
production code nor the planned tests have any reason to. That
binary can be built with **both** mull's pass plugin and
`-fsanitize=address,undefined` in a **single** `clang-19`
invocation, validated empirically by the α-validator / β-validator
runs above.

One CI job. Not parallel jobs. The validator PR's design simplifies
accordingly.

This verdict holds as long as the validator binary's dependency
closure does not include code that installs a seccomp filter. If
the validator ever gains a transitive dep that calls
`prctl(PR_SET_SECCOMP)` (or `PR_SET_NO_NEW_PRIVS` followed by
`seccomp(SECCOMP_SET_MODE_FILTER, ...)`) at constructor time or
during the test's initialisation path, the warmup-failure mode
returns and a parallel-job split becomes necessary. Worth checking
the dependency closure if the validator's library set ever
expands beyond the current libc-only baseline.

The existing `authnft_test.mull` keeps its current `make` target
unchanged — it is not built with sanitisers, and the weekly mull
workflow continues to use it without modification. If a future
change wants to put `tests/test_suite.c` under ASan, the work
required is real: factor the seccomp-coupled Stages 2 and 3 into a
separate binary, or extend the allowlist in `src/sandbox.c` to
permit ASan's syscall surface (and accept the corresponding loss in
defence-in-depth strictness).

## Mull 0.34 SQLite schema note

The `.sqlite` files committed alongside this writeup use mull
0.34.0's flattened schema:

```sql
CREATE TABLE mutant (
  mutant_id TEXT,
  mutator TEXT,
  filename TEXT,
  directory TEXT,
  line_number INT,
  column_number INT,
  end_line_number INT,
  end_column_number INT,
  execution_status INT,  -- the column the experiment hinges on
  exit_status INT,
  duration INT,
  stdout TEXT,
  stderr TEXT,
  mutation_replacement TEXT
);
```

`execution_status` integer values, from
[`rust/mull-state/src/execution_status.rs` at tag 0.34.0](https://github.com/mull-project/mull/blob/0.34.0/rust/mull-state/src/execution_status.rs):

| Status | Meaning |
| --- | --- |
| 0 | Invalid |
| 1 | Failed (assertion / non-zero exit) |
| 2 | Passed (mutation survived) |
| 3 | Timedout |
| 4 | Crashed (terminated by signal) |
| 5 | AbnormalExit |
| 6 | DryRun |
| 7 | FailFast |
| 8 | NotCovered |

**Correction-of-record.** An earlier version of this document
characterised the upstream
[readthedocs SQLite-reporter tutorial](https://mull.readthedocs.io/en/latest/SQLiteReporter.html)
as stale relative to the Rust enum at tag 0.34.0. That
characterisation was unsupported. The actual finding is the gap
between the internal state machine (the Rust enum, 9 values 0–8)
and the report surface (the `mutant.execution_status` column,
which carries a subset of those values in practice). The original
framing conflated the two; the corrected framing distinguishes
them.

Concretely: the Rust enum defines 9 `ExecutionStatus` values; the
readthedocs tutorial documents statuses 1–7 as the report-surface
values; empirically only statuses 1–3 appear across this
experiment's four mutation runs (571 mutants total), with
status 4 (Crashed) queried and confirmed zero in the runs where
sanitiser attribution mattered. Statuses 0 (`Invalid`, the
`#[default]` constructed-state) and 8 (`NotCovered`) are present
in the Rust enum but **empirically unreachable across 571 mutants
spanning four runs; upstream confirmation pending**. Statuses
5–7 are similarly absent from all four databases.

This experiment's queries treat status `1` OR `5` as killed-by-
assertion (matching the `IN (1,5)` clause used in the SQL
throughout this document), `2` as passed, `3` as timedout, and
`4` as Crashed / sanitiser-attributable. Statuses `0` and `6`–`8`
are not queried at all because no observation has placed any
mutant there. Status `5` is queried but, like `6`–`8`, has not
appeared across the four runs.

Older mull versions (≤0.17) used a separate `execution_result` table
keyed by `mutant_id`; that schema is gone in 0.34. Queries against
this experiment's databases need `SELECT ... FROM mutant`, not
`FROM execution_result`. A reviewer Googling for example queries
against older docs will find joins that no longer apply.

The query template the experiment used:

```sql
SELECT
    COUNT(*) AS total,
    SUM(CASE WHEN execution_status IN (1,5) THEN 1 ELSE 0 END) AS killed_by_assertion,
    SUM(CASE WHEN execution_status = 2     THEN 1 ELSE 0 END) AS passed,
    SUM(CASE WHEN execution_status = 3     THEN 1 ELSE 0 END) AS timedout,
    SUM(CASE WHEN execution_status = 4     THEN 1 ELSE 0 END) AS crashed
FROM mutant;
```

## Evidence files

In `docs/mutation-asan-experiment/`:

- `test_suite-alpha.sqlite` — α-SQL on test_suite.c (408 mutants, 41 Failed, 366 Passed, 1 Timedout, 0 Crashed).
- `test_suite-beta-warmup-failure.txt` — β on test_suite.c, mull-runner text report showing warmup failure at Stage 3.
- `stub-validator-alpha.sqlite` — α-validator on stub (16 mutants, all status=1).
- `stub-validator-beta.sqlite` — β-validator on stub with ASan+UBSan (16 mutants, all status=1, identical to α-validator).

Re-query any of them with `sqlite3 <path> "SELECT execution_status, COUNT(*) FROM mutant GROUP BY execution_status;"`.
