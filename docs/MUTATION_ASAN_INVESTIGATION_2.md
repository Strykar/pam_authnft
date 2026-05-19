# Investigation: mull+ASan compose suppression, reframed as Makefile pattern-rule omission

## Summary

The investigation set out to characterise mull's pass plugin
suppressing AddressSanitizer's stack-instrumentation in
composed `clang-19 -fpass-plugin=... -fsanitize=address,undefined`
invocations, observed in PR #51 as a line-55 mutant in
`util_normalize_ip` surviving with empty stderr despite a test
that catches it cleanly outside the compose. It found a
Makefile pattern-rule omission: the source-TU mull-object rule
(`$(OBJ_DIR)/%.mull.o: src/%.c`) does not reference
`$(MULL_EXTRA_CFLAGS)`, so `util_validators.mull.o` was
compiled without sanitiser instrumentation in production, and
the OOB write at `core[in_len] = '\0'` happened in unsanitised
code regardless of what the link-time `-fsanitize=address`
implied. The immediate consequence is a one-line Makefile fix
that takes the workflow's mutation score from 34/35 = 97.1% to
35/35 = 100%, not because coverage improved but because the
measurement was no longer under-counting sanitiser-only-
killable mutations.

The methodologically valuable output is not the Makefile bug.
It is the lineage of how the bisection ran for five rounds
under the wrong premise, produced internally-consistent
results that looked correct at each step, and was reframed at
a pre-committed mechanical-audit step (option (C),
mechanical-argv-diff) that surfaced the actual variable. The
bisection methodology worked correctly; only the premise was
wrong. That distinction is the substance of the codified rules
below.

## Background and original framing

PR #51 ([commit 4f75c7e](https://github.com/identd-ng/pam_authnft/commit/4f75c7e))
closed survivors from PR #50's first util-validator mutation
run and surfaced one mutant that resisted closure: line-55
`cxx_ge_to_gt` (`core_len >= sizeof(core)` mutated to
`core_len > sizeof(core)`) in `util_normalize_ip`. The mutant
survives the test that catches it locally under either
gcc+ASan or clang+ASan without mull's pass plugin. In the
composed `clang-19 -fpass-plugin=/usr/lib/mull-ir-frontend-19
-fsanitize=address,undefined` invocation that
util-validator-mutation.yml runs, captured mutant stdout was
`util_validators: all tests passed` and captured stderr was
empty.

The original framing in
[docs/MUTATION_ASAN_EXPERIMENT.md](MUTATION_ASAN_EXPERIMENT.md)
treated this as compose-suppression: that mull's pass plugin
in some way suppressed ASan's red-zone check on the OOB write
at `core[in_len] = '\0'`. The mutant produces no return-value
difference (function returns 0 either way), so behavioural
assertions cannot detect it; the only available detection
mechanism is ASan's red-zone check, which appeared to be the
thing the compose suppressed.

This framing motivated the bisection. The hypothesis was that
some flag or structural feature of the production build caused
mull's pass plugin to interact with ASan's stack
instrumentation in a way that disabled red-zone checks at
specific access sites.

The investigation took an experimental branch
(`experiment/mull-asan-compose-suppression`) and ran a throwaway
workflow (`experiment-compose-suppression.yml`) on a structurally
faithful stub that mirrored `util_normalize_ip`'s shape. Each
run was a one-line commit on the experiment branch, the workflow
was triggered on push, and the run's SQLite report captured the
mutant kill status per (status_code, stderr_content). The
verdict was interpreted against a pre-stated mapping rather
than against the status code's English name (a discipline
that emerged from a prior correction documented in
[d93e9bb](https://github.com/identd-ng/pam_authnft/commit/d93e9bb)).

## The bisection under the wrong premise

The bisection ran across seven commits on the experiment branch
(runs 4a, 5b, 5b', 5a-stkprot, 5a-autovarinit, 5a-cfprot,
5a-stkclash). Each run changed one variable from the previous
and was interpreted against a pre-stated (status_code,
stderr_content) verdict mapping in the workflow's build-step
comment. Three representative runs are covered below; the run
inventory at the end of this doc lists all seven with their
workflow run IDs and commit SHAs.

### Notation: source-line precision

The mutation point and the access site are at different
source locations:

- **Mutation point**: `src/util_validators.c:55:18` is the
  `>=` operator that mull's `cxx_ge_to_gt` mutator rewrites.
  In the stub, the analogous mutation point is at line 51:16.
- **Access site**: `src/util_validators.c:57:5` is the
  `core[in_len]` array index reference; `:57:20` is the
  `= '\0'` store.

The sanitiser diagnostics tag the access site; mull tags the
mutation point. Filter SQLite queries by the mutation-point
`line_number`.

### Run 4a: ASan as sole signal, H0 falsification

[Run 26080445650](https://github.com/identd-ng/pam_authnft/actions/runs/26080445650),
commit [82045a0](https://github.com/identd-ng/pam_authnft/commit/82045a0).

The first run that produced an interpretable signal. Two
coupled changes from prior runs, both serving signal
isolation: (1) test redesigned to drop return-value assertions
at the boundary (no path to non-zero exit except via ASan
abort), (2) build dropped `-fsanitize=undefined` so UBSan's
bounds check on `core[64]` couldn't preempt ASan's red-zone
check. Bare flags: no HARDENING, no `_FORTIFY_SOURCE`, `-O0`.

Result: line-51 `cxx_ge_to_gt` came back
`(1, AddressSanitizer: stack-buffer-overflow + "ABORTING")`,
stderr_len = 3525. ASan tripped cleanly on the OOB write.

Two methodological points surfaced. First, the pre-stated
verdict mapping had predicted "status=4 means ASan-aborted";
the prediction was wrong. mull-0.34 encodes signal-terminated
child as `execution_status = 1` with `exit_status = -1`, not
as `execution_status = 4`. The mistake was at the prediction
step, not the interpretation step (the stderr column
disambiguated the actual kill mechanism). Codified as Rule 2.
Second, ASan is not suppressed in the bare-stub compose, so
whatever causes the production "suppression" is not present
here. The bisection premise: add variables from the
4a-vs-production differential one at a time.

### Runs 5b and 5b': verdict-mapping correctness via signal preemption

5b ([run 26083179775](https://github.com/identd-ng/pam_authnft/actions/runs/26083179775),
commit [f94f04e](https://github.com/identd-ng/pam_authnft/commit/f94f04e))
re-added `-fsanitize=undefined` with
`UBSAN_OPTIONS=halt_on_error=1`. UBSan's bounds check on
`core[in_len]` fired and aborted before ASan got a turn;
stderr was a single UBSan diagnostic block. The binary outcome
the run was designed to produce ("UBSan-in-compose carries the
suppression" or "doesn't carry") was not producible because
UBSan's bounds-check semantics deterministically preempt
ASan's red-zone check at this access site.

5b' ([run 26083914570](https://github.com/identd-ng/pam_authnft/actions/runs/26083914570),
commit [19881b3](https://github.com/identd-ng/pam_authnft/commit/19881b3))
resolved the preemption by flipping `UBSAN_OPTIONS` to
`halt_on_error=0`. UBSan now logs the diagnostic and
continues; ASan's red-zone check fires on the subsequent
write. Result: stderr was two cleanly separated diagnostic
blocks (UBSan logged, then ASan aborted), stderr_len = 4784.
Both sanitisers are functional in the bare stub.

The 5b → 5b' pattern is a verdict-mapping correctness check:
when a pre-stated cell ("UBSan preempted ASan") is observed,
the run's H0 interpretation is undetermined, and a pre-planned
follow-up resolves the preemption. Codified as Rules 3 and 4.

### Run 5a-stkprot: representative HARDENING-flag elimination

[Run 26089833756](https://github.com/identd-ng/pam_authnft/actions/runs/26089833756),
commit [26ec3b8](https://github.com/identd-ng/pam_authnft/commit/26ec3b8).

Single-flag, single-variable diff from 5b'. Added
`-fstack-protector-strong`, the HARDENING flag with the most
direct plausible mechanism for interacting with ASan's stack
instrumentation: canary insertion plus local-variable
reordering reshapes the stack frame around arrays, exactly
where ASan's red zones live.

Result: line-51 mutants came back `(1, UBSan + ASan +
ABORTING)`, stderr_len = 4784, byte-identical to 5b'. Both
sanitisers fired; canary insertion did not change the OOB
write's detection. Cell 4: no effect. stkprot is not a
contributor to H0' in the bare stub.

The strict-sequencing rule for cell-4 eliminations: drop the
eliminated flag, test the next flag in isolation against the
bare-stub baseline. Carrying an eliminated flag forward into
subsequent runs would conflate "this flag in isolation" with
"this flag in combination with already-eliminated flags",
which are different questions.

### Further HARDENING-flag eliminations

5a-autovarinit (`-ftrivial-auto-var-init=zero`, run
[26093491304](https://github.com/identd-ng/pam_authnft/actions/runs/26093491304)),
5a-cfprot (`-fcf-protection`, run
[26096117471](https://github.com/identd-ng/pam_authnft/actions/runs/26096117471)),
and 5a-stkclash (`-fstack-clash-protection`, run
[26096477272](https://github.com/identd-ng/pam_authnft/actions/runs/26096477272))
each followed the 5a-stkprot pattern: one flag added in
isolation, line-51 mutants returned `(1, UBSan + ASan +
ABORTING)` with stderr_len = 4784 byte-identical to all prior
cell-4 runs. The 4×cell-4 result materialised after
5a-stkclash and triggered the pre-committed (C) → (A or B)
sequencing.

The byte-identical stderr_len across five consecutive runs
(5b' + four HARDENING-flag eliminations) is incidental
confirmation that the bisection variable was being changed
cleanly between runs and previous state wasn't bleeding through
via build cache or partial reverts. Codified as the heuristic
in the rules section.

## The reframe: mechanical-argv-diff at step (C)

The 4×cell-4 case triggered a pre-committed three-option
branching:
- (A) HARDENING-en-bloc cumulative run, testing flag
  interaction;
- (B) advance to non-HARDENING variables from the
  4a-vs-production differential;
- (C) re-derive the differential mechanically before
  choosing between (A) and (B).

The pre-committed sequencing was (C) → (A or B), not "obviously
do en-bloc next." (C) is a prerequisite for choosing between
(A) and (B) because the original 4a-vs-production differential
was eyeball-derived (read the Makefile and the workflow YAML,
list variables noticed to differ). The bisection had eliminated
the variables surfaced by the eyeball version, so (C) needed
to be mechanical.

### What the argv-diff surfaced

`MULL_EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" make -n test_util_validators.mull`
emits the exact clang invocations the production build would
execute. The two compile invocations for the
`test_util_validators.mull` target are:

```
# Test-TU compile (matches the bare-stub compose this bisection assumed was the production state):
clang-19 -fpass-plugin=/usr/lib/mull-ir-frontend-19 \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    -g -grecord-command-line -O0 -Iinclude \
    -c tests/test_util_validators.c -o obj/test_util_validators.mull.o

# Source-TU compile (the file containing the line-55 mutation target):
clang-19 -fpass-plugin=/usr/lib/mull-ir-frontend-19 \
    -g -grecord-command-line \
    -fPIC -Wall -Wextra -O2 -Iinclude -D_GNU_SOURCE \
    -fstack-clash-protection -fcf-protection -ftrivial-auto-var-init=zero \
    -fstack-protector-strong -Wformat -Wformat-security \
    -Werror=implicit-fallthrough -fno-strict-overflow -Wtrampolines \
    `pkg-config --cflags libnftables libseccomp libsystemd pam libcap audit` -O0 \
    -c src/util_validators.c -o obj/util_validators.mull.o
```

The source-TU compile invocation does NOT contain
`-fsanitize=address,undefined`. The test-TU compile invocation
does. The link step pulls in the sanitiser runtimes via
`-fsanitize=address,undefined` on the linker command, but
link-time `-fsanitize` does not retroactively instrument the
object files. Sanitiser instrumentation is a compile-time pass
that inserts `__asan_*` and `__ubsan_handle_*` call sites into
the IR; if those calls aren't in the object file, the runtime
has no per-access hooks to service.

The Makefile rules at lines 321-326 and 358-362 confirm the
asymmetry directly. The source-TU rule
`$(OBJ_DIR)/%.mull.o: src/%.c` does not reference
`$(MULL_EXTRA_CFLAGS)`; the test-TU rule
`$(OBJ_DIR)/test_util_validators.mull.o: tests/test_util_validators.c`
does.

So in production, `util_validators.mull.o` was compiled with
HARDENING + pkg-config cflags but with no sanitiser
instrumentation. The OOB write at `core[in_len] = '\0'` in
`util_normalize_ip` happened in unsanitised code. Both
sanitiser runtimes were linked but had no per-access hooks
in the source TU to service. The "compose suppression"
observed in PR #51 was a build-recipe asymmetry where the
source TU was never instrumented.

### Why the original enumeration missed it

The 4a-vs-production differential was enumerated by reading
the Makefile and the workflow YAML and listing variables
noticed to differ: HARDENING, _FORTIFY_SOURCE (via -D),
UBSan, TU expansion, pkg-config-inherited cflags, the test
surface. The list was correct for what it enumerated. It
missed the asymmetry because the asymmetry is structural,
not single-variable: two pattern rules with different recipe
shapes, one of which propagates `$(MULL_EXTRA_CFLAGS)` and
one of which doesn't.

Eyeball enumeration tests a hypothesis about structure
("which variables differ between A and B?"). It surfaces
variables the enumerator already suspected mattered. The
Makefile rule asymmetry is exactly the kind of variable an
enumerator wouldn't suspect, because the surface story (both
files end up in the same linked binary with `-fsanitize=address`
in play) suggests both are sanitised.

Mechanical-argv-diff enumerates the structure itself rather
than testing a hypothesis about it. It surfaces every flag
difference regardless of whether the enumerator suspected it.
This is what made (C) the load-bearing step: any structural
asymmetry that the eyeball enumeration missed would show up
in the argv-diff, and the bisection's eliminations would
have been wasted work testing a hypothesis derived from an
incomplete differential.

### Confirmation: run 5c

[Run 26099239135](https://github.com/identd-ng/pam_authnft/actions/runs/26099239135),
commit [865711f](https://github.com/identd-ng/pam_authnft/commit/865711f)
(parent [3541289](https://github.com/identd-ng/pam_authnft/commit/3541289)
applied the Makefile fix; the child commit fixed a checkpoint-
script grep bug that caught itself in the run-26098216078
first attempt; see Rule 6 below).

The Makefile fix is one line: add `$(MULL_EXTRA_CFLAGS)` to
the source-TU mull-object rule, mirroring the test-TU rule's
recipe shape. Workflow reverted to run-3-style production-
Makefile-driven build (not the bare stub), with the fix
applied.

Result: 35 mutants, all 35 killed (status=1). Zero survivors.
The line-55 mutant — survivor in run 3 with empty stderr —
came back status=1 with full sanitiser diagnostics:

```
src/util_validators.c:57:5: runtime error: index 64 out of bounds for type 'char[64]'
    ... cxx_ge_to_gt:.../util_validators.c:55:18:55:20 .../util_validators.c:57:20
    ... util_normalize_ip ...
    ... test_normalize_core_buffer_boundary tests/test_util_validators.c:251:14
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/util_validators.c:57:5
==N==ERROR: AddressSanitizer: stack-buffer-overflow on address ...
SUMMARY: AddressSanitizer: stack-buffer-overflow .../util_validators.c:57:20
==N==ABORTING
```

UBSan logs the bounds-check failure, execution continues
(experiment workflow's `halt_on_error=0`), ASan red-zone check
fires on the write, process aborts. The mutant is killed via
both sanitiser diagnostics. The sibling `cxx_ge_to_lt` mutant
at line 55 also killed via the same shape.

The canonical rebaseline against
`util-validator-mutation.yml` via workflow_dispatch
([run 26099584194](https://github.com/identd-ng/pam_authnft/actions/runs/26099584194))
produced the same 35/35 result, with UBSan-only diagnostics
(because that workflow uses `UBSAN_OPTIONS=halt_on_error=1`
and UBSan aborts before ASan gets a turn). Same kill verdict,
different kill mechanism, same source-TU-now-instrumented
fact.

## Codified methodological rules

Six rules and one heuristic emerged from the lineage. Rules
are followable (with specific tools and templates); the
heuristic is pattern-recognition for future investigators
running similar work.

### Rule 1: Interpretation-side — name the signal that produced the categorisation

Do not accept `execution_status = N` as "killed" without
naming which specific runtime event produced the
categorisation. Read the `stderr` column or other evidence,
not the status-code's English name.

**Followable form**: when interpreting a mull-runner result,
the SQL query that produces a verdict reads `stderr` (and
`exit_status` if relevant) alongside `execution_status`. The
status code is shorthand; the stderr is the actual evidence.

```sql
SELECT execution_status, mutator, line_number, column_number,
       exit_status, length(stderr) AS stderr_len, stderr
FROM mutant
WHERE line_number = <mutation_point> AND mutator = '<name>'
  AND filename LIKE '%<file>%';
```

Status `1` with non-empty stderr that names a sanitiser
diagnostic is sanitiser-kill. Status `1` with empty stderr
and `exit_status > 0` is assertion-or-other-non-signal kill.
Status `1` with `exit_status = -1` is signal-terminated child.
Status `4` is mull's narrower "crashed" category and is rarer
than the status name suggests. Always verify via stderr.

### Rule 2: Prediction-side (scoped) — verify load-bearing pre-run mappings against tool semantics

For load-bearing pre-run verdict mappings whose interpretation
a run's H0 verdict will rest on, verify the tool's status-code
semantics empirically before publishing the mapping. Casual
conversational predictions about tool behaviour are out of
scope; pre-run verdict mappings that decide whether a finding
is confirmed or falsified are in scope.

**Followable form**: before publishing a verdict mapping that
includes status codes whose semantics matter for the
interpretation, do one of: (a) read the tool's source for the
relevant decoding logic, (b) run a known-trip control case
locally, (c) cite documented enum definitions. The 4a run's
"status=4 means ASan-aborted" prediction was wrong because
mull-0.34 maps signal-terminated children to status=1, not
status=4. Catching that pre-run would have required either
reading mull's source around the child-status decoding or
running a known-aborting control case.

This rule is narrower than the audit-discipline rules below
because the verification cost is higher (reading source or
running a control is more work than a thirty-second grep).
Apply it only where the cost is justified.

### Rule 3: Pre-state observables, not semantics

Verdict mappings should be `(status_code, stderr_content)`
pairs with explicit interpretations, not status-name verdict
shorthand. The mapping is the load-bearing artefact for
post-run interpretation; if it collapses interpretation into
status-name semantics, post-run interpretation can drift.

**Followable template**: the verdict mapping table used
throughout the bisection is the form. Each row has an
empirical observable and an explicit interpretation. Ambiguous
or compound observables get their own rows ("UBSan diagnostic
only, no ASan" is distinct from "UBSan then ASan + ABORTING";
"interleaved diagnostics beyond clean block separation" is
distinct from "both diagnostics as cleanly separated blocks").

| Observable                                                       | Interpretation                                                                                  |
|---|---|
| `(2, stderr empty)`                                              | Mutant survived; the kill mechanisms in play didn't reach it                                    |
| `(1, only sanitiser-A diagnostic)`                               | Sanitiser-A tripped; sanitiser-B preempted or not present                                       |
| `(1, only sanitiser-B diagnostic)`                               | Sanitiser-B tripped; sanitiser-A preempted or not present                                       |
| `(1, both diagnostics as cleanly separated blocks)`              | Both sanitisers fired; first-by-stderr-anchor-line-order is the kill attribution                |
| `(1, interleaved diagnostics)`                                   | Attribution not safe (stderr writes not atomically synchronised across sanitiser handlers)      |
| `(1, no diagnostic, exit_status > 0)`                            | Non-sanitiser kill (assertion or other)                                                          |
| `(1, no diagnostic, exit_status = -1)`                           | Signal-terminated by something other than a sanitiser-induced abort; investigate                |

### Rule 4: Reviewer binary framing doesn't override pre-written enumerated mapping

When a reviewer proposes an intuitive binary outcome ("X is
the carrier or it isn't") that simplifies the pre-written
verdict mapping into two cells, the simplification does not
override the mapping. The mapping is the load-bearing
artefact, not the framing.

The 5b run's actual outcome was the third cell of a five-cell
mapping ("UBSan preempted ASan; ASan suppression status
undetermined") that the binary framing did not enumerate.
Accepting the binary framing post-result would have collapsed
the outcome into one of the two binary branches and lost the
pre-planned follow-up (5b': drop UBSan's `halt_on_error` so
ASan gets a turn).

**Followable form**: when a pre-written mapping has more cells
than a proposed binary framing, the binary framing is a
simplification, not a replacement. Run interpretations should
trace back to the pre-written mapping's cells, not to the
simplification.

### Rule 5 (headline): Read upstream documentation before designing integration; mechanical verification is the recovery step

For any integration with an external tool (build system,
mutation framework, sanitiser, test runner, observability
agent), the load-bearing first step is to read what the tool
says about itself: its documented integration patterns,
canonical examples, and the recipes the upstream provides for
the common cases. The mechanical-verification tools in the
follow-on list are the recovery step when the upstream-doc
step was skipped or when the integration drifts from the
documented pattern.

This is the lineage's most consequential codified rule because
it identifies a class of errors the single-fact rules don't
cover. Single-fact rules (verify a URL, grep a function name,
check a SHA) handle errors at the citation step; this rule
handles errors at the design step. The cost of following the
upstream-doc form is low (typically minutes of reading) and
the value is high: a documented canonical pattern is what the
tool's authors have already debugged across the cases the
project will encounter. Designing around the tool without
reading those docs means rediscovering by trial what was
already written down.

The investigation's reframe at step (C) was downstream of a
more basic missing step. The Makefile pattern-rule asymmetry
that produced the original observation (one rule references
`$(MULL_EXTRA_CFLAGS)`, another doesn't) was the kind of
thing mull's integration documentation would have flagged as a
gotcha: "propagate flags uniformly across all per-file rules
that produce mull-instrumented objects." Whether or not such a
sentence exists verbatim in mull's documentation, reading the
mull project's canonical Makefile-integration examples before
designing the project's two-rule pattern would likely have
surfaced the asymmetry pre-design. The bisection ran for
seven rounds against a counterfactual that the upstream-doc
step would have ruled out before it began.

**Followable form, in order of cost-per-yield**:

1. **Read upstream documentation for the tool you're
   integrating, before designing the integration**. Tool's
   README, integration guide, canonical-examples directory,
   official tutorial. Look for: the recipe the upstream
   suggests for the case at hand, gotchas the upstream
   flags, asymmetries the upstream warns about. Cost: minutes
   of reading. Yield: rules out the class of errors that
   come from rediscovering documented patterns.

2. **Search upstream issues and discussions for the specific
   integration pattern you're about to design**. Has someone
   else already hit this case? What did the maintainers say?
   Cost: a few minutes of searching. Yield: rules out the
   class of errors that come from designing around a known
   sharp edge.

3. **When the upstream-doc step was skipped or the integration
   has drifted, mechanical-verification tools surface the
   actual structure**:

   - **Build-system comparison**: `make -n <target>` against
     the production target with the same env the production
     workflow uses. Diff the resulting argv lists against
     the control build's argv lists. Variants:
     `make CC='echo'`, wrap `$CLANG` in a logging script.
   - **Process-level comparison**: `strace -f -e openat,execve`
     on both binaries. Surfaces file accesses, env
     propagation, sub-process spawns that the argv-level
     comparison doesn't capture.
   - **Linked-binary comparison**: `nm -D --defined-only`
     for exported-symbol asymmetries; `readelf -d` for
     dynamic-linking asymmetries; `readelf -p .comment` for
     compiler-version asymmetries.
   - **Object-level comparison**: `llvm-objdump -d
     --no-show-raw` against two `.o` files for the same
     source surfaces per-function codegen differences.
     Useful when build-system and link comparisons both
     pass but runtime behaviour still differs.
   - **Source-tree comparison**: `find . -name <pattern>
     -newer <reference>` for untracked changes;
     `git diff --stat <branch-A>..<branch-B> -- <subtree>`
     for branch-level scope.

The hierarchy is "upstream-doc-reading first; mechanical
verification when the integration has drifted; single-fact
rules for citations." Use single-fact rules for URLs and
SHAs. Use mechanical-verification tools when the load-bearing
claim is "system A and system B differ in some specific way."
Use the upstream-doc form when designing the integration in
the first place, before either of the above is needed.

### Rule 6: Review checkpoints have a perfunctory failure mode

Review checkpoints (pre-push audits, verify-fix scripts,
sanity-check steps) are cheaper to follow than rules but have
a failure mode rules don't: a rule fails by being forgotten
or ignored, a checkpoint fails by being performed perfunctorily.
"Looked over the diff, looks fine" is the perfunctory form.

Defence: checkpoints should produce a specific output, not
"reviewed" as a status. Verdict mapping confirmed (specifically:
each cell named, each observable enumerated). Audit list
confirmed (specifically: each grep result reported). Line-by-
line diff confirmed (specifically: each changed line traced
to its intended effect).

This caught itself in the 5c lineage. The initial 5c push
([run 26098216078](https://github.com/identd-ng/pam_authnft/actions/runs/26098216078))
failed on the verify-fix checkpoint because the script's grep
pipeline filtered for lines containing `src/util_validators.c`
and then checked those filtered lines for `fsanitize=address`,
but `make -n` emits the compile invocation across multiple
backslash-continued lines, so the path and the flag are never
on the same line. The checkpoint had been added without
running it against the actual `make -n` output; the perfunctory
review-the-script-once form. The CI failure was itself the
checkpoint catching its own logic bug before the mull build
ran on a state that would have produced an uninterpretable
verdict.

**Followable form**: when adding a checkpoint, run it locally
against the actual artefact it inspects (not against the
hypothetical artefact). Confirm a passing case AND a failing
case. The latter is the corollary "test the test" discipline
that distinguishes a real checkpoint from a perfunctory one.

### Heuristic: byte-identical stderr across consecutive cell-X eliminations is a coherence signal

Not a rule. A pattern-recognition heuristic for future
bisection investigators.

If a series of bisection eliminations produces byte-identical
stderr at the suppression site across consecutive runs, that
is incidental confirmation the bisection variable is being
changed cleanly between runs and previous state isn't bleeding
through via build cache or partial reverts. If stderr drifts
slightly run-to-run despite the verdict mapping landing the
same cell, investigate before continuing: drift may indicate
cached object files leaking into the build, partial revert
of an earlier variable, or some other state contamination.

This heuristic surfaced in the bare-stub bisection across
five consecutive runs (5b', 5a-stkprot, 5a-autovarinit,
5a-cfprot, 5a-stkclash), all producing `stderr_len = 4784`
byte-identical for the line-51 mutant. The byte-equality was
how the bisection knew, post-hoc, that the eliminations were
genuinely changing only the intended variable.

## Implications and out-of-scope follow-ups

The investigation produced three follow-up work items, all
out of scope for this writeup but named here so they don't
get lost:

1. **Merge the Makefile fix from the experiment branch to
   main**. The one-line fix at `Makefile` line 323 (adding
   `$(MULL_EXTRA_CFLAGS)` to the source-TU mull-object rule)
   lives only on the experiment branch. Production's
   util-validator-mutation.yml continues to under-count
   mutation score until the fix lands on main. Separate PR.

2. **The `test_suite.mull.o` rule has the same bug**.
   Makefile lines 328-333 build `tests/test_suite.c` with
   the same recipe shape as the source-TU rule and the same
   `$(MULL_EXTRA_CFLAGS)` omission. The authnft_test.mull
   mutation testing pipeline (the original, pre-per-validator-
   extraction) is affected by the same bug. The 5c fix only
   touches the generic `src/%.c → .mull.o` pattern rule;
   widening to include `test_suite.mull.o` is a separate
   trivial commit.

3. **Downstream consumers of the original Finding 4 framing**.
   PR #51's body, future work that references PR #51 or the
   experiment doc, any external readers who saw the
   compose-suppression framing before the supersession landed.
   The PR body is permanent post-squash-merge; the supersession
   of record is the experiment-doc revision (commit
   `<TBD post-push>` against `docs/MUTATION_ASAN_EXPERIMENT.md`).
   Discoverability chain: PR #51 body → experiment doc →
   supersession + this investigation doc.

## Reproducer template

The bisection ran against a faithful structural mirror of
`util_normalize_ip` rather than against the production binary,
to isolate variables one at a time. The template is worth
preserving for future investigators running similar work.

### Stub structure

The stub at `experiment/stub_compose_suppression.c` (on the
experiment branch) mirrors the production function's shape:

```c
#define CORE_SIZE 64

int faithful_check(const char *in, char *out, size_t out_sz)
{
        char core[CORE_SIZE];
        size_t in_len = strlen(in);

        if (in_len >= out_sz)        /* Line A: redundant guard for normal callers */
                return -1;
        if (in_len >= sizeof(core))  /* Line B: mutation target */
                return -1;
        memcpy(core, in, in_len);
        core[in_len] = '\0';         /* Line C: OOB write when mutated */

        if (out_sz > 0 && out)
                out[0] = '\0';
        return 0;
}
```

The mutation target is the `>=` operator on Line B. The
mutator `cxx_ge_to_gt` rewrites it to `>`, which lets
`in_len == sizeof(core)` through the guard, and the
subsequent `core[in_len]` access at Line C lands one byte
past the stack buffer. Behavioural assertions cannot detect
the difference: both original and mutant return 0 from
`faithful_check` when called with the boundary input. The
only available detection is ASan's red-zone check on the
OOB write (or UBSan's bounds check on the array index).

### Test structure

The test at `experiment/test_compose_suppression.c` is
signal-path-agnostic: no return-value assertions, main
returns 0 unconditionally. The only paths to non-zero exit
come from runtime instrumentation tripping. The test exercises
the boundary input (64 'x' characters + NUL into a 65-byte
input buffer, with out_sz = 128):

```c
static void test_boundary_case(void)
{
        char input[65];
        char out[128];
        memset(input, 'x', 64);
        input[64] = '\0';   /* strlen(input) == 64, exactly sizeof(core) */
        (void)faithful_check(input, out, sizeof(out));
}
```

The test also calls `faithful_check("hello", out, sizeof(out))`
as a coverage driver — without it, mull's coverage-driven
filtering may filter the Line-B mutant before generation. The
test function is not a correctness check; it's a coverage
trigger.

### Workflow template

The experiment workflow at
`.github/workflows/experiment-compose-suppression.yml` was
triggered on push to the experiment branch. Each run was one
commit changing one variable in the build configuration. The
build step's comment contained the pre-stated verdict mapping
in (status_code, stderr_content) form, mirroring Rule 3 above.

The post-mull-runner SQLite query step extracted the relevant
columns:

```yaml
- name: Query SQLite — survivors, crashes, mutator distribution
  if: always()
  run: |
    sqlite3 compose-suppression.sqlite \
      "SELECT execution_status, COUNT(*) FROM mutant
       GROUP BY execution_status ORDER BY execution_status;"
    sqlite3 compose-suppression.sqlite \
      "SELECT mutator, line_number, column_number, mutation_replacement
       FROM mutant WHERE execution_status = 2;"
    sqlite3 compose-suppression.sqlite \
      "SELECT mutator, line_number, column_number, mutation_replacement
       FROM mutant WHERE execution_status = 4;"
    sqlite3 compose-suppression.sqlite \
      "SELECT execution_status, mutator, line_number, column_number
       FROM mutant ORDER BY line_number, column_number;"
```

Post-run interpretation read the stderr column directly:

```sh
sqlite3 compose-suppression.sqlite \
  "SELECT stderr FROM mutant
   WHERE line_number = <mutation_point>
     AND mutator = '<cxx_ge_to_gt>';"
```

The verify-fix checkpoint pattern (Rule 6) for build-recipe
changes:

```yaml
- name: Verify <fix> propagates as intended
  run: |
    make -n <target> > /tmp/argv.txt 2>&1
    # Use -B context for multi-line make -n output:
    if ! grep -B5 '<source-path>' /tmp/argv.txt | grep -q '<expected-flag>'; then
        echo "::error::fix did not propagate"
        cat /tmp/argv.txt
        exit 1
    fi
    echo "Verified: <source-path> invocation now contains <expected-flag>"
    grep -B5 '<source-path>' /tmp/argv.txt
```

Test the checkpoint locally against the actual artefact it
inspects before pushing. The 5c lineage's checkpoint failure
([run 26098216078](https://github.com/identd-ng/pam_authnft/actions/runs/26098216078))
caught itself precisely because the checkpoint had not been
tested against `make -n`'s actual multi-line output before
the push.

## Run inventory

The experiment branch (`experiment/mull-asan-compose-suppression`)
was preserved through this writeup and tagged at HEAD as
`investigation/mull-asan-compose-suppression` after the doc
commits landed on main. The branch was then deleted; the tag
keeps the commit history without keeping the branch in the
active branch list.

| Run                | Workflow                          | Run ID                                                                                                | Commit                                                                                            | Verdict                                              |
|---|---|---|---|---|
| run 1 baseline     | experiment-compose-suppression    | [26054857613](https://github.com/identd-ng/pam_authnft/actions/runs/26054857613)                      | [b86821f](https://github.com/identd-ng/pam_authnft/commit/b86821f)                                | Build failure: multi-file mistake, no mutants generated |
| run 1 fix          | experiment-compose-suppression    | [26057334931](https://github.com/identd-ng/pam_authnft/actions/runs/26057334931)                      | [d45fcd6](https://github.com/identd-ng/pam_authnft/commit/d45fcd6)                                | Stub killed by assertion (signal-isolation broken)   |
| run 2              | experiment-compose-suppression    | [26059774039](https://github.com/identd-ng/pam_authnft/actions/runs/26059774039)                      | [7c1a90d](https://github.com/identd-ng/pam_authnft/commit/7c1a90d)                                | Stub + HARDENING, still assertion-killed             |
| run 3              | experiment-compose-suppression    | [26077275320](https://github.com/identd-ng/pam_authnft/actions/runs/26077275320)                      | [158606c](https://github.com/identd-ng/pam_authnft/commit/158606c)                                | Production source via Makefile: line-55 survived, suppression reproduced |
| run 4a             | experiment-compose-suppression    | [26080445650](https://github.com/identd-ng/pam_authnft/actions/runs/26080445650)                      | [82045a0](https://github.com/identd-ng/pam_authnft/commit/82045a0)                                | Bare stub, ASan-only: ASan tripped, "H0 falsified"   |
| run 5b             | experiment-compose-suppression    | [26083179775](https://github.com/identd-ng/pam_authnft/actions/runs/26083179775)                      | [f94f04e](https://github.com/identd-ng/pam_authnft/commit/f94f04e)                                | UBSan re-added, halt_on_error=1: UBSan preempted ASan |
| run 5b'            | experiment-compose-suppression    | [26083914570](https://github.com/identd-ng/pam_authnft/actions/runs/26083914570)                      | [19881b3](https://github.com/identd-ng/pam_authnft/commit/19881b3)                                | UBSan halt_on_error=0: both sanitisers fire cleanly  |
| run 5a-stkprot     | experiment-compose-suppression    | [26089833756](https://github.com/identd-ng/pam_authnft/actions/runs/26089833756)                      | [26ec3b8](https://github.com/identd-ng/pam_authnft/commit/26ec3b8)                                | +stack-protector-strong: cell 4                      |
| run 5a-autovarinit | experiment-compose-suppression    | [26093491304](https://github.com/identd-ng/pam_authnft/actions/runs/26093491304)                      | [71dd659](https://github.com/identd-ng/pam_authnft/commit/71dd659)                                | +trivial-auto-var-init=zero: cell 4                  |
| run 5a-cfprot      | experiment-compose-suppression    | [26096117471](https://github.com/identd-ng/pam_authnft/actions/runs/26096117471)                      | [a5e5b77](https://github.com/identd-ng/pam_authnft/commit/a5e5b77)                                | +cf-protection: cell 4                               |
| run 5a-stkclash    | experiment-compose-suppression    | [26096477272](https://github.com/identd-ng/pam_authnft/actions/runs/26096477272)                      | [5164b05](https://github.com/identd-ng/pam_authnft/commit/5164b05)                                | +stack-clash-protection: cell 4, 4×cell-4 materialised |
| run 5c (initial)   | experiment-compose-suppression    | [26098216078](https://github.com/identd-ng/pam_authnft/actions/runs/26098216078)                      | [3541289](https://github.com/identd-ng/pam_authnft/commit/3541289)                                | Failed on verify-fix checkpoint grep bug (caught itself) |
| run 5c (verified)  | experiment-compose-suppression    | [26099239135](https://github.com/identd-ng/pam_authnft/actions/runs/26099239135)                      | [865711f](https://github.com/identd-ng/pam_authnft/commit/865711f)                                | Makefile fix applied: 35/35 status=1, H0' confirmed  |
| canonical rebaseline | util-validator-mutation         | [26099584194](https://github.com/identd-ng/pam_authnft/actions/runs/26099584194)                      | (workflow_dispatch against experiment branch)                                                     | Canonical production workflow: 35/35 status=1, 100% mutation score |

SQLite reports for each run are preserved in the workflow run
artefacts under the `compose-suppression-report` (or
`util-validator-mutation-report` for the canonical rebaseline)
upload-artifact name. The 30-day artefact retention applies;
beyond that, the per-run SQLite stderr columns are
recoverable only by re-running against the same commit.
