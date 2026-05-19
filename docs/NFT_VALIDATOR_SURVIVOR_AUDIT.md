# nft-validator survivor audit (post-PR-#52 rebaseline)

**Empirical state:** `validator-mutation.yml` [run 26115718038](https://github.com/identd-ng/pam_authnft/actions/runs/26115718038) on PR #52's branch. 131 mutants total; 80 killed (status=1), 47 survived (status=2), 4 timedout (status=3). Score 61.1% by mull's killed/total formula. All mutants are in `src/nft_validator.c`.

The Makefile fix from PR #52 un-confounded the survivor set: sanitiser-detectable mutants that tests reach are now killable in principle. This audit classifies each of the 51 survivors into one of:

1. **Non-sanitiser-detectable real coverage gap**: needs assertion-based test additions.
2. **Sanitiser-detectable but test surface doesn't reach**: needs new test inputs.
3. **Equivalent mutant**: unkillable in principle, classification artefact.
4. **Killed-but-misclassified by workflow config**: would be status=1 under PR #51's fixes (not present in this workflow).

---

## Pre-audit Finding (highest leverage, no test-writing required)

**`validator-mutation.yml` is missing two PR #51 fixes** that `util-validator-mutation.yml` has:

### Workflow-config finding 1: `halt_on_error=0` is wrong-by-scope

Current:
```yaml
ASAN_OPTIONS: "abort_on_error=0:halt_on_error=0:print_summary=1"
UBSAN_OPTIONS: "halt_on_error=0:print_stacktrace=1:print_summary=1"
```

util-validator-mutation.yml (post-PR-#51):
```yaml
ASAN_OPTIONS: "abort_on_error=1:halt_on_error=1:print_summary=1"
UBSAN_OPTIONS: "halt_on_error=1:print_stacktrace=1:print_summary=1"
```

Same scope-transfer error PR #51's Finding 3 named: the `halt_on_error=0` setting is correct for the seccomp-coupled `test_suite.c` binary (which needs ASan-on-warmup to not abort) but wrong for the validator binaries (which install no seccomp filter and run mutants in separate subprocesses).

### Workflow-config finding 2: `--minimum-timeout` not set

Current:
```yaml
"mull-runner-${MULL_LLVM_MAJOR}" \
    --reporters IDE --reporters SQLite \
    ...
```

util-validator-mutation.yml has `--minimum-timeout 5000` from PR #51's Finding 2. Without it, ASan-induced aborts (300-400ms with stack symbolisation) can exceed mull's default per-mutant timeout and get classified as Timedout (status=3) rather than Failed (status=1).

### Empirical effect of applying both fixes

Three survivors/timeouts attribute to the missing fixes:

| Mutation | Current | Stderr evidence | After fixes |
|---|---|---|---|
| L69:41 `cxx_sub_to_add` | status=2 (survived) | ASan `global-buffer-overflow` in `MemcmpInterceptorCommon` — `tlen = line_end + t` (huge); memcmp at L95 reads 28 bytes past `t`. 3868 bytes of ASan output in stderr | status=1 via halt_on_error=1 |
| L94:18 `cxx_ge_to_lt` | status=3 (timedout) | ASan `global-buffer-overflow` (similar; short lines take the prefix path) | status=1 via halt_on_error=1 + minimum-timeout=5000 |
| L193:26 `cxx_lt_to_ge` | status=3 (timedout) | Test failures: `[FAIL] test_substitute_overflow_boundary` + `[FAIL] test_substitute_empty_placeholder_rejected` — `k >= 4` skips the bound-calc loop entirely; tests catch downstream effects | status=1 via minimum-timeout=5000 |

Two more timeouts (L61:14, L155:34, both `cxx_lt_to_le` / `cxx_lt_to_ge` on loop guards) are genuine infinite loops with empty stderr. They time out under any reasonable `--minimum-timeout`; they're "detected by timeout but not counted as killed by mull's score formula." Out of scope for this audit's test-writing.

**Projected post-fix score: 83/131 = 63.4% killed** (80 base + 3 reclassified), with 2 remaining infinite-loop timeouts and 46 status=2 survivors to audit.

---

## Status=2 survivor classification (46 mutants, all empty stderr)

Six patterns cover all 46. Counts and verdicts:

### Pattern P1: Pointer arithmetic (`cxx_sub_to_add` on pointer differences)

**Mutants** (3, excluding L69:41 which becomes a kill): L62:61, L64:45, L122:35

| Mutation | Source | Analysis | Verdict |
|---|---|---|---|
| L62:61 `end - p` → `end + p` | `memchr(p, '\n', (size_t)(end - p))` | Length becomes garbage. memchr stops at first `\n` match — if buffer has `\n` near the start, no OOB. Test inputs all have `\n` early. To catch: a buffer with no `\n` at all (or `\n` very far in). | **Category 2** |
| L64:45 `line_end - p` → `line_end + p` | `size_t line_len = (size_t)(line_end - p);` | `line_len` is `(void)line_len` at L157 — computed but unused. | **Category 3 (equivalent)** |
| L122:35 `line_end - q` → `line_end + q` | `if ((size_t)(line_end - q) < 13 ...)` | Garbage value passed to `< 13` check. `garbage < 13` is false for any reasonable garbage value, so the check fails open. memcmp reads 13 bytes from `q`. For include paths shorter than 13 bytes after `/`, OOB read past line_end. | **Category 2** |

### Pattern P2: Off-by-one loop bound (`<` ↔ `<=`)

**Mutants** (7): L68:18×2, L112:22, L113:19, L133:39, L134:40, L249:39

All mutate a loop guard from `<` to `<=` (or `<` to `>=`). The extra iteration reads the byte at the boundary position. For most test inputs, that byte is `\n` (end of line) which fails the loop's body condition, so the loop exits and behaviour matches the original. Equivalent in normal cases.

| Mutation | Conditions where it'd be caught |
|---|---|
| L68 `t < line_end` (whitespace skip) | Last line without trailing newline; whitespace at line_end position |
| L112 `q < line_end` (whitespace skip in include) | Same shape; include line without trailing newline |
| L113 `q < line_end` (quote-skip in include) | Same |
| L133 `g < line_end` (path traversal scan) | Include path ending without newline |
| L134 `g + 1 < line_end` (`..` lookahead) | Include path ending in `.` |
| L249 `i + plen < src_len` (token-boundary lookahead) | Source ending exactly at placeholder boundary |

**Verdict for all seven: Category 3 (equivalent in current test surface)** or **Category 2** if a test adds a no-trailing-newline input. Low-value to test for (the off-by-one is genuinely harmless given the surrounding code).

### Pattern P3: Exact-boundary equality (`>=` → `>`, `==` → `!=`)

**Mutants** (~25): L78:22, L94:18 (status=2), L96:19, L98:41, L109:18, L110:34, L110:50, L115:19, L135:24, L136:28×2, L137:27, L137:42, L137:57, L197:18, L201:15, L250:27, L250:42×2, L251:27, L251:42, L252:27, L252:42×2, L257:31, L275:24

Mutate a `>=` to `>` or `==` to `!=` on a boundary check. The test surface doesn't exercise the exact-boundary case. Highest-value category for test additions.

Representative examples:

| Mutation | Boundary | Test addition needed |
|---|---|---|
| L78:22 `tlen >= vlen` → `>` | Disallowed verb that is the entire line (no trailing space/tab/text) | A bad-verb test like `"flush\n"` exactly (no trailing content) |
| L94:18 `tlen >= prefix_len` → `>` | Shared-chain prefix matching the entire line | `"add rule inet authnft filter\n"` exactly (no trailing rule body) |
| L98:41 `t[i] == '\t'` → `!=` | Shared-chain prefix followed by `\t` instead of `\n` or ` ` | `"add rule inet authnft filter\tip saddr ...\n"` |
| L109:18 `tlen >= 8` → `>` | `"include\n"` (length exactly 8, including newline byte?) — depends on how line_len is computed | `"include\n"` with no path |
| L110:34/50 `t[7] == ' '` → `!=` etc. | `"include\t"` or `"include\""` directly (not `" "`) | Test cases with each of `' '`, `'\t'`, `'"'` after `include` |
| L115:19 `q >= line_end` → `>` | Include path that ends exactly at line_end | Edge-case include `include "/"` |
| L136:28 `g + 2 >= line_end` → `>` / `<` | `..` segment exactly at end of include path | `"include \"/etc/authnft/..\"\n"` (without trailing slash) |
| L137:27/42/57 `g[2] == X` → `!=` | `..` followed by various boundary chars | `"include \"/etc/authnft/..\\t\"\n"`, `..\"` literal, etc. |
| L197:18 `rlen > max_rep_len` → `>=` | All replacements same length | reps with rlen ties |
| L250-252 ASCII-range bounds | Character classes A/Z/a/z/0/9 at exact boundaries | Token-boundary tests with `@session_v4A`, `@session_v4Z`, `@session_v40`, `@session_v49` |

**Verdict for most: Category 1 (real coverage gap)** for the exact-boundary inputs. **Some are Category 3** where the exact-boundary case is structurally unreachable (e.g., if surrounding code ensures the equality never holds).

### Pattern P4: Counter mutations (`++` → `--`)

**Mutants** (2): L156:15 (`lineno++`), L193:32 (`k++`, status=2 case)

| Mutation | Analysis | Verdict |
|---|---|---|
| L156:15 `lineno++` → `lineno--` | `lineno` is only used in `pam_syslog` error messages — doesn't affect `rc`. Tests don't assert on syslog output. | **Category 3 (equivalent for test surface)** |
| L193:32 `k++` → `k--` | `k` is `size_t`; underflows to SIZE_MAX after first iteration; `k < 4` (SIZE_MAX < 4 = false) exits loop. Only `placeholders[0]` is examined. For tests with single-placeholder usage, output matches. | **Category 1 (real gap)**: need test with multi-placeholder input where the bound-calc loop actually matters for max_rep_len/min_ph_len |

### Pattern P5: Arithmetic mutations on bound calculation

**Mutants** (3): L200:46 (`-` → `+`), L200:51 (`/` → `*`), L202:34 (`/` → `*`)

| Mutation | Mechanism | Verdict |
|---|---|---|
| L200:46 `max_rep_len + min_ph_len - 1` → `+ 1` | Different ratio. Probably affects malloc size in edge cases. | **Category 2**: needs adversarial-ratio test |
| L200:51 `/ min_ph_len` → `* min_ph_len` | Huge ratio; check at L202 should catch (`src_len > SIZE_MAX/ratio`). | **Likely Category 3** if the L202 overflow check catches it; otherwise Category 2 |
| L202:34 `(SIZE_MAX - 1) / ratio` → `* ratio` | Overflow path. | **Likely Category 3** for same reason |

### Pattern P6: Bound-check direction (`>=` → `>` on `wi + N >= max_expand`)

**Mutants** (3): L233:24, L257:31, L275:24

All three are the `wi + 1 >= max_expand` (or `wi + rlen >= max_expand`) checks that prevent the trailing `\0` write or substitution writes from going OOB. Mutating to `>` lets wi reach exactly `max_expand-1` written, then the next byte writes at `max_expand` = one byte past.

| Mutation | Path | Verdict |
|---|---|---|
| L233:24 | comment/quote path | **Category 2**: needs input where comment/quote-byte writes land at exact bound |
| L257:31 | matched-placeholder path | **Category 2**: needs replacement that fills exactly to max_expand-1 |
| L275:24 | unmatched-byte path | **Category 2**: needs source-byte fill to max_expand-1 |

`test_substitute_overflow_boundary` exists but tests a coarse overflow case. The exact-boundary case needs a sharper input.

---

## Audit summary

| Category | Count | Resolution |
|---|---|---|
| (0) Killed-but-misclassified by workflow config | 3 (L69:41, L94:18, L193:26) | Workflow-config fix; no test-writing |
| (1) Non-sanitiser-detectable real coverage gap | ~7 mutants in pattern P3 + L193:32 (P4) | Assertion-based test additions on exact-boundary inputs |
| (2) Sanitiser-detectable but test doesn't reach | ~15 mutants across P1/P3/P6 | New test inputs that exercise the boundary |
| (3) Equivalent (test surface or structural) | ~21 mutants across P2/P4/P5 + edge cases of P3 | Document and accept |
| (timeout, genuine infinite loop) | 2 (L61:14, L155:34) | Not counted in mull score; not addressable via tests |

Counts are approximate; some mutations could move between categories depending on which test additions land.

**Highest-value actions, in priority order:**

1. **Workflow-config fixes** (one PR, no test writing). Transfers PR #51's halt_on_error and minimum-timeout fixes to `validator-mutation.yml`. Projected score 63.4%. Trivial diff (~3 lines).

2. **Exact-boundary test additions** for pattern P3 (about 7-10 new test cases) and pattern P6 (about 3 new test cases for substitute_placeholders bounds). Half-day's careful work; would land another ~10-15 kills. Projected score ~70-75%.

3. **No-newline-buffer tests** for pattern P1 (1-2 new test cases). Quick. Would catch L62:61 and L122:35.

4. **Multi-placeholder bound-calc test** for L193:32. One test case. Would catch the k-- mutant directly.

5. **Pattern P2 (off-by-one loop bounds) and Pattern P5 (bound-calc arithmetic edge cases)**: low-yield. Leave as Category-3-or-acceptable.

**Equivalent mutants to document and accept:** L64:45 (unused variable), L156:15 (lineno only used in error messages), most P2 mutants (off-by-one harmless in current surface), L200:51/L202:34 (caught by overflow check).

---

## Out of scope

- Test-writing itself. This is the audit; the test additions are a separate work item.
- Mutator-filter configuration (e.g., excluding the `_p` line-end mutators that produce mostly equivalents). Mull's `--exclude-mutators` option could trim category (3) from the report; out of audit scope.
- The two genuine infinite-loop timeouts (L61:14, L155:34). Detected by mull's timeout mechanism but not counted in score; not addressable via test additions without intrusive wallclock checks around the call.
