# Local root-capable audit harness

The hosted CI (GitHub Actions) can build, statically analyse, fuzz, and
mutation-test the pure surfaces, but it cannot exercise the code that needs
root + real nftables + systemd scopes + a cgroup hierarchy. That code —
`nft_handler_setup` and the full PAM session lifecycle — is where a leak
(Coverity CID 1659576, `frag_buf` on the nft-failure returns) survived
every gate except the weekly deep static scan.

This harness closes that gap. It runs the real lifecycle and the
`nft_handler_setup` error returns **under a leak detector**, in disposable
isolated environments, and it injects the faults needed to reach the error
returns the happy-path integration suite never takes.

## Why the leak survived (the gap this closes)

- `make test-integration` drives `nft_handler_setup` for real via
  pamtester, but never under a leak detector; the valgrind pass it runs is
  over the *unit* binary, which never reaches those paths.
- Even stage 10.14 (failure-path rollback) drives the call-3 substitution
  failure, which frees correctly; the `frag_buf` leaks were on the earlier
  returns (snprintf truncation, call-1/2 failure, handle-parse).
- So the fix isn't "run more happy-path tests" — it's **drive the error
  returns under a detector**. That is this project's own fault-matrix
  discipline (`coverage is the wrong frame for resource-holding code;
  enumerate the fault matrix and check the empty cells`) applied to CI.

## Tiers

| Tier | Substrate | Command | What it adds |
|---|---|---|---|
| 0 | host / GitHub-hosted | existing workflows | build, cppcheck, CodeQL, unit (non-root), fuzz, mutation, ASan/UBSan build-link |
| 1 | booted-systemd container (rootful, isolated) | `make audit` | fault driver under ASan/LSan + real pamtester lifecycle under valgrind; **catches the frag_buf class** |
| 2 | virtme-ng microVM (real kernel, KVM) | `make audit-vm` | same audit under a real kernel + real cgroup hierarchy; optional kernel matrix |
| 3 | Coverity weekly + local cov-build | (existing) | path-sensitive inter-procedural static backstop |

Both tier 1 and tier 2 are **disposable and isolated** — they install a PAM
module and rewrite nftables, which must never happen on the dev host. The
container mutates nothing on the host; the microVM overlays the host rootfs
so its `groupadd`/`useradd`/`nft` writes are ephemeral.

## The fault matrix (tier 1)

`audit/nft_fault_driver.c` links the production objects under
`-fsanitize=address,undefined` and drives `nft_handler_setup`'s returns
directly, with a real PAM handle so the module's logging is safe. The
sanitizer — not the script — owns the leak verdict (the process exits
non-zero if LeakSanitizer finds a definite leak).

| Scenario | Drives | Detector |
|---|---|---|
| `happy` (in a real transient scope) | the success path + the success-path free | ASan/LSan |
| `truncate` (all session fields maxed) | the snprintf-truncation return; also **reports whether that path is reachable** given the struct field caps | ASan/LSan |
| `nftfail` (pre-created conflicting chain) | the call-1-failure return | ASan/LSan |
| pamtester open+close | the real production lifecycle | valgrind memcheck |

**Reachability finding.** The `truncate` scenario reports
`truncation-path-reachable=no`: with every session field maxed the command
stays under `CMD_BUF_SIZE`, so the line-311 truncation return is
**unreachable in production** — defensive hardening, not a live leak. The
live `frag_buf` leaks were the nft-failure returns. The fix was correct
either way; the harness pins the severity split.

**Negative control.** Reverting any one `free(frag_buf)` and re-running the
container audit turns it RED with LSan attributing the leak to
`read_file` / `nft_handler_setup` — through the library-noise suppressions.
That is the proof the green is real.

## Usage

```sh
make audit            # tier 1: container fault matrix + valgrind lifecycle
make audit-vm         # tier 2: same audit under a real kernel (vng)
make audit-all        # tiers 1 + 2
make install-hooks    # route git hooks at .githooks/; pre-commit runs tier 1
```

Kernel matrix (tier 2):

```sh
KERNELS="host v6.12 v6.6" make audit-vm   # vng downloads upstream kernels
```

commit-time gate (after `make install-hooks`):

```sh
git commit ...                       # code commits run tier-1 first; doc-only commits skip
AUTHNFT_SKIP_AUDIT=1 git commit ...  # skip once (use sparingly)
git push                             # no re-run by default
AUTHNFT_AUDIT_ON_PUSH=1 git push     # opt-in: re-run tier-1 at push
AUTHNFT_AUDIT_VM=1       git push    # opt-in: also run tier-2 microVM
```

The gate is **pre-commit**: every commit that touches `src/ include/ audit/
ci/ tests/ Makefile Containerfile mull.yml pam_authnft.map` runs the tier-1
audit and is blocked on failure. Doc-only commits skip it, so writing docs
stays instant.

## Files

```
audit/nft_fault_driver.c   fault driver (ASan/UBSan), drives the error returns
audit/malloc_fail.c        LD_PRELOAD fail-Nth-allocation interposer
audit/run-audit.sh         in-substrate orchestrator (container + vng)
ci/vng-audit.sh            tier-2 microVM runner (host kernel + matrix)
.githooks/pre-commit       runs tier-1 audit on every code commit
.githooks/pre-push         opt-in tier-1/tier-2 at push
Containerfile              'audit' workflow case
Makefile                   audit / audit-container / audit-vm / audit-all / install-hooks
```

## Honest coverage boundaries

- `happy` runs inside a transient scope; its detailed return code lands in
  the scope's own journal, not the workflow log (cosmetic).
- The call-2 and handle-parse returns are not yet fault-injected under the
  ASan driver (they need a libnftables-level fault); they are covered
  leak-free on the success path under valgrind, and on the call-1 path
  under ASan. Injecting them is the next refinement.
- `audit/malloc_fail.so` (fail-Nth-allocation interposer) is a **manual**
  targeted tool, not part of the automated gate: a blind sweep fails
  loader/libc/PAM startup allocations before any module code, so it cannot
  tell a module bug from process-startup noise. Use it to confirm a
  specific allocation-failure return (see the recipe in `run-audit.sh`).
- The seccomp sandbox is bypassed for the valgrind pass (`AUTHNFT_NO_SANDBOX`);
  valgrind and seccomp tangle. The filter is audited separately by the
  `trace` workflow and the negative seccomp tests.
- Tier 1 shares the host kernel under a nested cgroup namespace, so the
  socket-cgroupv2 packet-classification stages (10.11/10.12) that need a
  real cgroup hierarchy are a tier-2 concern.
