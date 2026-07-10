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
| 0 | host / GitHub-hosted | existing workflows | build, cppcheck, CodeQL, unit (non-root), fuzz, mutation, ASan/UBSan build-link + the `sanitized-tests` unit runtime under ASan/UBSan/LSan, reproducible-build check, and the THIRD_PARTY linked-library drift gate |
| 1 | booted-systemd container (rootful, isolated) | `make audit` / `make test-integration-container`; gated nightly by `integration.yml` | unit suite (seccomp SIGSYS enforcement) + all five nft_handler_setup returns under ASan/LSan + real lifecycle under valgrind + the 25-stage integration suite; **catches the frag_buf class** |
| 2 | virtme-ng microVM (real kernel, KVM) | `make audit-vm` / `make audit-vm-matrix`; gated nightly by `audit-vm.yml` (hosted runners carry `/dev/kvm` since 2024) | the socket-cgroupv2 packet-match invariants (`tests/packet_match_headless.sh`) plus the A+C audit, under a real, pinnable kernel + real cgroup hierarchy, swept across a kernel matrix. The full integration suite (Part B) is still excluded here (host coupling) |
| 3 | Coverity weekly + local cov-build | (existing) | path-sensitive inter-procedural static backstop |
| M | Alpine container (musl libc) | `make test-musl` | unit suite built against musl; catches libc-specific seccomp allowlist gaps (the open/readv/writev class) the glibc tiers cannot |

Both tier 1 and tier 2 are **disposable and isolated** — they install a PAM
module and rewrite nftables, which must never happen on the dev host. The
container mutates nothing on the host; the microVM overlays the host rootfs
so its `groupadd`/`useradd`/`nft` writes are ephemeral.

Tier M is orthogonal to the privilege tiers. The seccomp allowlist in
`src/sandbox.c` is derived from glibc syscall traces, and musl routes
several libc operations through different syscalls (`fopen` via `open(2)`
not `openat`, stdio via `readv`/`writev` not `read`/`write`). A glibc-only
CI cannot see those, so tier M rebuilds the unit suite against musl and runs
stage 13, which fails closed (SIGSYS) on a gap. It found the missing
`open`/`readv`/`writev` entries. `apk` inside the Alpine container is a
separate package set from the host.

## The fault matrix (tier 1)

`audit/nft_fault_driver.c` links the production objects under
`-fsanitize=address,undefined` and drives `nft_handler_setup`'s returns
directly, with a real PAM handle so the module's logging is safe. The
call-2 and handle-parse returns (which need call 1 to succeed first) are
driven by `audit/nft_fail.so`, an LD_PRELOAD interposer that fails the
jump-rule command or corrupts the echo handle. The sanitizer — not the
script — owns the leak verdict (the process exits non-zero if
LeakSanitizer finds a definite leak). All five returns are leak-free on
the current tree, and each is proven by negative control (revert its
`free` and the matching scenario flips red).

| Scenario | Drives | Detector |
|---|---|---|
| `happy` (in a real transient scope) | the success path + the success-path free | ASan/LSan |
| `truncate` (all session fields maxed) | the snprintf-truncation return; also **reports whether that path is reachable** given the struct field caps | ASan/LSan |
| `nftfail` (pre-created conflicting chain) | the call-1-failure return | ASan/LSan |
| `call2fail` (jump rule fails, via the nft interposer) | the call-2-failure return | ASan/LSan |
| `handleparse` (handle marker corrupted, via the nft interposer) | the handle-parse-failure return | ASan/LSan |
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
make test-musl        # tier M: unit suite built against musl (Alpine)
make install-hooks    # route git hooks at .githooks/; pre-commit runs tier 1
```

Kernel matrix (tier 2):

```sh
make audit-vm-matrix                      # host v6.8 v5.14 v6.12 latest
KERNELS="host v6.8 latest" make audit-vm  # or pick your own set
```

The default set maps to deployments: v6.8 (Ubuntu 24.04 LTS base), v5.14
(RHEL 9 base), v6.12 (RHEL 10 base, upstream LTS), plus the host kernel
and `latest` (newest tagged mainline build, resolved at run time by
ci/vng-audit.sh — tracks Linus's tree). The `host` kernel needs nothing
extra. Upstream kernels are fetched by virtme-ng as Ubuntu mainline
`.deb`s (vanilla kernels, so the RHEL entries approximate the base
version without Red Hat's backports) and need `dpkg` on the host to
unpack them; on Arch, `pacman -S dpkg` first (the host-kernel audit does
not require it).

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
audit/nft_fail.c           LD_PRELOAD libnftables interposer (call-2 / handle-parse)
audit/malloc_fail.c        LD_PRELOAD fail-Nth-allocation interposer (manual)
audit/run-all.sh           orchestrator: Part A unit/seccomp + Part C fault matrix
audit/run-audit.sh         in-substrate orchestrator (container + vng)
ci/vng-audit.sh            tier-2 microVM runner (host kernel + matrix)
ci/musl-test.sh            tier-M musl build + unit suite (Alpine container)
.githooks/pre-commit       runs tier-1 audit on every code commit
.githooks/pre-push         opt-in tier-1/tier-2 at push
Containerfile              'audit' workflow case
Makefile                   audit / audit-container / audit-vm / audit-all / install-hooks
```

## Honest coverage boundaries

- `happy` runs inside a transient scope; its detailed return code lands in
  the scope's own journal, not the workflow log (cosmetic).
- Seccomp enforcement is covered by Part A's unit suite (Stage 2 = a
  blocked syscall must SIGSYS; Stage 3 = an allowlisted syscall survives;
  Stage 13 = the setup-path libc syscall surface survives), which the audit
  runs with the sandbox active.
- The integration suite (25 stages) runs green in its own booted-systemd
  container via `make test-integration-container`; stages 10.19-10.24 cover
  the fork-child sandbox fix (the session fork survives the sandbox, orphan
  nft state is reaped, and fork/pipe/child-death faults fail the session
  closed). It is NOT wired into the every-commit audit gate: inside the
  `make audit` Part B path it is OPT-IN (AUDIT_RUN_INTEGRATION=1, off by
  default) because that substrate has host-environment coupling (umask,
  file ownership, a degraded systemd in the microVM) the dedicated
  container avoids. Wiring it into Part B is follow-on work; run it via
  `make test-integration-container` / `sudo make test-integration`.
- `audit/malloc_fail.so` (fail-Nth-allocation interposer) is a **manual**
  targeted tool, not part of the automated gate: a blind sweep fails
  loader/libc/PAM startup allocations before any module code, so it cannot
  tell a module bug from process-startup noise. Use it to confirm a
  specific allocation-failure return (see the recipe in `run-audit.sh`).
- The seccomp sandbox is bypassed for the valgrind pass (`AUTHNFT_NO_SANDBOX`);
  valgrind and seccomp tangle. The filter is audited separately by the
  `trace` workflow and the negative seccomp tests.
- Tier 1 shares the host kernel under a nested cgroup namespace, so the
  socket-cgroupv2 packet-classification stages (integration 10.11-10.13)
  that need a real cgroup hierarchy are a tier-2 concern. Their kernel
  behaviour is extracted into `tests/packet_match_headless.sh` — systemd +
  nft + ncat only, no pamtester/PAM/sshd — which tier 2 runs in each guest
  kernel, so the allowed/disallowed match, the alloc-time invariant, and
  per-session isolation are proven across the kernel matrix. Exit 77 there
  means the guest kernel lacks socket-cgroupv2 (skipped, not failed).
- The container image ships no sshd, so 10.25 runs only its pamtester
  control arm there and skips the sshd loopback arm; the full stage needs
  a host with sshd (any OpenSSH >= 9.8, for PAMServiceName).
