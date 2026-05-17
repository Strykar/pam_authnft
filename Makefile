# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar

.POSIX:

CC         = gcc
PKG_CONFIG = pkg-config
PAM_DIR    = /usr/lib/security
MAN_DIR    = /usr/share/man/man8
PANDOC     = pandoc
TEST_USER  ?= authnft-test
TMPFILES_DIR = /usr/lib/tmpfiles.d
CFLAGS     =

LIBS      = libnftables libseccomp libsystemd pam libcap audit

HARDENING = -fstack-clash-protection \
            -fcf-protection \
            -ftrivial-auto-var-init=zero \
            -fstack-protector-strong \
            -Wformat -Wformat-security \
            -Werror=implicit-fallthrough \
            -fno-strict-overflow \
            -Wtrampolines

CFLAGS_BASE  = -fPIC -Wall -Wextra -O2 -Iinclude -D_GNU_SOURCE $(HARDENING)
LDFLAGS_BASE = -Wl,-z,relro,-z,now
SO_LDFLAGS   = $(LDFLAGS_BASE) -shared -Wl,--version-script=pam_authnft.map

TARGET   = pam_authnft.so
TEST_BIN = authnft_test
OBJ_DIR  = obj

OBJS = $(OBJ_DIR)/audit.o         \
       $(OBJ_DIR)/bus_handler.o   \
       $(OBJ_DIR)/event.o         \
       $(OBJ_DIR)/keyring.o       \
       $(OBJ_DIR)/nft_handler.o   \
       $(OBJ_DIR)/pam_entry.o     \
       $(OBJ_DIR)/peer_lookup.o   \
       $(OBJ_DIR)/sandbox.o       \
       $(OBJ_DIR)/session_file.o

all: $(TARGET)

debug:
	@$(MAKE) clean --no-print-directory
	@$(MAKE) CFLAGS_BASE="$(CFLAGS_BASE) -DDEBUG -g" all --no-print-directory

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS_BASE) `$(PKG_CONFIG) --cflags $(LIBS)` $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(SO_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS) `$(PKG_CONFIG) --libs $(LIBS)`

# Unit tests — no root required. Stages that need CAP_NET_ADMIN skip gracefully.
# Includes the differential-oracle harness (Phase 4.1 of the security plan)
# which cross-validates the small parsers against an independent Python
# implementation. Catches logic bugs that ASan-class fuzzing cannot find.
test: test-symbols test-oracle $(TEST_BIN)
	./$(TEST_BIN)

# Invariant guard #7: exported symbols must be exactly the two PAM entry points.
# Catches missing `static`, accidental re-exports, and broken version scripts.
test-symbols: $(TARGET)
	@echo "[STAGE 0] Exported symbol whitelist..."
	@exported=$$(nm -D --defined-only $(TARGET) | awk '$$2=="T"{print $$3}' | sort | xargs); \
	expected="pam_sm_close_session pam_sm_open_session"; \
	if [ "$$exported" = "$$expected" ]; then \
	    echo "[PASS] exactly two symbols exported"; \
	else \
	    echo "[FAIL] expected \"$$expected\", got \"$$exported\""; \
	    exit 1; \
	fi

# Differential oracle harness — Phase 4.1 of the security plan.
# Cross-validates pam_authnft's small parsers against an independent
# Python re-implementation. Catches logic bugs (wrong-but-plausible
# answers) that ASan-class fuzzing cannot find. No root required.
ORACLE_RUNNER = tests/oracle/oracle_runner

# The oracle runner targets several helpers that are file-static in
# production (validate_cgroup_path, keyring_sanitize, corr_sanitize_copy).
# Compile every src/*.c with -DFUZZ_BUILD so the static qualifier is
# stripped — same pattern the libFuzzer harnesses use. The production
# pam_authnft.so build path (no -DFUZZ_BUILD) is unaffected.
$(ORACLE_RUNNER): tests/oracle/oracle_runner.c $(wildcard src/*.c) include/authnft.h
	$(CC) $(CFLAGS_BASE) `$(PKG_CONFIG) --cflags $(LIBS)` -DFUZZ_BUILD -g -O1 \
	    tests/oracle/oracle_runner.c $(wildcard src/*.c) -o $@ \
	    `$(PKG_CONFIG) --libs $(LIBS)`

test-oracle: $(ORACLE_RUNNER)
	./tests/oracle/run.sh

# Audit aid for invariant guard #5 (seccomp allowlist provenance).
# Runs one pamtester open+close cycle under `strace -f -c` with the sandbox
# bypassed, producing a syscall summary in trace.log. This is NOT a gate —
# review the summary and diff against SCMP_SYS(...) in src/sandbox.c before
# adding any syscall to the allowlist.
trace: $(TARGET)
	@command -v strace >/dev/null || { echo "strace not installed"; exit 1; }
	@command -v pamtester >/dev/null || { echo "pamtester not installed"; exit 1; }
	sudo ./tests/trace.sh $(CURDIR)/$(TARGET)

# Feature-path companion to `make trace`. Runs the unit suite under
# `strace -f -c` to catalogue syscalls issued by code paths that the
# pamtester-driven trace cannot easily exercise (rhost_policy=kernel
# sock_diag, claims_env keyctl read). Output: trace-features.log plus a
# diff-friendly report on stderr identifying test-harness-only syscalls.
# No root required; no system state modified.
trace-features: $(TEST_BIN)
	@command -v strace >/dev/null || { echo "strace not installed"; exit 1; }
	./tests/trace_features.sh

$(TEST_BIN): $(TARGET)
	$(CC) $(CFLAGS_BASE) $(LDFLAGS_BASE) -g -O1 \
	    tests/test_suite.c $(OBJS) -o $(TEST_BIN) \
	    `$(PKG_CONFIG) --libs $(LIBS)`

# Integration tests — requires root (pamtester, nftables, systemd, valgrind).
# Runs the full session open/close cycle against the live system.
test-integration: $(TEST_BIN)
	sudo ./tests/integration_test.sh $(CURDIR)/$(TARGET)
	sudo -E AUTHNFT_AUDIT_MODE=1 valgrind \
	    --leak-check=full --show-leak-kinds=all --error-exitcode=1 \
	    ./$(TEST_BIN)
	@sudo chown -R $$(id -u):$$(id -g) . 2>/dev/null; true

# Containerised workflows. Every test surface the project ships runs
# inside a booted-systemd container on any host with podman or docker
# — no sudo required, no host state mutation.
#
# The container's PID 1 is systemd; a oneshot unit (authnft-workflow)
# reads /shared/workflow, executes the corresponding make goals,
# writes the exit code to /shared/exit, and halts the container.
# The host-side Makefile recipe reads the exit code back.

CONTAINER_IMG = pam_authnft-test
CONTAINER_BUILD = @command -v podman >/dev/null || { echo "podman not installed"; exit 1; } \
                  ; podman build -t $(CONTAINER_IMG) -f Containerfile . >/dev/null

# Common podman invocation. Callers set RESULT_DIR to a host path
# that will be bind-mounted to /shared, and populate
# $(RESULT_DIR)/workflow with the workflow name before calling.
define RUN_CONTAINER
	podman run --rm \
	    --systemd=always \
	    --cap-add=NET_ADMIN \
	    --cap-add=SYS_ADMIN \
	    --security-opt label=disable \
	    --security-opt seccomp=unconfined \
	    -v $(CURDIR):/src:ro,Z \
	    -v $(RESULT_DIR):/shared:Z \
	    $(CONTAINER_IMG) >/dev/null
	@echo "=== workflow output ==="
	@cat $(RESULT_DIR)/log 2>/dev/null || echo "(no log captured)"
	@EC=$$(cat $(RESULT_DIR)/exit 2>/dev/null || echo 1); \
	 echo "=== container exit: $$EC ==="; \
	 exit $$EC
endef

# Unit tests inside the container (`make test` — 10 stages, all with
# CAP_NET_ADMIN so no stages SKIP on that account).
test-container: RESULT_DIR = $(CURDIR)/.container-result
test-container:
	$(CONTAINER_BUILD)
	@mkdir -p $(RESULT_DIR) && echo unit > $(RESULT_DIR)/workflow
	$(RUN_CONTAINER)

# Full pamtester integration flow inside the container. systemd
# is running as PID 1, so StartTransientUnit over sd-bus works.
# This replaces `sudo make test-integration` as the default
# integration-test path.
test-integration-container: RESULT_DIR = $(CURDIR)/.container-result
test-integration-container:
	$(CONTAINER_BUILD)
	@mkdir -p $(RESULT_DIR) && echo integration > $(RESULT_DIR)/workflow
	$(RUN_CONTAINER)

# Seccomp allowlist trace inside the container. Produces
# trace.log and trace-claims.log, which are copied out to
# $(RESULT_DIR). Replaces `sudo make trace` as the default path.
trace-container: RESULT_DIR = $(CURDIR)/.container-result
trace-container:
	$(CONTAINER_BUILD)
	@mkdir -p $(RESULT_DIR) && echo trace > $(RESULT_DIR)/workflow
	$(RUN_CONTAINER)

# Software Bill of Materials. On-demand generation via syft, which
# parses the .so's DT_NEEDED entries plus build metadata. Output is
# CycloneDX 1.5 JSON suitable for upload alongside a GitHub release
# artefact. Hand-curated dependency inventory (license, version
# floors, security feeds) lives at docs/THIRD_PARTY.md and is the
# authoritative document for OSTIF compliance §5.
SBOM = pam_authnft.cdx.json

sbom: $(SBOM)

$(SBOM): $(TARGET)
	@command -v syft >/dev/null || { echo "syft required: https://github.com/anchore/syft"; exit 1; }
	syft scan file:$(TARGET) -o cyclonedx-json=$(SBOM)
	@echo "SBOM written to $(SBOM)"
	@echo "(human-readable dependency inventory: docs/THIRD_PARTY.md)"

# Reproducibility check — build pam_authnft.so twice on this host and
# verify the artefact is bit-identical. OSTIF best-practices §3
# ("reproducible builds where feasible") + supply-chain assurance: a
# known-good binary hash means a downstream packager can verify their
# build matches the upstream source without trusting the build
# infrastructure. Cross-machine reproducibility additionally requires
# identical toolchain (compiler version, libc, binutils) — see
# docs/REPRODUCIBLE_BUILDS.md.
reproducibility-check:
	@h1=$$($(MAKE) clean >/dev/null && $(MAKE) >/dev/null && sha256sum $(TARGET) | awk '{print $$1}'); \
	h2=$$($(MAKE) clean >/dev/null && $(MAKE) >/dev/null && sha256sum $(TARGET) | awk '{print $$1}'); \
	if [ "$$h1" = "$$h2" ]; then \
	    echo "[PASS] reproducible same-machine: $$h1"; \
	else \
	    echo "[FAIL] non-reproducible:"; \
	    echo "  build 1: $$h1"; \
	    echo "  build 2: $$h2"; \
	    exit 1; \
	fi

# Mutation testing — Phase 4.3 of the security audit plan. Uses
# mull (https://github.com/mull-project/mull), the LLVM-IR mutation
# tester. Same toolchain class as `make fuzz` (clang + LLVM).
#
# A surviving mutation = a line whose IR-level change wasn't caught
# by any test. Two interpretations:
#   - coverage gap: add a test that catches the change
#   - dead code:   the line has no observable effect
#
# Mull operates by embedding LLVM bitcode into the test binary at
# compile time (via -fpass-plugin=$(mull --print-pass-plugin-path))
# and then mutating that bitcode in-process at run time. Each
# mutation re-runs the binary; mull tallies kills and survivors.
#
# Requires: mull (mull-runner, mull-cxx) and a matching clang.
# Install:
#   Debian/Ubuntu: https://app.packagecloud.io/mull-project/mull-stable
#   Arch:          AUR `mull` or `mull-bin`
#
# The CI workflow .github/workflows/mutation.yml installs mull from
# the project's PackageCloud DEB repo and runs this target weekly.
MULL_CXX    ?= mull-cxx
MULL_RUNNER ?= mull-runner

mutation-report: $(TEST_BIN).mull
	@command -v $(MULL_RUNNER) >/dev/null 2>&1 || { \
	    echo "$(MULL_RUNNER) not in PATH — install mull first."; \
	    echo "  Debian/Ubuntu: https://app.packagecloud.io/mull-project/mull-stable"; \
	    echo "  Arch:          AUR mull / mull-bin"; \
	    exit 1; \
	}
	$(MULL_RUNNER) ./$(TEST_BIN).mull

# Build the test binary using mull-cxx, the documented clang wrapper
# that embeds LLVM bitcode and injects mull's pass plugin. Avoids
# guessing the plugin path or wiring -fembed-bitcode-marker by hand
# — mull-cxx handles the LLVM↔mull plumbing for the LLVM major it
# was packaged against.
$(TEST_BIN).mull: tests/test_suite.c $(wildcard src/*.c) include/authnft.h
	@command -v $(MULL_CXX) >/dev/null 2>&1 || { \
	    echo "$(MULL_CXX) not in PATH — install mull first (see comment above)."; \
	    exit 1; \
	}
	$(MULL_CXX) $(CFLAGS_BASE) `$(PKG_CONFIG) --cflags $(LIBS)` -g -O0 \
	    tests/test_suite.c $(wildcard src/*.c) -o $@ \
	    `$(PKG_CONFIG) --libs $(LIBS)`

install: $(TARGET) install-tmpfiles
	sudo mkdir -p /etc/authnft/users
	sudo install -m 755 $(TARGET) $(PAM_DIR)/$(TARGET)
	sudo install -m 644 data/authnft.slice /etc/systemd/system/authnft.slice
	sudo systemctl daemon-reload

# tmpfiles.d snippet creates /run/authnft/sessions/ at boot and reaps
# stale per-session JSON files older than 7 days. See data/authnft.tmpfiles
# and docs/INTEGRATIONS.txt §5.6.
install-tmpfiles:
	sudo install -d $(TMPFILES_DIR)
	sudo install -m 644 data/authnft.tmpfiles $(TMPFILES_DIR)/authnft.conf
	sudo systemd-tmpfiles --create $(TMPFILES_DIR)/authnft.conf

uninstall:
	sudo rm -f $(PAM_DIR)/$(TARGET)
	sudo rm -f $(MAN_DIR)/pam_authnft.8.gz
	sudo rm -f $(TMPFILES_DIR)/authnft.conf

# Manpage — requires pandoc. Builds pam_authnft.8 from man/pam_authnft.8.md.
man: man/pam_authnft.8

man/pam_authnft.8: man/pam_authnft.8.md
	$(PANDOC) -s -t man $< -o $@

install-man: man/pam_authnft.8
	sudo install -d $(MAN_DIR)
	sudo install -m 644 man/pam_authnft.8 $(MAN_DIR)/pam_authnft.8
	sudo gzip -f $(MAN_DIR)/pam_authnft.8

# Fuzz targets — requires clang + compiler-rt (libFuzzer).
# Builds harnesses with ASan + libFuzzer into fuzz/out/. Run a target
# directly to start fuzzing, optionally with a corpus directory.
# Surface and status: docs/FUZZ_SURFACE.md.
FUZZ_CC  = clang
FUZZ_OUT = fuzz/out
FUZZ_COMMON = -g -O1 -Iinclude -D_GNU_SOURCE -DFUZZ_BUILD \
              -fsanitize=address -fno-omit-frame-pointer

# Harness source files live at fuzz/fuzz_<name>.c. To add a new harness,
# drop the source in fuzz/ and append the binary path here.
FUZZ_TARGETS = $(FUZZ_OUT)/fuzz_username \
               $(FUZZ_OUT)/fuzz_fragment \
               $(FUZZ_OUT)/fuzz_substitute_placeholders \
               $(FUZZ_OUT)/fuzz_netlink_diag \
               $(FUZZ_OUT)/fuzz_keyring_sanitize \
               $(FUZZ_OUT)/fuzz_correlation_capture \
               $(FUZZ_OUT)/fuzz_cgroup_path \
               $(FUZZ_OUT)/fuzz_socket_inode

FUZZ_SRC_OBJS = $(patsubst src/%.c,$(FUZZ_OUT)/obj/%.o,$(wildcard src/*.c))

$(FUZZ_OUT)/obj/%.o: src/%.c
	@mkdir -p $(FUZZ_OUT)/obj
	$(FUZZ_CC) $(FUZZ_COMMON) -fsanitize=fuzzer-no-link \
	    `$(PKG_CONFIG) --cflags $(LIBS)` -c $< -o $@

$(FUZZ_OUT)/fuzz_%: fuzz/fuzz_%.c $(FUZZ_SRC_OBJS)
	@mkdir -p $(FUZZ_OUT)
	$(FUZZ_CC) $(FUZZ_COMMON) -fsanitize=fuzzer \
	    `$(PKG_CONFIG) --cflags $(LIBS)` \
	    $< $(FUZZ_SRC_OBJS) \
	    `$(PKG_CONFIG) --libs $(LIBS)` \
	    -o $@

fuzz: $(FUZZ_TARGETS)
	@echo "Fuzz targets ready in $(FUZZ_OUT)/:"
	@for t in $(FUZZ_TARGETS); do echo "  ./$$t"; done

# Coverage measurement — builds harnesses with -fprofile-instr-generate
# -fcoverage-mapping (separate from `make fuzz` since coverage flags are
# load-bearing across the whole link). Runs each harness for ~10s,
# merges profdata, generates HTML at docs/fuzz-coverage/index.html and
# a text summary on stdout. The 90% per-harness coverage bar is the
# threshold for promoting a row in docs/FUZZ_SURFACE.md from 🟡 to ✅.
#
# Build artefacts (objects, harness binaries, .profraw, .profdata) live
# under FUZZ_COV_OUT and ARE wiped by `make clean`. The HTML report under
# FUZZ_COV_HTML is preserved across `make clean` so it can be browsed
# without rebuilding.
FUZZ_COV_OUT  = fuzz/coverage
FUZZ_COV_HTML = docs/fuzz-coverage
# -ffile-prefix-map keeps absolute paths to the source tree out of the
# debug info / coverage mapping, so the generated HTML filenames are
# repo-relative (e.g. src/foo.c.html) instead of leaking the developer's
# home directory.
FUZZ_COV_CFLAGS = $(FUZZ_COMMON) -fprofile-instr-generate -fcoverage-mapping \
                  -fcoverage-prefix-map=$(CURDIR)/=

fuzz-coverage:
	@command -v llvm-profdata >/dev/null 2>&1 || { echo "llvm-profdata required"; exit 1; }
	@command -v llvm-cov      >/dev/null 2>&1 || { echo "llvm-cov required"; exit 1; }
	@rm -rf $(FUZZ_COV_OUT)
	@mkdir -p $(FUZZ_COV_OUT)/obj
	@for f in src/*.c; do \
	    $(FUZZ_CC) $(FUZZ_COV_CFLAGS) -fsanitize=fuzzer-no-link \
	        `$(PKG_CONFIG) --cflags $(LIBS)` \
	        -c "$$f" -o "$(FUZZ_COV_OUT)/obj/$$(basename $${f%.c}).o" || exit 1; \
	done
	@for h in $(notdir $(FUZZ_TARGETS)); do \
	    $(FUZZ_CC) $(FUZZ_COV_CFLAGS) -fsanitize=fuzzer \
	        `$(PKG_CONFIG) --cflags $(LIBS)` \
	        fuzz/$$h.c $(FUZZ_COV_OUT)/obj/*.o \
	        `$(PKG_CONFIG) --libs $(LIBS)` \
	        -o $(FUZZ_COV_OUT)/$$h || exit 1; \
	done
	@# Each harness reads its seed/regression corpus from
	@# fuzz/corpus/<harness-stem>/ (e.g., fuzz_fragment uses
	@# fuzz/corpus/fragment/). Seeds materially improve coverage in the
	@# 10s window — without them the IPv6 v4-mapped path, glob-in-include
	@# path, and similar narrow branches stay unhit.
	@for h in $(notdir $(FUZZ_TARGETS)); do \
	    corpus="fuzz/corpus/$${h#fuzz_}"; \
	    [ -d "$$corpus" ] || corpus=""; \
	    echo ">>> running $$h for 10s (corpus: $${corpus:-none})"; \
	    LLVM_PROFILE_FILE=$(FUZZ_COV_OUT)/$$h.profraw \
	        $(FUZZ_COV_OUT)/$$h -max_total_time=10 \
	        -artifact_prefix=$(FUZZ_COV_OUT)/$$h- \
	        $$corpus \
	        >/dev/null 2>&1 || true; \
	done
	llvm-profdata merge -sparse $(FUZZ_COV_OUT)/*.profraw \
	    -o $(FUZZ_COV_OUT)/merged.profdata
	@# Atomic-swap the HTML report so a developer browsing
	@# docs/fuzz-coverage/index.html never sees a missing or
	@# half-written file during regeneration. Render to a sibling
	@# directory, then mv-in-place. README.md + .gitignore stay put.
	@rm -rf $(FUZZ_COV_HTML).new $(FUZZ_COV_HTML).old
	@mkdir -p $(FUZZ_COV_HTML).new
	@first=$$(echo $(FUZZ_TARGETS) | awk '{print $$1}'); \
	    llvm-cov show $(FUZZ_COV_OUT)/$$(basename $$first) \
	        -instr-profile=$(FUZZ_COV_OUT)/merged.profdata \
	        -format=html -output-dir=$(FUZZ_COV_HTML).new \
	        --ignore-filename-regex='/usr/.*|fuzz/.*' \
	        src/
	@# llvm-cov bakes the absolute build path into the output filename
	@# tree and into HTML hrefs. Flatten the per-source tree to
	@# coverage/src/ and strip $(CURDIR)/ from every HTML body so the
	@# committed report is portable across clones — fresh checkouts on
	@# any path still render correctly on GitHub.
	@if [ -d "$(FUZZ_COV_HTML).new/coverage$(CURDIR)" ]; then \
	    mkdir -p "$(FUZZ_COV_HTML).new/coverage-flat"; \
	    cp -r "$(FUZZ_COV_HTML).new/coverage$(CURDIR)/src" "$(FUZZ_COV_HTML).new/coverage-flat/src"; \
	    rm -rf "$(FUZZ_COV_HTML).new/coverage"; \
	    mv "$(FUZZ_COV_HTML).new/coverage-flat" "$(FUZZ_COV_HTML).new/coverage"; \
	fi
	@# Two passes: first fix hrefs of the form coverage/<abs-path>/src/...
	@# (llvm-cov concatenates coverage/ with the absolute source path,
	@# eating the leading slash), then strip any remaining $(CURDIR)/
	@# occurrences from displayed file paths.
	@find $(FUZZ_COV_HTML).new -name '*.html' -exec sed -i \
	    -e 's|coverage$(CURDIR)/|coverage/|g' \
	    -e 's|$(CURDIR)/||g' \
	    {} +
	@# Now atomic-swap the freshly-rendered tree into place. The
	@# committed README.md and .gitignore are copied across so they
	@# survive the swap. The previous report is moved aside, then
	@# removed only after the new one is in place.
	@cp $(FUZZ_COV_HTML)/README.md   $(FUZZ_COV_HTML).new/ 2>/dev/null || true
	@cp $(FUZZ_COV_HTML)/.gitignore  $(FUZZ_COV_HTML).new/ 2>/dev/null || true
	@if [ -d $(FUZZ_COV_HTML) ]; then \
	    mv $(FUZZ_COV_HTML) $(FUZZ_COV_HTML).old; \
	fi
	@mv $(FUZZ_COV_HTML).new $(FUZZ_COV_HTML)
	@rm -rf $(FUZZ_COV_HTML).old
	@echo
	@echo "=== coverage summary ==="
	@first=$$(echo $(FUZZ_TARGETS) | awk '{print $$1}'); \
	    llvm-cov report $(FUZZ_COV_OUT)/$$(basename $$first) \
	        -instr-profile=$(FUZZ_COV_OUT)/merged.profdata \
	        --ignore-filename-regex='/usr/.*|fuzz/.*' \
	        src/
	@echo
	@echo "HTML report: $(FUZZ_COV_HTML)/index.html"

# clean intentionally does NOT wipe $(FUZZ_COV_HTML) — the report is the
# committed artefact, browsable without rebuilding. Re-run
# `make fuzz-coverage` to refresh.
clean:
	rm -rf $(OBJ_DIR) $(FUZZ_OUT) $(FUZZ_COV_OUT) $(TARGET) $(TEST_BIN) $(TEST_BIN).mull $(ORACLE_RUNNER) $(SBOM) *.d rules.tmp trace.log trace-claims.log trace-features.log man/pam_authnft.8 .container-result

distclean: clean
	@if sudo nft list tables 2>/dev/null | grep -q "inet authnft"; then \
	    sudo nft delete table inet authnft; \
	fi
	@sudo rm -f /etc/pam.d/authnft_test /etc/authnft/users/$(TEST_USER)

.PHONY: all debug clean fuzz fuzz-coverage reproducibility-check sbom mutation-report test test-oracle test-symbols test-integration test-container \
        test-integration-container trace trace-container trace-features \
        distclean install install-tmpfiles uninstall man install-man
