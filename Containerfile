# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Container image that runs every test surface the project ships —
# unit, integration, trace — inside a booted systemd environment. The
# host needs only podman or docker; no sudo, no host state mutation.
# The container boots systemd as PID 1 (required for the integration
# harness's sd-bus StartTransientUnit call), runs the requested
# workflow as a systemd oneshot unit, writes the exit code to a
# bind-mounted volume, and halts.
#
# Entry point: /sbin/init. Workflow selection is via the file at
# /shared/workflow which the Makefile bind-mounts before launch.
# Valid workflows: unit, integration, trace.
#
# Build:
#   podman build -t pam_authnft-test -f Containerfile .
#
# Run (see `make test-*-container` targets for canonical invocations):
#   mkdir -p ./result
#   echo integration > ./result/workflow
#   podman run --rm --systemd=always \
#       --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
#       --security-opt label=disable \
#       --security-opt seccomp=unconfined \
#       -v "$PWD:/src:ro,Z" \
#       -v "$PWD/result:/shared:Z" \
#       pam_authnft-test
#   cat ./result/exit

FROM registry.fedoraproject.org/fedora:latest

RUN dnf -y install \
        gcc \
        libasan \
        libubsan \
        make \
        pkgconf-pkg-config \
        nftables \
        nftables-devel \
        libseccomp-devel \
        systemd \
        systemd-devel \
        libcap-devel \
        audit-libs-devel \
        pam-devel \
        pamtester \
        valgrind \
        keyutils \
        strace \
        checksec \
        nmap-ncat \
        openssl \
        procps-ng \
        util-linux \
        sudo \
        git \
        diffutils \
        which \
    && dnf clean all

# Workflow runner. Reads /shared/workflow, copies /src -> /build,
# executes the target make goals, writes the exit code to
# /shared/exit. Halts systemd at the end so the container exits
# cleanly on `podman run --rm`.
RUN cat > /usr/local/bin/run-workflow <<'EOF' \
 && chmod +x /usr/local/bin/run-workflow
#!/bin/bash
set -uo pipefail
WORKFLOW=$(cat /shared/workflow 2>/dev/null || echo unit)
echo "=== Workflow: $WORKFLOW ==="

cp -a /src/. /build/
cd /build

EC=0
case "$WORKFLOW" in
    unit)
        make clean && make && make test || EC=$?
        ;;
    integration)
        # We are root inside the container — skip the sudo that
        # Makefile's test-integration target prefixes onto each
        # command. sudo under a systemd unit with no tty either
        # requires a relaxed sudoers (Defaults !requiretty) or
        # drops stdout into the void. Invoking the scripts
        # directly is cleaner.
        make clean && make && make test \
          && ./tests/integration_test.sh "$(pwd)/pam_authnft.so" \
          && AUTHNFT_AUDIT_MODE=1 valgrind \
                --leak-check=full --show-leak-kinds=all \
                --error-exitcode=1 ./authnft_test \
          || EC=$?
        ;;
    trace)
        make clean && make && ./tests/trace.sh "$(pwd)/pam_authnft.so" || EC=$?
        cp -f trace.log trace-claims.log /shared/ 2>/dev/null || true
        ;;
    audit)
        # Comprehensive local audit: unit suite (seccomp enforcement) +
        # integration suite (16 stages) + fault matrix (nft_handler_setup
        # error returns under ASan/LSan + lifecycle under valgrind). Covers
        # every gate the hosted CI cannot run for want of root/nft/systemd/
        # cgroup. Aggregated verdict in EC.
        ./audit/run-all.sh || EC=$?
        cp -f /tmp/vg.log /shared/valgrind.log 2>/dev/null || true
        cp -f /tmp/asan_authnft.* /tmp/scen-*.out /shared/ 2>/dev/null || true
        ;;
    trace-features)
        make clean && make && make trace-features || EC=$?
        cp -f trace-features.log /shared/ 2>/dev/null || true
        ;;
    investigate)
        # Identify call stacks for specific syscalls observed on
        # Fedora but not on Arch (getuid, geteuid, statfs).
        # Reuses trace.sh's test user + PAM config setup inline.
        make clean >/dev/null && make >/dev/null
        mkdir -p /etc/authnft/users
        getent group authnft >/dev/null || groupadd authnft
        getent passwd authnft-test >/dev/null \
          || useradd -r -s /usr/sbin/nologin -G authnft authnft-test
        echo 'add rule inet authnft @session_chain socket cgroupv2 level 2 . ip saddr @session_v4 accept' \
          > /etc/authnft/users/authnft-test
        chown root:root /etc/authnft/users/authnft-test
        chmod 644 /etc/authnft/users/authnft-test
        cat > /etc/pam.d/authnft_test <<'PAM'
auth     required  pam_permit.so
account  required  pam_permit.so
session  required  /build/pam_authnft.so
password required  pam_deny.so
PAM
        AUTHNFT_NO_SANDBOX=1 strace -f -k \
            -e trace=geteuid,getuid,statfs \
            -o /shared/investigate.log \
            pamtester -I rhost=127.0.0.1 authnft_test authnft-test \
            open_session close_session >/dev/null 2>&1 || true
        ;;
    *)
        echo "Unknown workflow: $WORKFLOW" >&2
        EC=2
        ;;
esac

echo "$EC" > /shared/exit
# Dump what the test actually printed into the volume so the host
# sees it without needing to pull logs from the journal.
journalctl -u authnft-workflow.service --no-pager -o cat > /shared/log 2>&1 || true
sync
systemctl --no-block poweroff
EOF

RUN mkdir -p /etc/systemd/system && \
    cat > /etc/systemd/system/authnft-workflow.service <<'EOF'
[Unit]
Description=pam_authnft test workflow runner
After=basic.target
Wants=basic.target

[Service]
Type=oneshot
RemainAfterExit=no
ExecStart=/usr/local/bin/run-workflow
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=600

[Install]
WantedBy=multi-user.target
EOF

RUN systemctl enable authnft-workflow.service \
 && mkdir -p /build /shared

ENTRYPOINT ["/sbin/init"]
