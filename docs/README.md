# Project documentation

| Document | Contents |
|---|---|
| [CONCEPTS.md](CONCEPTS.md) | Use cases, how the cgroupv2 match binds rules to sessions, integration surface |
| [ADMIN_GUIDE.md](ADMIN_GUIDE.md) | Quick start, configuration reference (module arguments, claims_env, PAM stack options, fragments, systemd controls), testing |
| [ARCHITECTURE.txt](ARCHITECTURE.txt) | Lifecycle, trust model, session identity, seccomp design, session-identity files, audit events |
| [INTEGRATIONS.txt](INTEGRATIONS.txt) | Stable contracts for producers and consumers: PAM stack (§1), claims_env keyring (§2), nft fragment composition (§4.6), systemd scopes (§5), session JSON (§5.6), structured journal events (§6.2), Linux audit-syscall events (§6.2.7) |
| [CONTRIBUTING.txt](CONTRIBUTING.txt) | Where help is wanted, build, layout, invariants, style, test procedures, seccomp allowlist derivation |
| [ROADMAP.md](ROADMAP.md) | What is stable now, what may change before 1.0, and what is planned |
| [TODO.txt](TODO.txt) | Near-term, medium-term, and deferred work items |
| [THIRD_PARTY.md](THIRD_PARTY.md) | Authoritative dependency inventory: licences, version floors, security feeds |
| [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) | Internal runbook for handling a security report (the public policy is [SECURITY.md](../SECURITY.md)) |
| [SECURITY_PRACTICES.md](SECURITY_PRACTICES.md) | Single-page overview of every security tool, doc, goal, and milestone in the project |
| [REPRODUCIBLE_BUILDS.md](REPRODUCIBLE_BUILDS.md) | What reproducibility we provide, what we don't, and how a packager verifies a release artefact |
| [FUZZ_SURFACE.md](FUZZ_SURFACE.md) | Fuzz-surface map: which functions are fuzzed, by which harness, at what coverage, and the bugs the harnesses found |
| [CI_LOCAL.md](CI_LOCAL.md) | Replicating the CI gates locally (the container audit tier, the fault matrix, the kernel packet-match check) |
| [../SECURITY.md](../SECURITY.md) | Vulnerability scope and reporting procedure |
