<!-- Thanks for contributing. Keep this focused; unrelated cleanups belong in separate PRs. -->

## Summary

<!-- One or two sentences on what this changes and why. -->

## Invariants touched

<!--
If your change affects any of the following, describe how and why it's safe.
Otherwise, write "none".

- Exported symbol set (src/pam_authnft.map)
- Lifecycle ordering in pam_sm_open_session / pam_sm_close_session
- Session-data persistence via pam_set_data
- Seccomp allowlist (src/sandbox.c)
- Fragment permission check (st_uid == 0 && !world-writable)
- Two-call nftables transaction (element insert before fragment include)
- Error asymmetry (open = strict, close = best-effort)
-->

## Tests

- [ ] `make clean && make` passes with the release hardening flag set
- [ ] `make test` passes, including the stage-0 symbol whitelist check
- [ ] `sudo make test-integration` passes — or explain why it doesn't apply
- [ ] If a guarded invariant is touched (see docs/CONTRIBUTING.txt
      "Invariant guards"), the corresponding test was re-run and is noted above
- [ ] New syscalls reached from handlers are accompanied by `make trace`
      evidence and an entry in `src/sandbox.c`

## Notes for the reviewer

<!-- Anything subtle, anything you'd like a second pair of eyes on. -->
