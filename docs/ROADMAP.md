# Stability and roadmap

**Stable now**: the PAM interface (exactly two exported symbols), the three
nftables set types and their schemas, the fragment ownership model
(`st_uid == 0`, no world-writable), the element comment grammar documented
in [INTEGRATIONS.txt §6.1](INTEGRATIONS.txt), the session-identity
JSON schema (`v=2`, §5.6), the structured journald audit fields (§6.2),
and the Linux audit-syscall channel
(`AUDIT_USER_ERR` with reason tags `missing | perms | content | nft-syntax`,
§6.2.7).

**May change before 1.0**: `claims_env` wire format details,
`rhost_policy=kernel` NETLINK internals, `authnft.slice` shipped defaults.

**Planned**: OSS-Fuzz registration (project files staged at
[../tests/fuzz/oss-fuzz/](../tests/fuzz/oss-fuzz/), submission gated on
project age), a fragment linter (wraps the libnftables dry run),
pluggable fragment sources, and packaging for Arch (AUR) and Debian.
See [TODO.txt](TODO.txt) for the full list.
