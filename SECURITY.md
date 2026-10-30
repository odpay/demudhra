# Security and trust boundaries

demudhra changes certificate trust. Every run lists what it found and asks before
removing anything. The only removal authority is locally computed
SHA-256 of DER, compared with the selected table. Subject names and Java/NSS
aliases are never certificate identities; aliases become selectors only after
fingerprint verification.

The wrapper is the user's trust root. Release builds stamp the immutable HTTPS
base URL and SHA-256 of both platform scripts and the fingerprint table into it.
Matching those pins proves downloaded payload bytes match the wrapper.
A compromised payload plus a rewritten SHA256SUMS is rejected. A compromised
wrapper can replace both code and pins, so this does not authenticate that wrapper;
it is fetched over HTTPS from demudhra.sh. The cohosted manifest provides no separate authenticity. This project ships no
signing key and makes no signed-release claim.

The installed shell, OpenSSL, native store tools, updater programs, and `PATH` are
trusted. A privileged removal is unsuitable for a directory tree actively writable
by an adversary. Byte rechecks catch tested concurrent updates, but they do not
eliminate all filesystem races. Close browsers, JVM store writers, and Keychain
Access before confirming removal or undo. There is no global transaction or crash recovery
across several stores. Earlier successful removals may remain after exit 2.

Backup directories are private and may contain private keys, keychains, and other
credentials from native store snapshots. Undo replaces saved files and sometimes
whole generated-output directories. Review its commands and avoid undo after
unrelated changes. No backup or machine inventory is transmitted by the tool.

Discovery has documented path and format limits. Compiled-in roots, inaccessible
stores, browser root programs, and running processes can continue using roots
that a file edit does not affect. Keep upstream security updates current and
restart consumers. A clean scan is not proof that every application is protected.

For a security report, provide a minimal temporary-root reproduction, script
version, platform, and redacted output through the repository's security-reporting
channel when one is configured. Do not attach real keychains, keystores, passwords,
or backup directories. No private reporting address is configured in this checkout.
