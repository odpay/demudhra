# Changelog

## [0.1.1] - 2026-10-29

- Expand bounded default scans to developer tools, macOS app bundles, Homebrew,
  MacPorts, version managers, Python tools and conda distributions, cloud CLIs,
  editor extensions, and additional Linux OpenSSL and Java stores.
- Discover explicit CA paths from runtime environment variables and read-only
  git, npm, pip, curl, and wget configuration. Include hashed `SSL_CERT_DIR`
  entries, `JAVA_HOME`, and every Java executable on PATH.
- Remove Apple-format subject and certificate headers with fingerprint-selected
  certificates, then re-parse the applied bundle. Explain Apple's existing app
  protection, command-line exposure, update resets, and optional AAA removal.
- Report Node, Go, Deno, Bun, and Rust toolchain versions on labelled lines and
  count runtimes whose compiled roots require an update. Go is not counted: it
  uses the system trust store, which demudhra cleans, unless a binary embeds its
  own roots.
- Show the install command as `curl -fsSL https://demudhra.sh/run | sh` everywhere.
- Build v0.1.1 with verified wrapper pins and keep v0.1.0 unchanged. Add
  disposable-root coverage for each new discovery class, Apple-format headers,
  literal config paths, and post-apply verification failures.
- State certificate counts the same way everywhere: 43 in the list, 17 by default,
  42 with `--all-emudhra` (17 plus 25), and AAA Certificate Services only with
  `--include-aaa`. Script help, the active-set line, README, site and certificate
  page all use these numbers.
- New site: self-hosted fonts, favicon, social card, a 404 page, and a terminal
  block captured from a real run against a fake test root. The certificate page is
  generated from `data/fingerprints.tsv`. `/fonts/*` is cached for a year.
  `tools/release.py --carry` serves earlier version folders unchanged.
- Add the MIT licence.
- The site's HTML pages load cookieless PostHog page analytics (memory
  persistence, no autocapture or session recording). `/run`, the scripts and the
  fingerprint data send nothing.

## [0.1.0]

- Print the removal prompt only when reading a terminal answer. End explicit
  dry runs with a plain unchanged message, and place `Summary:` after the groups
  and report diagnostics.
- Generate home-page root naming and selection counts from certificate metadata.
  Preserve the ECC G3 default-root name and additional roots and cross-certificates
  wording. Check home-page names, TSV subjects, catalog labels, and recorded issuers.
- Report the scan, then ask through `/dev/tty` before removal. Add `--yes`, `-y`,
  and explicit `--dry-run`; keep `--apply` as an alias for `--yes`.
- Ask before a sudo re-execution, retain per-user removals, and report needs-root
  and unresolved manual work with distinct exit codes.
- Prune container layers, snaps, overlay and squashfs mounts, the checkout's own
  fixtures, and backup directories. Follow symlinked top-level directories.
- Persist Debian and Alpine packaged-source distrust in `ca-certificates.conf`;
  detect derivative distro families and installed blocklist layouts.
- Edit macOS `/etc/ssl/cert.pem` using Apple's supported administrator procedure.
  Keep SIP-protected roots report-only. Restore keychains through `security` APIs,
  remove trust settings, and support verified legacy SHA-1 selectors.
- Keep `--include-aaa` opt-in and describe Apple and Microsoft guidance precisely.
  Default and `--all-emudhra` selections continue to exclude AAA.
- Build a static versioned `dist/` layout with artifact hashes pinned inside the
  wrapper at `/run`. Keep the development `UNRELEASED` guard. Checked-in and
  released platform scripts omit all test hooks; tests build separate copies.
- Replace per-certificate byte-sized `dd` with a POSIX awk byte-preserving splitter.
  Decode and hash PEM certificates in batches. Scan known trust locations by default
  and add `--deep` for broader discovery. Add grouped output, `--verbose`, terminal
  progress, unique unreadable counts, and quiet skips for malformed third-party PEMs.
- Reuse discovered targets after confirmation. Back up and delete pure bundles when
  removal leaves them empty; retain originally empty files and other content.
- Add a static landing page, certificate-source page generated from metadata, and
  release hosting headers. Resolve verification shell executables before tests.
- Extend temp-tree, prompt, HTTPS tamper, packaged-source, and macOS shim checks.
  Keep one GitHub Actions template with a macOS job under `ci/github-workflows/`.
  Remove repository-specific agent skills.
