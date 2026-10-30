# demudhra

Update your OS and runtimes first. Install current CA packages, browsers, language
runtimes, and application updates, then restart their consumers. demudhra removes
selected certificates from local stores by the SHA-256 fingerprint of decoded DER.
It never matches a certificate by its name.

One run scans and reports what it would remove, then asks through `/dev/tty`:

```text
found N certs in M places. remove them? [y/N]
```

Only `y` or `Y` proceeds to backups, removal, and native store regeneration.
Any other answer changes nothing. Without a terminal it stays a dry run.
Use `--dry-run` to report without asking, or `--yes` for unattended removal.
`--apply` remains an alias for `--yes`. Removal can break dependent services.
Close browsers, JVMs, and Keychain Access before confirming removal or undo.

## Run

```sh
curl -fsSL https://demudhra.sh/run | sh
```

Pass flags after `sh -s --`, for example `curl -fsSL https://demudhra.sh/run | sh -s -- --dry-run`.

The wrapper pins the SHA-256 of both platform scripts and `fingerprints.tsv` and refuses to run if a download does not match. See [SECURITY.md](SECURITY.md) and [RELEASING.md](RELEASING.md).

From a clone, run `sh demudhra-linux.sh` or `sh demudhra-macos.sh` (the clone's `demudhra.sh` has no release pins and exits). These scripts
work offline with the sibling `data/fingerprints.tsv` and require POSIX sh, OpenSSL,
awk, and standard Unix utilities. Only the wrapper downloads files.

If confirmed targets need root, writable per-user targets are removed first.
The script lists the remaining targets and, when sudo and a terminal are available,
asks once `these need root. re-run with sudo? [y/N]`. An explicit y re-executes the
same saved script and flags plus `--yes`, recomputing the scan as root. sudo handles
its own password prompt. Otherwise the script prints the exact sudo command and
exits 4. The wrapper exports `DEMUDHRA_SCRIPT_PATH` with its downloaded script path
so this re-execution also works under `curl | sh`. On exit 3 or 4 the wrapper
retains this private download directory so printed commands remain usable; remove
it after completing that work. This is an internal path variable,
not a remote download override.

## Select certificates

The certificate snapshot is dated 25 October 2026. Metadata and source links live in
[data/certs.json](data/certs.json). `--list` prints the selected fingerprints,
groups, subjects, and sources.

`data/fingerprints.tsv` lists 43 certificates. 42 are eMudhra's and one is Sectigo's
AAA Certificate Services root, which is never selected unless you ask for it:

| Selection | Selects | Scope |
| --- | ---: | --- |
| Default | 17 | emSign ECC Root CA - G3 and the 16 affected intermediates and cross-signs |
| `--all-emudhra` | 42 | The default 17 plus 25 more eMudhra roots and cross-certificates, including G1 |
| `--include-aaa` | +1 | AAA Certificate Services (Sectigo), with either selection: 18 or 43 |

G1 remains trusted by Mozilla, Chrome, and Apple in the supplied snapshot.
`--all-emudhra` is a broader policy choice. AAA Certificate Services is a Sectigo
root. Apple names it as the Sectigo cross-sign root and provides optional removal
in step 3 of its guidance. Microsoft reports removing an AAA Certificate Services
cross-sign; its post does not identify a fingerprint. The AAA fingerprint here is
computed from the included certificate fixture.
Neither the default nor `--all-emudhra` selects AAA without `--include-aaa`.

Sources include [Apple's guidance](https://support.apple.com/en-us/149555),
[Mozilla's incident record](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449),
[Google's announcement](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/),
[Microsoft's 26 October response](https://www.microsoft.com/en-us/msrc/blog/2026/10/microsoft-response-to-compromised-emudhra-certificate-authority-keys),
and [Tanium's write-up](https://www.tanium.com/blog/emudhra-ca-compromise-find-and-fix-your-exposure-with-tanium).

## Options and exit codes

| Option | Effect |
| --- | --- |
| `--yes`, `-y` | Report, then back up and remove without asking |
| `--apply` | Alias for `--yes` |
| `--dry-run` | Report only, never ask; takes precedence over `--yes` |
| `--deep` | Also search broader application and home trees with pruning |
| `--verbose` | Show every matched path and the malformed-file count |
| `--all-emudhra` | Select all 42 eMudhra certificates (the default 17 plus 25) |
| `--include-aaa` | Also select the AAA Certificate Services root described by Apple (+1) |
| `--list` | List selected identities without scanning |
| `--backup-dir DIR` | Parent for private timestamped backups |
| `--no-system` | Skip system anchors and generated bundles |
| `--no-java`, `--no-nss` | Skip direct Java or NSS adapters |
| `--no-python`, `--no-node`, `--no-ruby` | Skip those file ecosystems |
| `--no-bundles`, `--no-keychains` | Skip other bundles or macOS keychains |
| `--help`, `--version` | Display usage or version |

Native OS regeneration can also update OS-provided Java stores with `--no-java`.
Files reached through a skipped ecosystem's alias are protected from direct edits.

| Exit | Meaning |
| ---: | --- |
| 0 | Clean scan, or confirmed removal completed without recorded failures or unresolved matches |
| 1 | Usage, setup, invalid metadata, or download/pinned-hash failure |
| 2 | Real inspection or mutation failure; earlier removals may have succeeded |
| 3 | Confirmed run has matches requiring manual action; exact next steps appear in output |
| 4 | Targets require root; output lists targets and the sudo command |
| 10 | Report-only run found matches; nothing changed |
| 11 | User declined or gave an empty answer; nothing changed |

Unreadable paths are counted separately as `not readable (run as root to include)`;
they do not alone cause exit 2. A clean scan does not prove complete coverage.
The summary counts occurrences, backups, failures, unreadable paths, and unresolved
manual work. Malformed PEM files are skipped unchanged and counted only with
`--verbose`. A nonempty pure certificate bundle is deleted when its last selected
certificate is removed. Its backup and undo command remain available. Originally
empty files and non-certificate content are retained.

## Linux stores and persistence

`ID`, `ID_LIKE`, and release-name fallbacks select native regeneration for Debian,
Ubuntu, Mint, Pop!_OS, Kali, Raspberry Pi OS, Zorin, Devuan, RHEL, Fedora, CentOS,
Rocky, AlmaLinux, Oracle Linux, Amazon Linux, Arch, Alpine, SUSE, and openSUSE.
Unsupported families refuse system mutation. File-based runtime scans still work
with `--no-system`.

| Family | Regeneration and persistent distrust |
| --- | --- |
| Debian and Ubuntu derivatives | `update-ca-certificates --fresh` with empty hooks; fingerprint-matched packaged paths are disabled with `!relative/path.crt` in backed-up `/etc/ca-certificates.conf` |
| Alpine | `update-ca-certificates`; packaged paths are also disabled in `ca-certificates.conf` |
| RHEL family | `update-ca-trust extract`; exact-certificate distrust records |
| Arch | `update-ca-trust extract` or `trust extract-compat`; exact-certificate distrust records |
| SUSE | `update-ca-certificates --fresh`; exact-certificate distrust records |

The Debian `!` blacklist persists when a CA package restores its certificate file.
Undo restores the original configuration. Tests run the real updater entirely in
temporary directories, restore a packaged file, and verify the root stays absent.
Upgrades that replace local configuration, environment rebuilds, or application
updates still warrant another scan.

Current [update-ca-trust documentation](https://www.mankier.com/8/update-ca-trust),
[Arch's manual](https://man.archlinux.org/man/update-ca-trust.8.en), and
[SUSE's manual](https://manpages.opensuse.org/Tumbleweed/ca-certificates/update-ca-certificates.8.en.html)
name `blocklist`. Older installations can use `blacklist`. The script prefers
existing directories, then installed manual guidance. When it cannot establish the
installed layout, it writes the same fingerprint-verified record to both names.
Distrust records are excluded from subsequent removal. Generated stores are checked
for returned matches. Unknown updater hooks and custom SUSE layouts are refused.

## macOS stores

Apple's [supported administrator procedure](https://support.apple.com/en-us/149555)
of 29 October 2026 says Safari, Mail, and apps using Apple frameworks are already
protected by Apple's automatic blocks. Command-line tools supplied with macOS or
Xcode Command Line Tools, including curl, git, Python, Ruby, Perl, and OpenSSL,
use `/etc/ssl/cert.pem` without those blocks or revocation checks. demudhra removes
selected fingerprints from this file, including each removed certificate's Apple
subject and `###` headers, and re-parses the result after applying it. Backups and
undo preserve the original file. A macOS update may restore the bundle, so rerun
after updating. Apps with their own root lists need their own updates.

If AAA Certificate Services remains in this file, the six Sectigo cross-signed
intermediates still verify through it. `--include-aaa` performs Apple's optional
removal and may break sites chained through unaffected Sectigo intermediates.

System and login keychains
use `security` with verified fingerprint selectors and `-t` to remove trust settings.
Older SHA-1-only `-Z` implementations get a SHA-1 selector derived from the exact
SHA-256-selected certificate, after a fresh collision check. Failure is reported
with manual instructions. Other-owner login keychains remain report-only; run
in that owner's session to preserve user-domain trust settings.

SIP-protected System roots are report-only. The tool does not disable SIP or
claim it deleted them. Output includes the exact certificate export and admin deny
command for manual review. An unresolved report-only hit makes a confirmed run
exit 3 when no higher-priority failure or root requirement exists. Inspection or mutation failures return 2,
and targets needing root return 4.
Keychain undo reimports saved certificates and trust settings through `security`;
it does not overwrite a keychain file held open by securityd.

## Scan boundaries and what this does NOT cover

The default scan checks known OS trust stores, Java homes, browser profiles,
Python and Node bundle locations, per-user runtime directories, and explicit
bundle environment variables. A bounded search also finds virtual environments
and node_modules under likely application and home directories. `--deep` removes
the depth limits and adds broader system trees, with the same pruning. Candidate names and sizes limit parsing; files larger
than 5 MiB are skipped. macOS limits home discovery
to runtime locations, Firefox profiles, and keychains to avoid walking Documents,
Desktop, and other TCC-protected content. Symlinked top-level directories are followed;
recursive directory symlinks are not. The tool's own checkout, fixture trees outside
test roots, Git metadata, and all marked backup directories are excluded.

| Area | Limit or required action |
| --- | --- |
| Container/image layers, Docker, Podman, containerd, LXC | Pruned. Rebuild images from updated base images and CA packages |
| Snap, overlay directories, squashfs mounts, Nix store | Pruned. Update the package/image through its owner |
| Compiled Node, Deno, Bun, and Rust webpki roots | Detected runtimes appear with versions in `cannot_change`; update runtimes and rebuild applications |
| Go | Standard Go uses the system trust store on Linux and macOS, which demudhra cleans. The Go version is reported for reference. Binaries that embed their own roots (for example `x509roots/fallback`) need a rebuild |
| SIP-protected macOS System roots | Detect and print manual distrust guidance; install Apple's updates |
| Firefox and Chrome NSS profiles | Requires `certutil`; built-in roots need NSS updates; locked or ambiguous stores are refused |
| Java cacerts, jssecacerts, JKS, PKCS12, keystore, truststore | All known JDK locations, `JAVA_HOME`, and Java executables on PATH; requires `keytool`, tries `changeit`; custom passwords and private-key aliases need manual work |
| macOS developer tools and app bundles | Command Line Tools, Xcode, app `Contents`, bundled JREs, user JVMs, and JetBrains support directories; bounded scans prune large framework internals |
| Homebrew and MacPorts | Homebrew OpenSSL and CA configuration, Cellar runtime bundles, MacPorts OpenSSL and curl |
| Python, Node, Ruby, and Java version managers | asdf, mise, rtx, SDKMAN, Gradle JDKs, `.jdks`, rbenv, RVM, Volta, fnm, pyenv, and nvm |
| Python tools and conda distributions | pipx, uv, Rye, Miniconda, Anaconda, Miniforge, Mambaforge, micromamba, `.conda`, and `/opt/conda` |
| Cloud CLIs and editor extensions | Google Cloud SDK, AWS CLI v2, Azure CLI, VS Code, Cursor, and JetBrains bundles in known install directories |
| Linux OpenSSL and Java stores | `/usr/lib/ssl`, `/usr/local/ssl`, `/etc/ssl/certs/java`, `/usr/share/ca-certificates-java`, `/etc/pki/java`, and `/usr/lib/jvm` |
| Flatpak runtimes | Report-only when discovered; update runtimes through Flatpak |
| AppImage, archives, embedded roots, built-in NSS roots | No universal package inspection or extraction; update applications |
| Windows | Not covered; use OS updates and Microsoft's guidance |
| Android, iOS, embedded devices, UEFI | Not covered |
| Package caches, encrypted volumes, custom stores, inaccessible paths | Covered only if readable matching files are in scanned locations |
| Running processes | Restart consumers; removal does not flush in-memory trust |

Explicit file targets include `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`,
`REQUESTS_CA_BUNDLE`, `AWS_CA_BUNDLE`, `GIT_SSL_CAINFO`, `PIP_CERT`, npm `cafile`,
`HTTPLIB2_CA_CERTS`, `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH`, `CARGO_HTTP_CAINFO`,
`DENO_CERT`, and `BUNDLE_SSL_CA_CERT`. `SSL_CERT_DIR` includes hashed certificate
files. Read-only config discovery includes global and system git `http.sslCAInfo`,
`~/.npmrc`, pip configuration, `~/.curlrc`, and `~/.wgetrc`; npm is never executed.
Configuration files are parsed as data, never sourced as shell code.
Pruned stores stay excluded even through an alias or environment target.

## Backups, undo, and verification

Backups live under `$HOME/demudhra-backups` by default. Each modified file and native
output tree is backed up before mutation. The report prints `undo.sh` and its exact
command. Close consumers and run undo with the necessary permissions.
Restore several runs in reverse order. Undo can overwrite
unrelated later changes. Keep backups private.

File replacements and file undo use a sibling temporary copy followed by rename.
Tree undo copies the complete snapshot to a sibling staging directory first,
keeps the live tree in place, and renames staged leaf files over their targets.
It removes extra entries only after successful restoration and refuses directory
type conflicts. A failure can leave some restored leaves; inspect the error and
rerun undo after resolving it. This is not a global or crash-atomic transaction across
stores. PEM survivors retain original bytes, CRLF, comments, and final-newline state.

Run bounded local verification with Python, OpenSSL, ShellCheck, and the selected shells:

```sh
python3 tools/verify.py --timeout 45 --shell dash --shell sh --shell 'busybox sh'
```

Each subprocess has a 45-second maximum. Use `--batch-size 3` if a complete suite
exceeds that limit on a loaded host; retain the timeout as an incomplete attempt. [VERIFICATION.md](VERIFICATION.md) records
the latest results. `tests/containers/` holds the native distro container suite.

Tests generate separate instrumented scripts under ignored `.build/` directories.
Test overrides require `DEMUDHRA_TESTING=1`, print warnings, and confine changes
with `DEMUDHRA_TEST_ROOT`. Neither checked-in nor released platform scripts contain
these hooks.

## License

MIT. See [LICENSE](LICENSE).
