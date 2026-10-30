# Verification

Verified on 29 October 2026 for v0.1.1. No real-system removal ran. Apply and
undo used disposable roots, temporary NSS and Java stores, and macOS security
shims. Logs are kept locally under the ignored `.build/` directory.

## Shell matrix

All **97 cases passed under each shell**, for **291 passing case executions**.
No cases were skipped. On this box, `/bin/sh` resolves to dash. BusyBox is 1.37.0.

| Suite | Cases per shell | sh | dash | BusyBox sh |
| --- | ---: | --- | --- | --- |
| Files and certificate selection | 16 | PASS | PASS | PASS |
| Real NSS and Java stores | 8 | PASS | PASS | PASS |
| Local HTTPS wrapper, release and site build | 15 | PASS | PASS | PASS |
| macOS security shim | 15 | PASS | PASS | PASS |
| Isolated Debian regeneration | 3 | PASS | PASS | PASS |
| Distro and distrust directories | 5 | PASS | PASS | PASS |
| Confirmation, pruning, permissions, concurrency, undo | 20 | PASS | PASS | PASS |
| Bounded discovery and Apple-format bundles | 15 | PASS | PASS | PASS |

Each shell ran a complete verification invocation. Set `verification_shell` to
`sh`, `dash`, or `/tmp/demudhra-userspace/usr/bin/busybox sh`, and set
`verification_name` to `sh`, `dash`, or `busybox`.

```sh
python3 tools/verify.py --timeout 45 --shell "$verification_shell" \
  --shellcheck /tmp/demudhra-tools/bin/shellcheck \
  --output ".build/pass6/$verification_name"
```

Each child command has a 45-second timeout. All three invocations exited zero.

ShellCheck 0.11.0 passed the nine source and generated shell files, plus `dist/run`
and both v0.1.1 platform scripts. `tools/generate.py --check --verify-pems`
verified all 43 release certificate DER hashes and generated-artifact consistency.

## Feature map

| Behavior | Executable checks |
| --- | --- |
| Fingerprint-only selection, default, broader and AAA sets | `tests/test_files.py`, release `--list` checks |
| Bounded known locations, explicit environment and config paths, hashed certificate directories, all Java executables on PATH | `tests/test_discovery.py` uses the production discovery registry inside a test root |
| Apple subject and `###` header removal, byte preservation, re-parsing the actual applied file, verification failure and undo | Apple-format fixture and `AppleBundle` cases in `tests/test_discovery.py` |
| Literal config values, another user's `~/` paths, missing environment targets, constrained hash filenames | `Discovery` cases in `tests/test_discovery.py` |
| Runtime versions, compiled roots counts, Flatpak report-only behavior | Runtime shims and disposable Flatpak trees in `tests/test_discovery.py` |
| Review before confirmation, unchanged target checks, backups, skips, prunes and undo | `tests/test_workflow.py`, `tests/test_files.py` |
| Java and NSS removal, macOS keychains, persistent Linux distrust and regeneration | `tests/test_stores.py`, `tests/test_macos.py`, `tests/test_distro.py`, `tests/test_debian_regeneration.py` |
| Pinned downloads, tamper refusal, versioned release layout | `tests/test_entrypoint.py` runs a local HTTPS server |

The Apple fixture contains two fake certificates with identical subjects and
separate fingerprints. Removal retains the unrelated certificate, its headers,
and the global preamble. Undo restores the exact original bytes. New location
checks plant fake certificates in every requested location class, apply removal,
and verify undo. Java discovery checks use real JKS stores and keytool.

## Default dry-run timing

One normal-PATH invocation of `sh demudhra-linux.sh --dry-run` took **12.007 s**
on this eight-core box. It exited 10 because it found matches. The load average
at launch was 4.27, 3.10, 2.00. This is one end-to-end timing, not a speedup claim.

```text
Summary: found=57 removed=0 backed_up=0 failed=0 cannot_change=5 manual_remaining=1 unreadable=2
```

The report had empty stderr and grouped output. Node, Go, Bun, and Cargo each
appeared on one labelled version line. The fifth `cannot_change` entry was an NSS
profile whose inspection requires certutil on the normal PATH. Store tests use
the installed userspace certutil and keytool directly. Two host paths were
unreadable. A repeat run of the built v0.1.1 script took 11.6 s with the same summary.

## Release and site

`tools/release.py --version 0.1.1 --output dist --carry <previous dist>/v0.1.0`
built the release into an empty `dist/`. `--carry` checked v0.1.0 against its
`SHA256SUMS`, and the copied folder is byte-identical to the one served at
`https://demudhra.sh/v0.1.0/`. All four v0.1.1 manifest hashes and the wrapper's
three embedded pins match the artifact bytes. Both platform scripts report 0.1.1
and contain no test hooks. Their `--list` counts are 17, 42, 18, and 43 for the
four combinations of `--all-emudhra` and `--include-aaa`. ShellCheck passes on
`dist/run` and both v0.1.1 scripts.

The home page's terminal block was re-captured from the v0.1.1 code with
`tools/capture_transcript.py` against a fake Debian root, answering `y` in a pty.
Headless Chrome rendered the home and certificate pages at 1440x900 and 390x844.
The certificate page lists each of the 43 fingerprints exactly once.

macOS behaviour was exercised on Linux through the `security` shim and
Apple-format `/etc/ssl/cert.pem` fixtures. The native distro container suite is in
`tests/containers/`.
