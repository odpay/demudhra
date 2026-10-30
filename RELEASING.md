# Build static release files

This procedure builds the static files served at `demudhra.sh`. It does not
commit, push, tag, upload, or publish. The wrapper in the repository has no
release URL or pins; `tools/release.py` stamps them into the built `/run`.

## Validate inputs

`data/fingerprints.tsv` and `data/certs.json` record 43 certificates: 17 in the
default set, 25 more that `--all-emudhra` adds (42 eMudhra certificates in all),
and the Sectigo AAA Certificate Services root, selected only by `--include-aaa`. New identities
require a certificate fixture, a DER SHA-256 check, and primary-source evidence.

Generate the offline scripts, verify all certificate hashes, then run the CLI
suites under each available shell:

```sh
timeout 45s python3 tools/generate.py
timeout 45s python3 tools/generate.py --check --verify-pems
python3 tools/verify.py --timeout 45 --shell dash --shell sh --shell 'busybox sh'
```

`tools/verify.py` gives each command a 45-second timeout and retains its output.
On macOS, use the available `sh` interpreter and install a timeout utility for
commands that use `timeout`. The native distro container suite is in
`tests/containers/`.

## Build one version

Choose the release version without a `v` prefix. Build into a new or empty
directory. Pass every version folder that is already published with `--carry`
so it is served unchanged; each one is checked against its `SHA256SUMS` first:

```sh
timeout 45s python3 tools/release.py --version 0.1.1 --output dist --carry old-dist/v0.1.0
```

The builder checks generated inputs and excludes test-only hooks from both
platform scripts. It stamps the platform version, builds the static site, and
creates:

```text
dist/
  index.html          from site/index.src.html and site/transcript.raw
  404.html
  style.css, favicon.svg, og.png, fonts/
  certs/index.html    generated from data/fingerprints.tsv and data/certs.json
  data/certs.json
  _headers
  run
  v0.1.0/             carried unchanged
  v0.1.1/
    demudhra-linux.sh
    demudhra-macos.sh
    fingerprints.tsv
    certs.json
    SHA256SUMS
```

The wrapper contains the versioned base URL `https://demudhra.sh/v0.1.1` and
the SHA-256 hashes of both platform scripts and `fingerprints.tsv`. It checks
downloaded bytes against those embedded hashes before execution. The wrapper
is the user's trust root. Someone who changes the wrapper can change its pins.

`SHA256SUMS` records the four versioned files for independent consistency checks.
The wrapper does not download or trust that manifest. Changing both an artifact
and the manifest still fails against an unchanged wrapper.

For a local HTTPS test server, `--url https://localhost:PORT/v0.1.1` overrides
the versioned base URL. No runtime environment variable overrides the URL or
pins. The local HTTPS tests exercise downloads, the pipe command, platform
arguments, artifact tampering, and artifact-plus-manifest tampering:

```sh
timeout 45s python3 tests/test_entrypoint.py
```

Check the packaged bytes against the manifest:

```sh
cd dist/v0.1.1
timeout 45s shasum -a 256 -c SHA256SUMS
```

## Publish the directory intact

Serve `dist/` as the static site root. `/run` serves the wrapper. Serve each
version folder at its matching URL. Keep published version folders immutable. Publish
the wrapper only after its pinned version folder is available.

The user command:

```sh
curl -fsSL https://demudhra.sh/run | sh
```

The wrapper saves the selected platform script and its fingerprint table in a
private temporary directory. It exports the internal `DEMUDHRA_SCRIPT_PATH`
for a user-approved sudo re-execution of that same saved script. The platform
script reports matches before it asks for confirmation through `/dev/tty`.
Only an explicit `y` or `Y`, or `--yes`, permits changes. `--dry-run` never asks.

The `_headers` file sets `text/plain; charset=utf-8` for `/run` and shell
files, `X-Content-Type-Options: nosniff` for all paths, a five-minute cache
lifetime for `/run`, and a one-year immutable cache for `/fonts/*`. Configure equivalent headers if the static host does not
support `_headers`. Serve the landing page at `/` and the generated certificate
list at `/certs/`. There is no worker or redirect required for `/run`.

To preview only the site pages, run
`timeout 45s python3 tools/release.py --site-only --output /tmp/site`. The site
uses self-hosted fonts, local CSS and a small inline copy handler. Its only
external requests are cookieless PostHog page analytics through `hp.demudhra.sh`;
`/run` and the scripts send nothing. The command remains selectable without JavaScript.

The terminal block on the home page is a real run. Re-capture it after output
changes with `python3 tools/capture_transcript.py --seed-root FAKE_ROOT`, where
`FAKE_ROOT` is a disposable fake filesystem tree. The capture runs an instrumented
copy under `DEMUDHRA_TEST_ROOT` with a no-op regeneration shim and answers `y`
in a pty; it never touches the host's stores. `tools/sitebuild.py` picks the lines
shown and marks every cut with `...`.

The CI workflow template is `ci/github-workflows/verify.yml`. Copy it to
`.github/workflows/verify.yml` when enabling GitHub Actions.

Record exact checks and remaining gaps in `VERIFICATION.md`. Do not publish
local test logs, caches, private paths, or fixtures as release assets.
