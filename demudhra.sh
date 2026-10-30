#!/bin/sh
set -u

VERSION='0.1.1'
RELEASE_URL='UNRELEASED'
LINUX_SHA256='UNRELEASED'
MACOS_SHA256='UNRELEASED'
FINGERPRINTS_SHA256='UNRELEASED'

usage() {
    cat <<'HELP'
demudhra: download a platform script whose SHA-256 is pinned in this wrapper.
Usage: sh demudhra.sh [--yes | --dry-run] [--all-emudhra] [--include-aaa] [options]
One run reports matches, then asks through /dev/tty before removal.
Only y/Y or --yes (-y, --apply) permits changes. --dry-run never asks.
Without a terminal this stays a dry run; --yes is required unattended.
Default: 17 certificates (emSign ECC Root CA - G3 + 16 intermediates).
--all-emudhra: 42 (adds 25 eMudhra roots and cross-certificates, incl. G1).
--include-aaa: +1, the Sectigo AAA Certificate Services root named in
Apple's optional removal step. 43 certificates in the list in total.
Platform options include --list, --backup-dir DIR, --no-system, --no-java,
--no-nss, --no-python, --no-node, --no-ruby, --no-bundles, --no-keychains,
-h, and --version. Read the platform script for details.
Exit codes: 0 clean/applied, 10 report-only matches, 11 declined removal,
1 usage/download error, 2 partial failure, 3 manual action remains,
4 selected targets need root.
Pinned hashes prove that downloaded bytes match this wrapper's pins.
The wrapper itself is the trust root. A modified wrapper can change the pins.
DEMUDHRA_SCRIPT_PATH is an internal path to the saved platform script used
for an explicitly approved sudo re-execution. It is not a download override.
An unreleased checkout exits 1. Build the static dist layout with tools/release.py.
HELP
}

case ${1-} in
    -h|--help) usage; exit 0 ;;
    --version) printf '%s\n' "demudhra $VERSION"; exit 0 ;;
esac

error() {
    printf '%s\n' "demudhra: $*" >&2
    exit 1
}

case $(uname -s) in
    Linux) platform=demudhra-linux.sh; expected_script=$LINUX_SHA256 ;;
    Darwin) platform=demudhra-macos.sh; expected_script=$MACOS_SHA256 ;;
    *) error 'Unsupported OS. Only Linux and macOS are supported.' ;;
esac

url=$RELEASE_URL
case $url in
    https://?*) ;;
    *) error 'UNRELEASED: no release URL or pinned hashes configured. Nothing downloaded or executed. Read RELEASING.md.' ;;
esac
case $url in
    *'?'*|*'#'*|*[[:space:]]*|*\\*) error 'Release URL must be an HTTPS directory without query, fragment, whitespace, or backslash.' ;;
esac
for pin in "$expected_script" "$FINGERPRINTS_SHA256"; do
    printf '%s\n' "$pin" | awk 'length($0)!=64 || /[^0-9a-f]/ {exit 1}' || error 'Invalid or unreleased SHA-256 pin. Nothing executed.'
done
url=${url%/}
command -v curl >/dev/null 2>&1 || error 'curl is required for release downloads.'
if command -v openssl >/dev/null 2>&1; then
    hash_backend=openssl
elif command -v shasum >/dev/null 2>&1; then
    hash_backend=shasum
else
    error 'openssl or shasum is required to check pinned SHA-256 before execution.'
fi

umask 077
scratch=$(mktemp -d "${TMPDIR:-/tmp}/demudhra-download.XXXXXXXX") || error 'Cannot create private download directory.'
keep_scratch=0
trap 'if [ "$keep_scratch" = 0 ]; then rm -rf "$scratch"; fi' 0
trap 'exit 1' HUP INT TERM
mkdir "$scratch/data" || error 'Cannot create data directory.'

fetch() {
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 20 "$url/$1" -o "$scratch/$2" || error "Download failed for $1. Nothing executed."
}

hash_file() {
    if [ "$hash_backend" = openssl ]; then
        hash_output=$(openssl dgst -sha256 "$1") || return 1
        printf '%s\n' "$hash_output" | awk '{print tolower($NF)}'
    else
        hash_output=$(shasum -a 256 "$1") || return 1
        printf '%s\n' "$hash_output" | awk '{print tolower($1)}'
    fi
}

fetch "$platform" "$platform"
fetch fingerprints.tsv data/fingerprints.tsv
for asset in "$platform" data/fingerprints.tsv; do
    case $asset in
        "$platform") expected=$expected_script ;;
        *) expected=$FINGERPRINTS_SHA256 ;;
    esac
    actual=$(hash_file "$scratch/$asset") || error "Could not hash $asset. Nothing executed."
    [ "$actual" = "$expected" ] || error "SHA-256 mismatch for $asset against wrapper pin. Nothing executed."
done
printf '%s\n' "Downloaded bytes match this wrapper's SHA-256 pins for $platform and fingerprints.tsv from $url" >&2
DEMUDHRA_SCRIPT_PATH=$scratch/$platform
export DEMUDHRA_SCRIPT_PATH
sh "$DEMUDHRA_SCRIPT_PATH" "$@"
result=$?
case $result in
    3|4)
        keep_scratch=1
        printf '%s\n' "Saved platform files retained at $scratch for the printed manual/sudo command. Remove this directory after completing that work." >&2;;
esac
exit "$result"
