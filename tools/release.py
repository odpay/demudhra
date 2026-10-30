#!/usr/bin/env python3
"""Build the unpublished static dist layout. Nothing is uploaded."""

import argparse
import hashlib
import pathlib
import re
import shutil
import subprocess
import sys
import urllib.parse

from generate import platform_script
from sitebuild import build_site

ROOT = pathlib.Path(__file__).resolve().parents[1]


def carry_release(src, out):
    """Copy an already-published version folder unchanged after checking its SHA256SUMS."""
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?', src.name):
        raise ValueError(f'--carry expects a vX.Y.Z directory: {src}')
    listed = set()
    for row in (src / 'SHA256SUMS').read_text().splitlines():
        digest, name = row.split('  ', 1)
        if hashlib.sha256((src / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f'{src}/{name} does not match its SHA256SUMS')
        listed.add(name)
    extra = {p.name for p in src.iterdir()} - listed - {'SHA256SUMS'}
    if extra:
        raise ValueError(f'{src} has files outside SHA256SUMS: {sorted(extra)}')
    shutil.copytree(src, out / src.name, copy_function=shutil.copy2)


HEADERS = """/*
  X-Content-Type-Options: nosniff
/run
  Content-Type: text/plain; charset=utf-8
  Cache-Control: public, max-age=300
/*.sh
  Content-Type: text/plain; charset=utf-8
/fonts/*
  Cache-Control: public, max-age=31536000, immutable
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', help='release version (default from wrapper, without v prefix)')
    parser.add_argument('--url', help='override versioned HTTPS artifact directory for local release testing')
    parser.add_argument('--output', type=pathlib.Path, default=ROOT / 'dist',
                        help='new or empty output directory (default dist); nothing is uploaded')
    parser.add_argument('--site-only', action='store_true',
                        help='render only the site pages and assets into --output, without a release')
    parser.add_argument('--carry', type=pathlib.Path, action='append', default=[],
                        help='copy an existing published vX.Y.Z folder unchanged (checked against its SHA256SUMS)')
    args = parser.parse_args()
    wrapper = (ROOT / 'demudhra.sh').read_text()
    version = args.version or re.search(r"^VERSION='([^']+)'$", wrapper, re.M).group(1)
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?', version):
        parser.error('--version must be a semantic version without a v prefix')
    url = args.url or f'https://demudhra.sh/v{version}'
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.netloc or parsed.query or parsed.fragment or re.search(r"[\s'\\]", url):
        parser.error('--url must be one HTTPS artifact directory without quotes, whitespace, query, or fragment')
    out = args.output.resolve()
    if out == ROOT or out in ROOT.parents:
        parser.error('--output cannot contain the source repository')
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        parser.error('--output must be new or empty; refusing to overwrite existing artifacts')
    if args.site_only:
        build_site(out, version)
        print(f'Built site pages into {out}/. Nothing uploaded.')
        return
    carried = [path.resolve() for path in args.carry]
    if any(path.name == f'v{version}' for path in carried):
        parser.error('--carry cannot replace the version being built')
    subprocess.run([sys.executable, str(ROOT / 'tools/generate.py'), '--check'],
                   cwd=ROOT, check=True, timeout=45)
    assets = {f'demudhra-{platform}.sh': re.sub(r'^version=[^\n]+$',
              f'version={version}', platform_script(platform, release=True), flags=re.M).encode()
              for platform in ('linux', 'macos')}
    assets['fingerprints.tsv'] = (ROOT / 'data/fingerprints.tsv').read_bytes()
    assets['certs.json'] = (ROOT / 'data/certs.json').read_bytes()
    pins = {name: hashlib.sha256(data).hexdigest() for name, data in assets.items()}
    stamps = {'VERSION': version, 'RELEASE_URL': url.rstrip('/'),
              'LINUX_SHA256': pins['demudhra-linux.sh'],
              'MACOS_SHA256': pins['demudhra-macos.sh'],
              'FINGERPRINTS_SHA256': pins['fingerprints.tsv']}
    for name, value in stamps.items():
        pattern = rf"^{name}='[^']*'$"
        wrapper, count = re.subn(pattern, f"{name}='{value}'", wrapper, flags=re.M)
        if count != 1:
            parser.error(f'wrapper must contain exactly one {name} marker')
    versioned = out / f'v{version}'
    versioned.mkdir(parents=True)
    for name, data in assets.items():
        path = versioned / name
        path.write_bytes(data)
        path.chmod(0o755 if name.endswith('.sh') else 0o644)
    (versioned / 'SHA256SUMS').write_text(''.join(
        f'{pins[name]}  {name}\n' for name in assets), encoding='ascii')
    build_site(out, version)
    for path in carried:
        carry_release(path, out)
    (out / 'run').write_text(wrapper)
    (out / 'run').chmod(0o755)
    (out / '_headers').write_text(HEADERS)
    print(f'Built {out}/ with site files, /run, and /v{version}/. Nothing uploaded.')


if __name__ == '__main__':
    main()
