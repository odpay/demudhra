#!/usr/bin/env python3
"""Exercise native trust regeneration only inside a disposable test image."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
MARKER = Path('/.demudhra-disposable-container')
BLOCKS = re.compile(
    rb'-----BEGIN (?:TRUSTED )?CERTIFICATE-----\r?\n.*?'
    rb'-----END (?:TRUSTED )?CERTIFICATE-----(?:\r?\n|$)', re.S,
)
DISTROS = {
    'debian': ('/usr/local/share/ca-certificates', '/usr/share/ca-certificates/mozilla',
               ['/etc/ssl/certs/ca-certificates.crt']),
    'ubuntu': ('/usr/local/share/ca-certificates', '/usr/share/ca-certificates/mozilla',
               ['/etc/ssl/certs/ca-certificates.crt']),
    'alpine': ('/usr/local/share/ca-certificates', '/usr/share/ca-certificates/mozilla',
               ['/etc/ssl/certs/ca-certificates.crt']),
    'fedora': ('/etc/pki/ca-trust/source/anchors', '/usr/share/pki/ca-trust-source/anchors',
               ['/etc/pki/tls/certs/ca-bundle.crt']),
    'archlinux': ('/etc/ca-certificates/trust-source/anchors', '/usr/share/ca-certificates/trust-source/anchors',
                  ['/etc/ssl/certs/ca-certificates.crt', '/etc/ssl/cert.pem']),
    'opensuse': ('/etc/pki/trust/anchors', '/usr/share/pki/trust/anchors',
                 ['/var/lib/ca-certificates/ca-bundle.pem', '/etc/ssl/ca-bundle.pem']),
}


def run(args, expected=0, env=None):
    result = subprocess.run([str(x) for x in args], env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=45)
    print(result.stdout, end='')
    if result.returncode != expected:
        raise AssertionError(f'{args!r}: expected {expected}, got {result.returncode}')
    return result.stdout


def sha(pem):
    der = subprocess.check_output(['openssl', 'x509', '-outform', 'DER'], input=pem, timeout=45)
    return hashlib.sha256(der).hexdigest()


def hashes(path):
    return [sha(block) for block in BLOCKS.findall(path.read_bytes())]


def regenerate(distro):
    if distro in ('debian', 'ubuntu', 'alpine', 'opensuse'):
        run(['update-ca-certificates'])
    elif distro == 'archlinux':
        import shutil
        if shutil.which('update-ca-trust'):
            run(['update-ca-trust', 'extract'])
        else:
            run(['trust', 'extract-compat'])
    else:
        run(['update-ca-trust', 'extract'])


def snapshot(paths):
    result = {}
    for directory in paths:
        base = Path(directory)
        if not base.exists():
            continue
        entries = [base] if base.is_file() else sorted(base.rglob('*'))
        for path in entries:
            if path.is_symlink():
                result[str(path)] = ('link', os.readlink(path))
            elif path.is_file():
                info = path.stat()
                result[str(path)] = (hashlib.sha256(path.read_bytes()).hexdigest(),
                                     info.st_mode, info.st_uid, info.st_gid)
    return result


def main():
    if (os.environ.get('DEMUDHRA_CONTAINER_TEST') != '1' or not MARKER.is_file()
            or os.geteuid() != 0 or REPO != Path('/work')):
        raise SystemExit('Refusing native apply outside the disposable /work container image.')
    if Path('/var/run/docker.sock').exists() or Path('/run/podman/podman.sock').exists():
        raise SystemExit('Refusing native apply with a host container-engine socket mounted.')
    distro = MARKER.read_text().strip()
    if distro not in DISTROS:
        raise SystemExit(f'Unknown disposable image: {distro}')
    anchor_dir, packaged_dir, bundle_names = DISTROS[distro]
    anchor = Path(anchor_dir)
    anchor.mkdir(parents=True, exist_ok=True)
    data = json.loads((REPO / 'data/certs.json').read_text())
    record = next(row for row in data if row['group'] == 'default-root')
    target_bytes = (REPO / 'tests/fixtures' / record['pem_path']).read_bytes()
    aaa = next(row for row in data if row['group'] == 'opt-in-cross-sign')
    survivor_bytes = (REPO / 'tests/fixtures' / aaa['pem_path']).read_bytes()
    target_sha, survivor_sha = sha(target_bytes), sha(survivor_bytes)
    assert target_sha == record['sha256']
    assert survivor_sha not in {row['sha256'] for row in data if row['group'] != 'opt-in-cross-sign'}
    suffix = '.pem' if distro == 'opensuse' else '.crt'
    target = anchor / ('demudhra-container-target' + suffix)
    survivor = anchor / ('demudhra-container-survivor' + suffix)
    assert not target.exists() and not survivor.exists()
    target.write_bytes(target_bytes)
    survivor.write_bytes(survivor_bytes)
    packaged = Path(packaged_dir) / ('demudhra-packaged-target' + suffix)
    assert not packaged.exists()
    packaged.parent.mkdir(parents=True, exist_ok=True)
    packaged.write_bytes(target_bytes)
    if distro in ('debian', 'ubuntu', 'alpine'):
        config = Path('/etc/ca-certificates.conf')
        relative = str(packaged.relative_to('/usr/share/ca-certificates'))
        with config.open('a') as stream:
            stream.write('\n' + relative + '\n')
    regenerate(distro)
    bundles = [Path(name) for name in bundle_names if Path(name).is_file()]
    assert bundles, f'No system bundle found among {bundle_names}'
    for bundle in bundles:
        listed = hashes(bundle)
        assert target_sha in listed, f'Fixture did not reach real system output {bundle}'
        assert survivor_sha in listed, f'Survivor did not reach real system output {bundle}'
    env = os.environ.copy()
    for name in list(env):
        if name.startswith('DEMUDHRA_TEST_') or name in (
                'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE',
                'CURL_CA_BUNDLE', 'AWS_CA_BUNDLE', 'JAVA_HOME'):
            env.pop(name)
    backups = Path('/tmp/demudhra-native-backups')
    assert not backups.exists()
    paths = ['/etc/ssl', '/etc/pki', '/etc/ca-certificates', '/etc/ca-certificates.conf',
             '/usr/share/ca-certificates', '/usr/local/share/ca-certificates',
             '/usr/share/pki', '/usr/share/ca-certificates/trust-source',
             '/var/lib/ca-certificates']
    before = snapshot(paths)
    run(['dash', REPO / 'demudhra-linux.sh', '--dry-run', '--no-java', '--no-nss'], expected=10, env=env)
    assert snapshot(paths) == before, 'Native dry run changed trust files'
    run(['dash', REPO / 'demudhra-linux.sh', '--apply', '--no-java', '--no-nss',
         '--backup-dir', backups], env=env)
    assert not target.exists() or target_sha not in hashes(target), 'Target remains in source anchor'
    assert survivor.read_bytes() == survivor_bytes, 'Unrelated source anchor changed'
    assert list(backups.rglob('undo.sh')), 'No undo script was written'
    for bundle in bundles:
        assert target_sha not in hashes(bundle), f'Target remains in generated bundle {bundle}'
        assert survivor_sha in hashes(bundle), f'Survivor was removed from {bundle}'
    second_apply = run(['dash', REPO / 'demudhra-linux.sh', '--yes', '--no-java', '--no-nss',
                        '--backup-dir', backups], env=env)
    assert re.search(r'\bremoved=0\b', second_apply), 'Second apply was not idempotent'
    packaged.write_bytes(target_bytes)
    regenerate(distro)
    for bundle in bundles:
        assert target_sha not in hashes(bundle), f'Package-style reinstall restored target in {bundle}'
        assert survivor_sha in hashes(bundle), f'Package-style reinstall removed survivor in {bundle}'
    print(f'PASS: {distro} native dry run, local and packaged sources, persistent distrust after package-style reinstall, backups, and idempotence')


if __name__ == '__main__':
    main()
