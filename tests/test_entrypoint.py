#!/usr/bin/env python3
"""Exercise the wrapper against a local HTTPS server and pinned release bytes."""

import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

REPO = Path(__file__).resolve().parents[1]
SHELL = shlex.split(os.environ.get('DEMUDHRA_TEST_SHELL', 'dash'))


class Entrypoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_temp = tempfile.TemporaryDirectory(prefix='demudhra-https-')
        cls.server_base = Path(cls.server_temp.name)
        cls.cert = cls.server_base / 'localhost.pem'
        key = cls.server_base / 'localhost.key'
        config = cls.server_base / 'localhost.cnf'
        config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\n')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cls.cert), '-days', '1',
                        '-config', str(config)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
        cls.downloads = []

        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                cls.downloads.append(self.path)
                return super().do_GET()

        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0),
            functools.partial(Handler, directory=str(cls.server_base)))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.cert, key)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.url = f'https://localhost:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=5)
        cls.server_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='demudhra-entrypoint-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.assets = self.server_base / 'vtest'
        self.assets.mkdir(exist_ok=True)
        self.args = self.base / 'arguments'
        self.saved_path = self.base / 'saved-path'
        self.env = os.environ.copy()
        self.env.update({'PATH': str(self.bin) + os.pathsep + self.env['PATH'],
                         'MOCK_ARGUMENTS': str(self.args), 'MOCK_OS': 'Linux',
                         'MOCK_SAVED_PATH': str(self.saved_path),
                         'CURL_CA_BUNDLE': str(self.cert)})
        self.executable('uname', '#!/bin/sh\nprintf "%s\\n" "$MOCK_OS"\n')
        script = b'''#!/bin/sh
printf '%s\\n' "$@" > "$MOCK_ARGUMENTS"
printf '%s\\n' "$DEMUDHRA_SCRIPT_PATH" > "$MOCK_SAVED_PATH"
[ "$DEMUDHRA_SCRIPT_PATH" = "$0" ] || exit 98
[ -f "$(dirname "$0")/data/fingerprints.tsv" ] || exit 99
exit 10
'''
        for platform in ('linux', 'macos'):
            (self.assets / f'demudhra-{platform}.sh').write_bytes(script)
        (self.assets / 'fingerprints.tsv').write_bytes(b'fixture fingerprint data\n')
        self.manifest()
        self.wrapper = self.base / 'demudhra.sh'
        self.wrapper.write_text(self.stamped_wrapper())
        self.downloads.clear()

    def executable(self, name, source):
        path = self.bin / name
        path.write_text(source)
        path.chmod(0o755)

    def manifest(self):
        names = ('demudhra-linux.sh', 'demudhra-macos.sh', 'fingerprints.tsv')
        (self.assets / 'SHA256SUMS').write_text(''.join(
            f'{hashlib.sha256((self.assets / name).read_bytes()).hexdigest()}  {name}\n'
            for name in names))

    def stamped_wrapper(self):
        source = (REPO / 'demudhra.sh').read_text()
        stamps = {'RELEASE_URL': self.url + '/vtest',
                  'LINUX_SHA256': hashlib.sha256((self.assets / 'demudhra-linux.sh').read_bytes()).hexdigest(),
                  'MACOS_SHA256': hashlib.sha256((self.assets / 'demudhra-macos.sh').read_bytes()).hexdigest(),
                  'FINGERPRINTS_SHA256': hashlib.sha256((self.assets / 'fingerprints.tsv').read_bytes()).hexdigest()}
        for name, value in stamps.items():
            source = re.sub(rf"^{name}='[^']*'$", f"{name}='{value}'", source, flags=re.M)
        return source

    def invoke(self, *args):
        return subprocess.run(SHELL + [str(self.wrapper), *args], env=self.env,
                              capture_output=True, text=True, timeout=45)

    def test_linux_and_macos_pins_arguments_exit_and_saved_script(self):
        for name, asset in (('Linux', 'demudhra-linux.sh'), ('Darwin', 'demudhra-macos.sh')):
            self.env['MOCK_OS'] = name
            self.downloads.clear()
            result = self.invoke('--yes', '--backup-dir', 'path with spaces', '--no-java')
            self.assertEqual(result.returncode, 10, result.stderr)
            self.assertEqual(self.args.read_text().splitlines(),
                             ['--yes', '--backup-dir', 'path with spaces', '--no-java'])
            self.assertEqual(self.downloads, ['/vtest/' + asset, '/vtest/fingerprints.tsv'])
            self.assertIn("match this wrapper's SHA-256 pins", result.stderr)
            self.assertFalse(Path(self.saved_path.read_text().strip()).exists(), 'scratch tree leaked')

    def test_actionable_exit_retains_script_for_printed_sudo_command(self):
        for code in (3, 4):
            target = self.assets / 'demudhra-linux.sh'
            target.write_bytes(target.read_bytes().replace(b'exit 10', f'exit {code}'.encode()).replace(b'exit 3', f'exit {code}'.encode()))
            self.wrapper.write_text(self.stamped_wrapper())
            result = self.invoke('--yes')
            self.assertEqual(result.returncode, code, result.stderr)
            saved = Path(self.saved_path.read_text().strip())
            self.assertTrue(saved.is_file())
            self.assertIn('retained', result.stderr)
            shutil.rmtree(saved.parent)

    def test_macos_real_shasum_fallback_rejects_tampering(self):
        for name in ('sh', 'dash', 'rm', 'mkdir', 'mktemp', 'awk', 'dirname', 'curl', 'shasum'):
            location = shutil.which(name)
            if location:
                (self.bin / name).symlink_to(location)
        self.env.update({'PATH': str(self.bin), 'MOCK_OS': 'Darwin'})
        result = self.invoke('--list')
        self.assertEqual(result.returncode, 10, result.stderr)
        self.args.unlink()
        (self.assets / 'fingerprints.tsv').write_bytes(b'tampered\n')
        result = self.invoke()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('mismatch', result.stderr)
        self.assertFalse(self.args.exists())

    def test_modified_script_or_list_never_executes_even_with_modified_manifest(self):
        for target in ('demudhra-linux.sh', 'fingerprints.tsv'):
            original = (self.assets / target).read_bytes()
            (self.assets / target).write_bytes(original + b'# tampered\n')
            self.manifest()
            result = self.invoke('--yes')
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('mismatch', result.stderr)
            self.assertFalse(self.args.exists())
            (self.assets / target).write_bytes(original)

    def test_manifest_is_not_an_authentication_input(self):
        (self.assets / 'SHA256SUMS').write_text('not a manifest\n')
        result = self.invoke('--list')
        self.assertEqual(result.returncode, 10, result.stderr)
        self.assertNotIn('/vtest/SHA256SUMS', self.downloads)

    def test_wrapper_itself_is_the_trust_root(self):
        tampered = self.assets / 'demudhra-linux.sh'
        tampered.write_bytes(tampered.read_bytes().replace(b'exit 10', b'exit 7'))
        self.wrapper.write_text(self.stamped_wrapper())
        self.assertEqual(self.invoke('--list').returncode, 7)

    def test_unsupported_os_and_unreleased_guard_do_not_download(self):
        self.env['MOCK_OS'] = 'FreeBSD'
        self.assertEqual(self.invoke().returncode, 1)
        self.assertFalse(self.downloads)
        self.env['MOCK_OS'] = 'Linux'
        self.wrapper.write_bytes((REPO / 'demudhra.sh').read_bytes())
        self.env['DEMUDHRA_RELEASE_URL'] = self.url + '/vtest'
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn('UNRELEASED', result.stderr)
        self.assertFalse(self.downloads)

    def test_missing_curl_fails_before_download(self):
        (self.bin / 'awk').symlink_to(shutil.which('awk'))
        (self.bin / 'dash').symlink_to(shutil.which('dash') or shutil.which('sh'))
        (self.bin / 'sh').symlink_to(shutil.which('sh'))
        self.env['PATH'] = str(self.bin)
        result = self.invoke()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('curl is required', result.stderr)
        self.assertFalse(self.downloads)

    def test_real_https_curl_pipe_passes_flags_and_exit_code(self):
        (self.server_base / 'run').write_bytes(self.wrapper.read_bytes())
        command = f'curl -fsSL {shlex.quote(self.url + "/run")} | {shlex.join(SHELL)} -s -- --dry-run --include-aaa'
        result = subprocess.run(SHELL + ['-c', command], env=self.env,
                                capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 10, result.stderr)
        self.assertEqual(self.args.read_text().splitlines(), ['--dry-run', '--include-aaa'])

    def test_actual_built_release_https_list_and_tamper(self):
        dest = self.server_base / 'actual-dist'
        result = subprocess.run([sys.executable, str(REPO / 'tools/release.py'),
            '--version', '1.2.3', '--url', self.url + '/actual-dist/v1.2.3',
            '--output', str(dest)], capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.wrapper.write_bytes((dest / 'run').read_bytes())
        self.env.update({'DEMUDHRA_TESTING': '1', 'DEMUDHRA_TEST_ROOT': '/does-not-exist',
                         'DEMUDHRA_TEST_FINGERPRINTS': '/does-not-exist'})
        result = self.invoke('--list')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('86a1ecba', result.stdout.lower())
        self.assertNotIn('d7a7a0fb5d7e2731', result.stdout.lower())
        self.assertNotIn('WARNING', result.stderr)
        target = dest / 'v1.2.3/demudhra-linux.sh'
        target.write_bytes(target.read_bytes() + b'\n# tampered\n')
        (dest / 'v1.2.3/SHA256SUMS').write_text(
            hashlib.sha256(target.read_bytes()).hexdigest() + '  demudhra-linux.sh\n')
        result = self.invoke('--list')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('mismatch', result.stderr)

    def test_help_and_version_do_not_download(self):
        for flag in ('--help', '--version'):
            self.assertEqual(self.invoke(flag).returncode, 0)
            self.assertFalse(self.downloads)
        self.assertIn('--yes', self.invoke('--help').stdout)


class ReleaseBuild(unittest.TestCase):
    def build(self, *args):
        return subprocess.run([sys.executable, str(REPO / 'tools/release.py'), *args],
                              capture_output=True, text=True, timeout=45)

    def test_homepage_and_catalog_counts_match_tsv(self):
        rows = [line.split('\t') for line in (REPO / 'data/fingerprints.tsv').read_text().splitlines()
                if line and not line.startswith('#')]
        groups = [group for _, group, _, _ in rows]
        root_subject, = [subject for _, group, subject, _ in rows if group == 'default-root']
        root_name = re.search(r'(?:^|,)CN=([^,]+)', root_subject).group(1)
        self.assertEqual(root_name, 'emSign ECC Root CA - G3')
        default = groups.count('default-root') + groups.count('default-intermediate')
        more = groups.count('all-emudhra-root')
        self.assertEqual((default, more, groups.count('opt-in-cross-sign'), len(rows)), (17, 25, 1, 43))
        with tempfile.TemporaryDirectory(prefix='demudhra-site-') as base:
            dest = Path(base) / 'dist'
            result = self.build('--version', '1.2.3', '--output', str(dest))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            home = (dest / 'index.html').read_text()
            self.assertNotIn('{{', home)
            self.assertIn(f'The default set is {default} certificates: {root_name} plus the 16 above.', home)
            self.assertIn(f'{default + more} instead of {default}: adds the {more} other eMudhra roots', home)
            self.assertIn(f'The full list is {len(rows)}: those {default}, the {more} that', home)
            self.assertIn('v1.2.3', home)
            self.assertIn('<span class="ask">found ', home)
            catalog = (dest / 'certs/index.html').read_text()
            self.assertIn(f'The list has {len(rows)} certificates. A default run removes {default}.', catalog)
            self.assertIn(f'adds {more} more, for {default + more} eMudhra certificates.', catalog)
            for sha, group, subject, _ in rows:
                self.assertEqual(catalog.count(f'<td class="fp">{sha}</td>'), 1, sha)
            for group, title in (('default-root', 'default: root'), ('default-intermediate', 'default: intermediates'),
                                 ('all-emudhra-root', '--all-emudhra'), ('opt-in-cross-sign', '--include-aaa')):
                self.assertIn(f'<h2>{title} ({groups.count(group)})</h2>', catalog)
            certs = json.loads((dest / 'data/certs.json').read_text())
            self.assertEqual(certs, json.loads((REPO / 'data/certs.json').read_text()))

    def test_site_only_and_carry(self):
        with tempfile.TemporaryDirectory(prefix='demudhra-site-only-') as base:
            dest = Path(base) / 'site'
            result = self.build('--site-only', '--version', '1.2.3', '--output', str(dest))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual({p.name for p in dest.iterdir()},
                             {'index.html', '404.html', 'style.css', 'favicon.svg', 'og.png', 'fonts', 'certs', 'data'})
            old = Path(base) / 'v1.0.0'
            old.mkdir()
            (old / 'a.txt').write_text('a\n')
            (old / 'SHA256SUMS').write_text(hashlib.sha256(b'a\n').hexdigest() + '  a.txt\n')
            dest = Path(base) / 'dist'
            result = self.build('--version', '1.2.3', '--output', str(dest), '--carry', str(old))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((dest / 'v1.0.0/a.txt').read_text(), 'a\n')
            (old / 'a.txt').write_text('tampered\n')
            result = self.build('--version', '1.2.3', '--output', str(Path(base) / 'dist2'), '--carry', str(old))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('does not match its SHA256SUMS', result.stderr)

    def test_versioned_layout_pins_every_download_and_strips_test_hooks(self):
        before = (REPO / 'demudhra.sh').read_bytes()
        with tempfile.TemporaryDirectory(prefix='demudhra-release-') as base:
            dest = Path(base) / 'dist'
            result = self.build('--version', '1.2.3', '--output', str(dest))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            assets = dest / 'v1.2.3'
            self.assertEqual({p.name for p in dest.iterdir()}, {'run', 'v1.2.3', 'index.html', '404.html', 'style.css',
                             'favicon.svg', 'og.png', 'fonts', 'certs', 'data', '_headers'})
            self.assertEqual({p.name for p in assets.iterdir()},
                {'demudhra-linux.sh', 'demudhra-macos.sh', 'fingerprints.tsv', 'certs.json', 'SHA256SUMS'})
            rows = (assets / 'SHA256SUMS').read_text().splitlines()
            self.assertEqual(len(rows), 4)
            for row in rows:
                expected, name = row.split('  ', 1)
                self.assertEqual(hashlib.sha256((assets / name).read_bytes()).hexdigest(), expected)
            wrapper = (dest / 'run').read_text()
            self.assertIn("RELEASE_URL='https://demudhra.sh/v1.2.3'", wrapper)
            self.assertIn('curl -fsSL https://demudhra.sh/run | sh', (dest / 'index.html').read_text())
            self.assertEqual((dest / 'certs/index.html').read_text().count('<td class="fp">'), 43)
            self.assertEqual((dest / 'data/certs.json').read_bytes(), (REPO / 'data/certs.json').read_bytes())
            headers = (dest / '_headers').read_text()
            self.assertIn('/run\n  Content-Type: text/plain; charset=utf-8', headers)
            self.assertIn('X-Content-Type-Options: nosniff', headers)
            self.assertIn('/fonts/*\n  Cache-Control: public, max-age=31536000, immutable', headers)
            self.assertEqual(headers.count('Content-Type: text/plain'), 2)
            for name, pin in (('demudhra-linux.sh', 'LINUX_SHA256'),
                              ('demudhra-macos.sh', 'MACOS_SHA256'),
                              ('fingerprints.tsv', 'FINGERPRINTS_SHA256')):
                digest = hashlib.sha256((assets / name).read_bytes()).hexdigest()
                self.assertIn(f"{pin}='{digest}'", wrapper)
            for platform in ('linux', 'macos'):
                script = assets / f'demudhra-{platform}.sh'
                self.assertNotIn('DEMUDHRA_TEST', script.read_text())
                result = subprocess.run(SHELL + ['-n', str(script)], capture_output=True, text=True, timeout=45)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((REPO / 'demudhra.sh').read_bytes(), before)
            repeated = self.build('--version', '1.2.3', '--output', str(dest))
            self.assertNotEqual(repeated.returncode, 0)
            self.assertIn('refusing to overwrite', repeated.stderr)

    def test_build_rejects_non_https_or_unquotable_url(self):
        with tempfile.TemporaryDirectory(prefix='demudhra-release-') as base:
            dest = Path(base) / 'dist'
            for url in ('http://example.invalid/ref', 'https://example.invalid/ref?next=x',
                        "https://example.invalid/ref'quote", 'https://example.invalid/ref\nnext'):
                result = self.build('--url', url, '--output', str(dest))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(dest.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
