#!/usr/bin/env python3
"""Exercise bounded default discovery through the public command-line scripts."""
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import unittest

from test_files import REPO, Sandbox, command, fingerprint, snapshot
from test_stores import KEYTOOL


class Discovery(Sandbox):
    def setUp(self):
        super().setUp()
        self.env['DEMUDHRA_TEST_DEFAULT_SCAN'] = '1'
        for name in ('SSL_CERT_DIR', 'HTTPLIB2_CA_CERTS', 'GRPC_DEFAULT_SSL_ROOTS_FILE_PATH',
                     'CARGO_HTTP_CAINFO', 'DENO_CERT', 'BUNDLE_SSL_CA_CERT', 'PIP_CERT',
                     'NPM_CONFIG_CAFILE', 'npm_config_cafile', 'GIT_SSL_CAINFO'):
            self.env.pop(name, None)

    def check_locations(self, locations, script='demudhra-linux.sh'):
        paths = [self.put(location, self.good + self.bad) for location in locations]
        before = snapshot(self.root)
        output = self.invoke('--dry-run', '--verbose', '--no-keychains', script=script, expected=10)
        for path in paths:
            self.assertIn(str(path), output)
        self.assertEqual(snapshot(self.root), before)
        self.apply('--no-keychains', script=script)
        for path in paths:
            self.assertEqual(path.read_bytes(), self.good, str(path))
        self.undo()
        self.assertEqual(snapshot(self.root), before)

    def test_version_managers_and_python_node_ruby_distributions(self):
        roots = ['.asdf/installs/python/3.14', '.local/share/mise/installs/python/3.14',
                 '.rtx/installs/python/3.14', '.sdkman/candidates/java/25', '.gradle/jdks/25',
                 '.jdks/25', '.rbenv/versions/3.4', '.rvm/rubies/3.4', '.volta/tools/image/node/22',
                 '.fnm/node-versions/v22', '.local/share/fnm/node-versions/v22',
                 '.pyenv/plugins/plugin/extra', '.local/pipx/venvs/tool', '.local/share/pipx/venvs/tool',
                 '.local/share/uv/python/cpython-3.14', '.local/share/uv/tools/tool', '.rye/py/cpython-3.14',
                 'miniforge3', 'mambaforge', 'micromamba/envs/tool', '.conda/envs/tool',
                 '.vscode/extensions/vendor.tool', '.cursor/extensions/vendor.tool',
                 '.local/share/JetBrains/Toolbox/apps/idea']
        self.check_locations(['home/tester/' + root + '/lib/python3/site-packages/certifi/cacert.pem'
                              for root in roots])

    def test_cloud_cli_and_conda_system_locations(self):
        roots = ['opt/conda', 'opt/miniconda3', 'opt/anaconda3', 'home/tester/google-cloud-sdk',
                 'usr/lib/google-cloud-sdk', 'opt/google-cloud-sdk', 'usr/local/aws-cli/v2/current',
                 'home/tester/.local/aws-cli/v2/current', 'opt/az', 'home/tester/.azure-cli-env']
        self.check_locations([root + '/lib/python3/site-packages/certifi/cacert.pem' for root in roots])

    def test_macos_developer_apps_java_home_and_package_managers(self):
        roots = ['Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.14',
                 'Applications/Xcode-beta.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.14',
                 'Applications/IDE.app/Contents/jbr', 'Applications/Other.app/Contents/Resources/runtime',
                 'home/tester/Library/Java/JavaVirtualMachines/jdk/Contents/Home',
                 'home/tester/Library/Application Support/JetBrains/Toolbox/apps/idea/jbr',
                 'opt/homebrew/etc/openssl@3', 'opt/homebrew/etc/openssl',
                 'opt/homebrew/etc/ca-certificates',
                 'opt/homebrew/Cellar/ca-certificates/2026', 'opt/homebrew/Cellar/openssl@3/3.6',
                 'opt/homebrew/Cellar/python@3.14/3.14', 'opt/homebrew/Cellar/node/22',
                 'usr/local/etc/openssl@3', 'usr/local/etc/ca-certificates', 'usr/local/Cellar/python/3.14',
                 'opt/local/etc/openssl', 'opt/local/share/curl']
        self.check_locations([root + '/lib/python3/site-packages/certifi/cacert.pem' for root in roots],
                             script='demudhra-macos.sh')

    def test_linux_ssl_java_package_roots_and_bundle_filenames(self):
        roots = ['usr/lib/ssl', 'usr/local/ssl', 'usr/share/ca-certificates-java', 'etc/pki/java',
                 'usr/lib/jvm/first', 'usr/lib/jvm/second']
        names = ['cacert.pem', 'cert.pem', 'curl-ca-bundle.crt', 'ca-bundle.crt',
                 'ca-certificates.crt', 'tls-ca-bundle.pem', 'ca-root-nss.crt']
        self.check_locations([root + '/a/b/c/d/e/' + names[index % len(names)]
                              for index, root in enumerate(roots)] +
                             ['usr/local/ssl/bundles/' + name for name in names])

    def test_environment_files_and_hashed_ssl_cert_directories(self):
        names = ['HTTPLIB2_CA_CERTS', 'GRPC_DEFAULT_SSL_ROOTS_FILE_PATH', 'CARGO_HTTP_CAINFO',
                 'DENO_CERT', 'BUNDLE_SSL_CA_CERT', 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE']
        paths = []
        for name in names:
            path = self.put('configured/' + name + '.data', self.good + self.bad)
            self.env[name] = str(path)
            paths.append(path)
        hashed = self.put('hashed/12aB34cD.0', self.good + self.bad)
        ignored = self.put('hashed/arbitrary', self.bad)
        wrong_suffix = self.put('hashed/12345678.0junk', self.bad)
        nested = self.put('hashed/nested/12ab34cd.1', self.bad)
        hashed2 = self.put('hashed2/ffffffff.9', self.good + self.bad)
        alias = self.root / 'hashed/aaaaaaaa.1'
        alias.symlink_to(hashed)
        self.env['SSL_CERT_DIR'] = str(hashed.parent) + ':' + str(hashed2.parent)
        self.apply()
        for path in paths + [hashed, hashed2]:
            self.assertEqual(path.read_bytes(), self.good, str(path))
        self.assertEqual(ignored.read_bytes(), self.bad)
        self.assertEqual(wrong_suffix.read_bytes(), self.bad)
        self.assertEqual(nested.read_bytes(), self.bad)
        self.assertEqual(alias.read_bytes(), self.good)

    def test_configuration_paths_are_literal_and_tools_are_not_executed(self):
        configs = [('home/tester/.npmrc', 'cafile = "{}"'),
                   ('home/tester/.pip/pip.conf', 'cert = {}'),
                   ('home/tester/.config/pip/pip.conf', 'cert = {}'),
                   ('home/tester/.config/pip/pip.ini', 'cert = {}'),
                   ('home/tester/pip.ini', 'cert = {}'),
                   ('home/tester/.pip/pip.ini', 'cert = {}'),
                   ('home/tester/pip/pip.ini', 'cert = {}'),
                   ('home/tester/Library/Application Support/pip/pip.conf', 'cert = {}'),
                   ('home/tester/.curlrc', 'cacert = "{}"'),
                   ('home/tester/.wgetrc', 'ca_certificate = {}'),
                   ('etc/pip.conf', 'cert = {}'), ('etc/xdg/pip/pip.conf', 'cert = {}'),
                   ('Library/Application Support/pip/pip.conf', 'cert = {}')]
        targets = []
        for index, (config, template) in enumerate(configs):
            target = self.put('configured/target ' + str(index) + '.data', self.good + self.bad)
            self.put(config, ('# ignored\n' + template.format(target) + '\n').encode())
            targets.append(target)
        for scope, config in [('global', 'home/tester/.gitconfig'), ('system', 'etc/gitconfig')]:
            target = self.put('configured/git-' + scope + '.data', self.good + self.bad)
            self.put(config, ('[http]\nsslCAInfo = "' + str(target) + '"\n').encode())
            targets.append(target)
        malicious = self.put('configured/$(touch forbidden).data', self.good + self.bad)
        self.put('home/tester/.npmrc', ('cafile="' + str(malicious) + '"\n').encode())
        targets[0] = malicious
        bindir = self.root / 'bin'
        bindir.mkdir()
        marker = self.base / 'executed'
        for name in ('npm', 'pip', 'python', 'ruby'):
            shim = bindir / name
            shim.write_text('#!/bin/sh\ntouch ' + shlex.quote(str(marker)) + '\nexit 99\n')
            shim.chmod(0o755)
        self.env['PATH'] = str(bindir) + ':' + self.env['PATH']
        self.apply('--no-keychains')
        for target in targets:
            self.assertEqual(target.read_bytes(), self.good, str(target))
        self.assertFalse(marker.exists())
        self.assertFalse((REPO / 'forbidden').exists())

    def test_config_tilde_uses_the_home_owning_the_config(self):
        targets = []
        for user in ('tester', 'alice'):
            targets.append(self.put('home/' + user + '/configured.data', self.good + self.bad))
            self.put('home/' + user + '/.npmrc', b'cafile = ~/configured.data\n')
        before = snapshot(self.root)
        self.apply()
        for target in targets:
            self.assertEqual(target.read_bytes(), self.good)
        self.undo()
        self.assertEqual(snapshot(self.root), before)

    def test_missing_explicit_environment_bundle_keeps_failure_status(self):
        self.env['HTTPLIB2_CA_CERTS'] = str(self.root / 'missing.data')
        output = self.invoke('--dry-run', expected=2)
        self.assertIn('Environment bundle does not exist', output)

    def test_default_bounds_and_pruned_frameworks_are_respected(self):
        paths = ['Applications/App.app/Contents/Frameworks/Electron Framework.framework/cert.pem',
                 'Applications/App.app/Contents/Frameworks/Chromium Embedded Framework.framework/cert.pem',
                 'Applications/App.app/Contents/' + 'nested/' * 15 + 'cacert.pem',
                 'snap/core/current/cert.pem', 'opt/overlay/inside/cert.pem',
                 'home/tester/.local/share/uv/.git/cacert.pem']
        for location in paths:
            self.put(location, self.bad)
        before = snapshot(self.root)
        self.apply('--no-keychains', script='demudhra-macos.sh')
        self.assertEqual(snapshot(self.root), before)

    def test_flatpak_runtime_is_report_only(self):
        paths = [self.put(root + '/org.example/x86_64/stable/active/files/etc/cert.pem', self.bad)
                 for root in ('var/lib/flatpak/runtime', 'home/tester/.local/share/flatpak/runtime')]
        before = snapshot(self.root)
        output = self.apply(expected=3)
        self.assertIn('report-only', output)
        self.assertIn('cannot_change=2', [line for line in output.splitlines() if line.startswith('Summary:')][-1])
        self.assertEqual(snapshot(self.root), before)
        self.assertFalse(self.backups.exists())
        for path in paths:
            self.assertIn(str(path), output)

    def test_compiled_runtime_versions_are_prefixed_and_counted(self):
        bindir = self.root / 'bin'
        bindir.mkdir()
        versions = {'node': 'v20.19.2', 'go': 'go version go1.26 linux/amd64',
                    'deno': 'deno 2.6.0\nv8 hidden detail', 'bun': '1.4.0',
                    'rustup': 'rustup 1.29.0\nextra detail', 'cargo': 'cargo 1.92.0'}
        for name, version in versions.items():
            shim = bindir / name
            shim.write_text('#!/bin/sh\nprintf "%s\\n" ' + shlex.quote(version) + '\n')
            shim.chmod(0o755)
        self.env.update(PATH=str(bindir) + ':' + self.env['PATH'], DEMUDHRA_TEST_RUNTIMES='1')
        output = self.invoke('--dry-run')
        for name, version in versions.items():
            first = version.splitlines()[0]
            expected = first if first.startswith(name + ' ') else name + ' ' + first
            self.assertEqual(sum(line.startswith(expected + ': ') for line in output.splitlines()), 1, output)
        self.assertNotIn('\nv20.19.2\n', output)
        self.assertNotIn('hidden detail', output)
        self.assertNotIn('extra detail', output)
        self.assertIn('go version go1.26 linux/amd64: Go uses the system trust store', output)
        self.assertIn('cannot_change=5', output)

    def test_new_java_names_java_home_and_every_java_path(self):
        self.assertTrue(KEYTOOL, 'keytool is required for Java discovery verification')
        source = self.base / 'source.pem'
        source.write_bytes(self.bad)
        prototype = self.base / 'prototype.jks'
        command([KEYTOOL, '-importcert', '-noprompt', '-storetype', 'JKS', '-keystore', prototype,
                 '-storepass', 'changeit', '-alias', 'selected', '-file', source])
        paths = []
        for relative in ['etc/ssl/certs/java/cacerts', 'usr/share/ca-certificates-java/store.keystore',
                         'etc/pki/java/truststore.custom', 'usr/lib/jvm/first/lib/security/jssecacerts',
                         'configured/java-home/lib/security/cacerts',
                         'configured/java-first/lib/security/cacerts',
                         'configured/java-second/jre/lib/security/cacerts']:
            paths.append(self.put(relative, prototype.read_bytes()))
        self.env['JAVA_HOME'] = str(self.root / 'configured/java-home')
        dirs = []
        for name in ('first', 'second'):
            executable = self.put('configured/java-' + name + '/bin/java', b'#!/bin/sh\nexit 99\n')
            executable.chmod(0o755)
            aliasdir = self.root / ('java-path-' + name)
            aliasdir.mkdir()
            (aliasdir / 'java').symlink_to(executable)
            dirs.append(str(aliasdir))
        self.env['PATH'] = ':'.join(dirs + [str(Path(KEYTOOL).parent), self.env['PATH']])
        before = snapshot(self.root)
        self.invoke('--dry-run', '--verbose', expected=10)
        self.assertEqual(snapshot(self.root), before)
        self.apply()
        for path in paths:
            result = subprocess.run([KEYTOOL, '-list', '-keystore', str(path), '-storepass', 'changeit',
                                     '-alias', 'selected'], capture_output=True, timeout=45)
            self.assertNotEqual(result.returncode, 0, str(path))
        self.undo()
        self.assertEqual(snapshot(self.root), before)


class AppleBundle(Sandbox):
    def test_apple_format_removes_only_matching_block_headers_and_reverifies(self):
        fixture = (REPO / 'tests/fixtures/apple-cert.pem').read_bytes()
        certs = re.findall(br'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n', fixture, re.S)
        self.overrides.write_text(f'{fingerprint(certs[1])}\tdefault-root\tTest\thttps://example.invalid\n')
        path = self.put('etc/ssl/cert.pem', fixture)
        before = snapshot(self.root)
        output = self.invoke('--dry-run', '--no-keychains', script='demudhra-macos.sh', expected=10)
        self.assertIn('already protected by Apple', output)
        self.assertIn('command-line tools', output)
        self.assertIn('Rerun demudhra after updating', output)
        self.assertEqual(snapshot(self.root), before)
        output = self.apply('--no-keychains', script='demudhra-macos.sh')
        expected = fixture[:fixture.index(b'### Selected fixture certificate')]
        self.assertEqual(path.read_bytes(), expected)
        self.assertIn('verified by re-parsing', output)
        self.assertEqual(fingerprint(path.read_bytes()), fingerprint(certs[0]))
        self.undo()
        self.assertEqual(snapshot(self.root), before)

    def test_postapply_reverification_rejects_an_altered_actual_file(self):
        target = self.put('etc/ssl/cert.pem', self.good + self.bad)
        appended = self.base / 'appended.pem'
        appended.write_bytes(self.bad)
        bindir = self.base / 'mv-bin'
        bindir.mkdir()
        shim = bindir / 'mv'
        shim.write_text('#!/bin/sh\n' + shlex.quote(shutil.which('mv')) + ' "$@" || exit $?\n'
                        + 'for destination do :; done\n'
                        + 'if [ "$destination" = "$CORRUPT_TARGET" ]; then cat "$CORRUPT_PEM" >> "$destination"; fi\n')
        shim.chmod(0o755)
        self.env.update(PATH=str(bindir) + ':' + self.env['PATH'], CORRUPT_TARGET=str(target),
                        CORRUPT_PEM=str(appended))
        output = self.apply('--no-keychains', script='demudhra-macos.sh', expected=2)
        self.assertIn('Certificate re-verification failed after removal', output)
        self.env['PATH'] = os.environ['PATH']
        self.undo()
        self.assertEqual(target.read_bytes(), self.good + self.bad)

    def test_aaa_warning_only_when_fingerprint_is_present_and_not_selected(self):
        self.overrides.write_text(f'{self.bad_sha}\tdefault-root\tTest\thttps://example.invalid\n'
                                  f'{self.good_sha}\topt-in-cross-sign\tOptional\thttps://example.invalid\n')
        path = self.put('etc/ssl/cert.pem', self.good + self.bad)
        output = self.invoke('--dry-run', '--no-keychains', script='demudhra-macos.sh', expected=10)
        self.assertEqual(output.count('6 Sectigo cross-signed intermediates still verify via AAA in this file'), 1)
        self.assertIn('unaffected Sectigo intermediates', output)
        output = self.apply('--include-aaa', '--no-keychains', script='demudhra-macos.sh')
        self.assertNotIn('6 Sectigo cross-signed', output)
        self.assert_contents_or_removed(path, b'')
        self.undo()
        path.write_bytes(self.bad)
        output = self.invoke('--dry-run', '--no-keychains', script='demudhra-macos.sh', expected=10)
        self.assertNotIn('6 Sectigo cross-signed', output)


if __name__ == '__main__':
    unittest.main(verbosity=2)
