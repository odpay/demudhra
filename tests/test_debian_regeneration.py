#!/usr/bin/env python3
"""Use Debian's real updater with every input/output/hook path confined to temp."""
import re
from pathlib import Path
import shutil
import subprocess
import unittest

from test_files import Sandbox, fingerprint, snapshot

PEM_BLOCK = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)

UPDATER = shutil.which('update-ca-certificates') or ('/usr/sbin/update-ca-certificates' if Path('/usr/sbin/update-ca-certificates').is_file() else None)


class DebianRegeneration(Sandbox):
    def test_regeneration_preserves_original_survivor_bytes_and_undo(self):
        before = self.good.replace(b"\n", b"\r\n") + self.bad
        bundle = self.put("etc/ssl/certs/ca-certificates.crt", before)
        shim = self.base / "regen-shim"
        shim.write_text("""#!/usr/bin/env python3
import pathlib, sys
p=pathlib.Path(sys.argv[1])/'etc/ssl/certs/ca-certificates.crt'
p.write_bytes(p.read_bytes().replace(b'\\r\\n',b'\\n'))
""")
        shim.chmod(0o755)
        self.env['DEMUDHRA_TEST_REGEN'] = str(shim)
        original = snapshot(self.root)
        self.invoke(expected=10)
        self.assertEqual(snapshot(self.root), original)
        self.apply()
        self.assertEqual(bundle.read_bytes(), self.good.replace(b"\n", b"\r\n"))
        self.undo()
        self.assertEqual(snapshot(self.root), original)

    @unittest.skipUnless(UPDATER, 'Debian updater unavailable; NOT RUN')
    def test_native_updater_in_isolated_directories(self):
        if '--hooksdir' not in Path(UPDATER).read_text(errors='replace'):
            self.skipTest('Updater lacks directory override options; NOT RUN')
        source = self.root / 'usr/share/ca-certificates'
        local = self.root / 'usr/local/share/ca-certificates'
        output = self.root / 'etc/ssl/certs'
        hooks = self.root / 'empty-hooks'
        config = self.root / 'etc/ca-certificates.conf'
        for directory in source, local, output, hooks:
            directory.mkdir(parents=True, exist_ok=True)
        config.write_text('# isolated fixture\n')
        target = self.put('usr/local/share/ca-certificates/target.crt', self.bad)
        good = self.put('usr/local/share/ca-certificates/survivor.crt', self.good)
        args = [UPDATER, '--fresh', '--certsconf', str(config),
                '--certsdir', str(source), '--localcertsdir', str(local),
                '--etccertsdir', str(output), '--hooksdir', str(hooks)]
        def update():
            result = subprocess.run(args, env=self.env, capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        def hashes():
            return [fingerprint(p) for p in PEM_BLOCK.findall((output / 'ca-certificates.crt').read_bytes())]
        update()
        self.assertIn(self.bad_sha, hashes())
        before = snapshot(self.root)
        self.invoke(expected=10)
        self.assertEqual(snapshot(self.root), before)
        self.apply()
        self.assertFalse(target.exists())
        self.assertEqual(good.read_bytes(), self.good)
        update()
        self.assertNotIn(self.bad_sha, hashes())
        self.assertIn(self.good_sha, hashes())
        update()
        self.assertNotIn(self.bad_sha, hashes())
        self.invoke()
        print('PASS: real Debian updater in temporary directories; target absent after two regenerations')

    @unittest.skipUnless(UPDATER, 'Debian updater unavailable; NOT RUN')
    def test_packaged_source_stays_disabled_after_reinstall_and_undo(self):
        if '--hooksdir' not in Path(UPDATER).read_text(errors='replace'):
            self.skipTest('Updater lacks directory override options; NOT RUN')
        source = self.root / 'usr/share/ca-certificates'
        local = self.root / 'usr/local/share/ca-certificates'
        output = self.root / 'etc/ssl/certs'
        hooks = self.root / 'empty-hooks'
        for directory in source, local, output, hooks:
            directory.mkdir(parents=True, exist_ok=True)
        config = self.put('etc/ca-certificates.conf',
                          b'# packaged fixture\nmozilla/target.crt\nmozilla/same-subject.crt\n')
        target = self.put('usr/share/ca-certificates/mozilla/target.crt', self.bad)
        survivor = self.put('usr/share/ca-certificates/mozilla/same-subject.crt', self.good)
        local_target = self.put('usr/local/share/ca-certificates/local-target.crt', self.bad)
        original_config = config.read_bytes()
        args = [UPDATER, '--fresh', '--certsconf', str(config),
                '--certsdir', str(source), '--localcertsdir', str(local),
                '--etccertsdir', str(output), '--hooksdir', str(hooks)]

        def update():
            result = subprocess.run(args, env=self.env, capture_output=True,
                                    text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return [fingerprint(block) for block in
                    PEM_BLOCK.findall((output / 'ca-certificates.crt').read_bytes())]

        self.assertIn(self.bad_sha, update())
        self.invoke('--dry-run', expected=10)
        self.assertEqual(config.read_bytes(), original_config)
        self.apply()
        self.assertIn('!mozilla/target.crt', config.read_text().splitlines())
        self.assertIn('mozilla/same-subject.crt', config.read_text().splitlines())
        self.assertNotIn('!mozilla/same-subject.crt', config.read_text().splitlines())
        self.assertFalse(local_target.exists())
        self.assertNotIn(self.bad_sha, update())
        target.write_bytes(self.bad)
        after_reinstall = update()
        self.assertNotIn(self.bad_sha, after_reinstall)
        self.assertIn(self.good_sha, after_reinstall)
        self.assertEqual(survivor.read_bytes(), self.good)
        self.undo()
        self.assertEqual(config.read_bytes(), original_config)
        self.assertEqual(target.read_bytes(), self.bad)
        self.assertEqual(local_target.read_bytes(), self.bad)
        self.assertIn(self.bad_sha, update())
        print('PASS: real Debian updater keeps packaged target absent after file restoration; undo restores configuration and sources')


if __name__ == '__main__':
    unittest.main(verbosity=2)
