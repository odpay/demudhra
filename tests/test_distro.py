#!/usr/bin/env python3
"""Check distro-family and persistent distrust selection with fake os-release."""
from pathlib import Path
import unittest

from test_files import Sandbox


class DistroDetection(Sandbox):
    def test_id_and_id_like_families(self):
        cases = [
            ('linuxmint', 'ubuntu debian', 'debian'),
            ('pop', 'ubuntu debian', 'debian'),
            ('kali', 'debian', 'debian'),
            ('raspbian', 'debian', 'debian'),
            ('zorin', 'ubuntu debian', 'debian'),
            ('devuan', 'debian', 'debian'),
            ('amzn', 'centos rhel fedora', 'rhel'),
            ('custom-derivative', 'ubuntu debian', 'debian'),
            ('custom-rhel', 'rhel fedora', 'rhel'),
            ('archlinux', '', 'arch'),
            ('opensuse-tumbleweed', 'suse opensuse', 'suse'),
            ('alpine', '', 'alpine'),
        ]
        for identifier, like, family in cases:
            with self.subTest(identifier=identifier):
                self.put('etc/os-release', f'ID={identifier}\nID_LIKE="{like}"\n'.encode())
                output = self.invoke('--dry-run')
                self.assertIn(f'Linux distro: {family} ', output)

    def test_version_name_and_vendor_file_fallbacks(self):
        for release in (b'ID=custom\nVERSION="Debian 13 (trixie)"\n',
                        b'NAME="Raspberry Pi OS"\n',
                        b'ID=linuxmint\n'):
            with self.subTest(release=release):
                self.put('etc/os-release', release)
                self.assertIn('Linux distro: debian ', self.invoke('--dry-run'))
        (self.root / 'etc/os-release').unlink()
        self.put('usr/lib/os-release', b'ID=amzn\nVERSION_ID=2023\n')
        self.assertIn('Linux distro: rhel ', self.invoke('--dry-run'))

    def test_os_release_is_never_executed(self):
        sentinel = self.base / 'should-not-exist'
        self.put('etc/os-release', f'ID=$(touch "{sentinel}")\nID_LIKE=debian\n'.encode())
        self.assertIn('Linux distro: debian ', self.invoke('--dry-run'))
        self.assertFalse(sentinel.exists())

    def test_existing_distrust_directory_preference_and_package_restoration(self):
        for family, base in [('fedora', 'etc/pki/ca-trust/source'),
                             ('archlinux', 'etc/ca-certificates/trust-source'),
                             ('opensuse-tumbleweed', 'etc/pki/trust')]:
            for directory_name in ('blocklist', 'blacklist'):
                with self.subTest(family=family, directory=directory_name):
                    self.put('etc/os-release', f'ID={family}\n'.encode())
                    directory = self.root / base / directory_name
                    directory.mkdir(parents=True, exist_ok=True)
                    target = self.put('usr/share/pki/ca-trust-source/anchors/target.crt', self.bad)
                    self.apply()
                    record = directory / f'demudhra-{self.bad_sha}.pem'
                    self.assertTrue(record.is_file())
                    self.assertIn(b'BEGIN CERTIFICATE', record.read_bytes())
                    target.write_bytes(self.bad)
                    self.assertTrue(record.is_file(), 'package-style restoration lost persistent distrust')
                    self.undo()
                    self.assertFalse(record.exists())
                    target.unlink()
                    directory.rmdir()

    def test_installed_manual_or_safe_superset_selects_directory(self):
        self.put('etc/os-release', b'ID=fedora\n')
        manual = self.put('usr/share/man/man8/update-ca-trust.8',
                          b'Install distrust in /etc/pki/ca-trust/source/blocklist/\n')
        target = self.put('usr/share/pki/ca-trust-source/anchors/target.crt', self.bad)
        self.apply()
        modern = self.root / f'etc/pki/ca-trust/source/blocklist/demudhra-{self.bad_sha}.pem'
        legacy = self.root / f'etc/pki/ca-trust/source/blacklist/demudhra-{self.bad_sha}.pem'
        self.assertTrue(modern.is_file())
        self.assertFalse(legacy.exists())
        self.undo()
        modern.parent.rmdir()
        manual.unlink()
        output = self.apply()
        self.assertIn('safe superset', output)
        self.assertTrue(modern.is_file())
        self.assertTrue(legacy.is_file())
        self.undo()
        self.assertEqual(target.read_bytes(), self.bad)


if __name__ == '__main__':
    unittest.main(verbosity=2)
