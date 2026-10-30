#!/usr/bin/env python3
"""Exercise the shipped macOS script with an explicit security shim, never macOS stores."""

import json
import os
import subprocess
import unittest

from test_files import Sandbox, fingerprint, snapshot


SECURITY_SHIM = '''#!/usr/bin/env python3
import hashlib, json, os, pathlib, re, subprocess, sys
args = sys.argv[1:]
with open(os.environ["MOCK_SECURITY_LOG"], "a") as trace:
    trace.write(json.dumps(args) + "\\n")
op = args[0]
if op in ("trust-settings-export", "trust-settings-import"):
    if op == "trust-settings-export":
        if os.environ.get("MOCK_SECURITY_NO_TRUST_SETTINGS"):
            print("SecTrustSettingsCreateExternalRepresentation: No Trust Settings were found.", file=sys.stderr)
            sys.exit(1)
        if os.environ.get("MOCK_SECURITY_EXPORT_FAIL"):
            print("mock trust-settings export failure", file=sys.stderr)
            sys.exit(1)
        pathlib.Path(args[-1]).write_bytes(b"<?xml version='1.0'?><plist><dict/></plist>\\n")
    sys.exit(0)
store = pathlib.Path(args[-2] if op == "add-certificates" else args[-1])
root = pathlib.Path(os.environ["DEMUDHRA_TEST_ROOT"]).resolve()
if not store.resolve().is_relative_to(root):
    print("shim refuses keychain path outside test root", file=sys.stderr)
    sys.exit(90)
if op == "find-certificate":
    sys.stdout.buffer.write(store.read_bytes())
    sys.exit(0)
if op == "add-certificates":
    if args[1] != "-k": sys.exit(93)
    store.write_bytes(pathlib.Path(args[-1]).read_bytes() + store.read_bytes())
    sys.exit(0)
if op == "delete-certificate":
    if os.environ.get("MOCK_SECURITY_REFUSE_DELETE"):
        print("mock keychain locked or selector unsupported", file=sys.stderr)
        sys.exit(1)
    if args[1:3] != ["-t", "-Z"] or not re.fullmatch("[0-9a-f]{40}|[0-9a-f]{64}", args[3]):
        print("shim requires digest selector and trust-setting removal", file=sys.stderr)
        sys.exit(91)
    selector = args[3]
    if os.environ.get("MOCK_SECURITY_SHA1_ONLY") and len(selector) == 64:
        print("older security only supports SHA-1 -Z", file=sys.stderr)
        sys.exit(1)
    if os.environ.get("MOCK_SECURITY_NOOP_DELETE"):
        sys.exit(0)
    if os.environ.get("MOCK_SECURITY_DELETE_ALL"):
        store.write_bytes(b"")
        sys.exit(0)
    data = store.read_bytes()
    pattern = re.compile(rb"-----BEGIN CERTIFICATE-----\\n.*?-----END CERTIFICATE-----\\n", re.S)
    def keep(match):
        cert = match.group()
        result = subprocess.run(["openssl", "x509", "-outform", "DER"], input=cert, capture_output=True, check=True, timeout=45)
        hashing = hashlib.sha256 if len(selector) == 64 else hashlib.sha1
        return b"" if hashing(result.stdout).hexdigest() == selector else cert
    store.write_bytes(pattern.sub(keep, data))
    sys.exit(0)
print("unsupported shim operation", file=sys.stderr)
sys.exit(92)
'''


class MacOSBehaviour(Sandbox):
    def setUp(self):
        super().setUp()
        self.shim = self.base / "security"
        self.shim.write_text(SECURITY_SHIM)
        self.shim.chmod(0o755)
        self.trace = self.base / "security.jsonl"
        self.env.update({"DEMUDHRA_TESTING": "1",
                         "DEMUDHRA_TEST_SECURITY": str(self.shim),
                         "MOCK_SECURITY_LOG": str(self.trace)})
        self.system = self.put("Library/Keychains/System.keychain", self.bad + self.good)
        self.login = self.put("Users/tester/Library/Keychains/login.keychain-db", self.bad + self.good)
        self.sip = self.put("System/Library/Keychains/SystemRootCertificates.keychain", self.bad + self.good)
        self.os_bundle = self.put("etc/ssl/cert.pem", self.bad + self.good)

    def invoke(self, *args, **kwargs):
        kwargs["script"] = "demudhra-macos.sh"
        return super().invoke(*args, **kwargs)

    def commands(self):
        return [json.loads(line) for line in self.trace.read_text().splitlines()] if self.trace.exists() else []

    def test_keychain_dry_apply_backup_undo_idempotence_and_sip_reports(self):
        before = snapshot(self.root)
        output = self.invoke(expected=10)
        self.assertEqual(before, snapshot(self.root), "macOS shim dry run changed files")
        self.assertIn("SIP-protected", output)
        self.assertIn("security add-trusted-cert -d -r deny", output)
        self.assertIn("REPORT ONLY", output)
        self.assertTrue(all(c[0] == "find-certificate" for c in self.commands()))
        self.assertFalse(self.backups.exists())
        output = self.apply(expected=3)
        self.assertIn("REMOVED keychain", output)
        for store in (self.system, self.login):
            self.assertEqual(store.read_bytes(), self.good)
            self.assertEqual(fingerprint(store.read_bytes()), self.good_sha)
        self.assertEqual(self.sip.read_bytes(), self.bad + self.good)
        self.assertEqual(self.os_bundle.read_bytes(), self.good)
        deletes = [c for c in self.commands() if c[0] == "delete-certificate"]
        self.assertEqual(len(deletes), 2)
        self.assertTrue(all(c[1:4] == ["-t", "-Z", self.bad_sha] for c in deletes))
        self.assertFalse(any(c[-1] == str(self.sip) for c in deletes))
        self.assertEqual(len(list(self.backups.rglob("mac-trust-*.plist"))), 2)
        after = snapshot(self.root)
        self.apply(expected=3)
        self.assertEqual(after, snapshot(self.root), "macOS shim reapply changed files")
        self.assertEqual(len([c for c in self.commands() if c[0] == "delete-certificate"]), 2)
        self.undo()
        self.assertEqual(before, snapshot(self.root), "macOS shim undo did not restore certificate bytes")
        undo_text = next(self.backups.rglob("undo.sh")).read_text()
        self.assertIn("add-certificates", undo_text)
        self.assertNotIn("cp -p ", "\n".join(line for line in undo_text.splitlines() if "keychain" in line))
        self.assertEqual(len([c for c in self.commands() if c[0] == "trust-settings-import"]), 2)

    def test_no_explicit_shim_disables_keychain_commands_in_fake_root(self):
        self.env.pop("DEMUDHRA_TEST_SECURITY")
        before = snapshot(self.root)
        output = self.apply()
        self.assertIn("keychain commands disabled", output)
        self.assertFalse(self.trace.exists())
        self.assertEqual(self.os_bundle.read_bytes(), self.good)
        self.assertEqual(self.system.read_bytes(), self.bad + self.good)

    def test_keychain_skip_and_system_skip_are_observed(self):
        before = snapshot(self.root)
        self.apply("--no-keychains")
        self.assertEqual(self.os_bundle.read_bytes(), self.good)
        self.os_bundle.write_bytes(self.bad + self.good)
        self.assertFalse(self.trace.exists())
        self.apply("--no-system")
        self.assertEqual(self.system.read_bytes(), self.bad + self.good)
        self.assertEqual(self.sip.read_bytes(), self.bad + self.good)
        self.assertEqual(self.os_bundle.read_bytes(), self.bad + self.good)
        self.assertEqual(self.login.read_bytes(), self.good)

    def test_failed_trust_backup_prevents_all_deletion(self):
        self.env["MOCK_SECURITY_EXPORT_FAIL"] = "1"
        before = snapshot(self.root)
        output = self.apply(expected=2)
        self.assertIn("Cannot export", output)
        self.assertEqual(self.os_bundle.read_bytes(), self.good)
        self.assertEqual(self.system.read_bytes(), self.bad + self.good)
        self.assertEqual(self.login.read_bytes(), self.bad + self.good)
        self.assertFalse(any(c[0] == "delete-certificate" for c in self.commands()))

    def test_absent_custom_trust_settings_are_recorded_before_deletion(self):
        self.env["MOCK_SECURITY_NO_TRUST_SETTINGS"] = "1"
        before = snapshot(self.root)
        output = self.apply(expected=3)
        self.assertIn("No pre-existing", output)
        self.assertEqual(self.system.read_bytes(), self.good)
        self.assertEqual(self.login.read_bytes(), self.good)
        self.assertEqual(len(list(self.backups.rglob("mac-trust-*.absent"))), 2)
        self.assertFalse(list(self.backups.rglob("mac-trust-*.plist")))
        self.undo()
        self.assertEqual(before, snapshot(self.root))
        self.assertFalse(any(c[0] == "trust-settings-import" for c in self.commands()))

    def test_failed_deletion_reports_manual_action_and_fingerprint_checked_fallback(self):
        self.env["MOCK_SECURITY_REFUSE_DELETE"] = "1"
        before = snapshot(self.root)
        output = self.apply(expected=2)
        self.assertIn("NOT REMOVED", output)
        self.assertIn("Manual step: unlock", output)
        self.assertEqual(self.system.read_bytes(), self.bad + self.good)
        self.assertEqual(self.login.read_bytes(), self.bad + self.good)
        deletes = [c for c in self.commands() if c[0] == "delete-certificate"]
        self.assertEqual(len(deletes), 4)
        self.assertTrue(all(c[1:3] == ["-t", "-Z"] for c in deletes))

    def test_test_root_symlink_escape_is_not_given_to_security(self):
        self.system.unlink()
        outside = self.base / "outside.keychain"
        outside.write_bytes(self.bad)
        self.system.symlink_to(outside)
        original = outside.read_bytes()
        self.apply(expected=2)
        self.assertEqual(original, outside.read_bytes())
        self.assertFalse(any(c[-1] == str(self.system) for c in self.commands()))

    def test_older_security_uses_sha1_only_after_sha256_selection(self):
        self.env["MOCK_SECURITY_SHA1_ONLY"] = "1"
        output = self.apply(expected=3)
        self.assertIn("older SHA-1 -Z API", output)
        self.assertEqual(self.system.read_bytes(), self.good)
        self.assertEqual(self.login.read_bytes(), self.good)
        deletes = [c for c in self.commands() if c[0] == "delete-certificate"]
        self.assertEqual([len(c[3]) for c in deletes], [64, 40, 64, 40])
        import hashlib
        der = subprocess.run(["openssl", "x509", "-outform", "DER"], input=self.bad,
                             capture_output=True, check=True, timeout=45).stdout
        self.assertTrue(all(c[3] in (self.bad_sha, hashlib.sha1(der).hexdigest()) for c in deletes))
        self.undo()
        self.assertEqual(self.system.read_bytes(), self.bad + self.good)

    def test_os_bundle_keeps_crlf_and_unrelated_bytes_with_undo(self):
        before = b"# preamble\r\n" + self.good.replace(b"\n", b"\r\n") + self.bad.replace(b"\n", b"\r\n") + b"# last"
        self.os_bundle.write_bytes(before)
        self.apply("--no-keychains")
        self.assertEqual(self.os_bundle.read_bytes(), b"# preamble\r\n" + self.good.replace(b"\n", b"\r\n") + b"# last")
        self.undo()
        self.assertEqual(self.os_bundle.read_bytes(), before)

    def test_login_keychain_lookup_does_not_walk_documents(self):
        hidden = self.put("Users/tester/Documents/private/cacert.pem", self.bad)
        nested = self.put("Users/tester/Documents/login.keychain-db", self.bad)
        output = self.apply(expected=3)
        self.assertNotIn(str(hidden), output)
        self.assertFalse(any(c[-1] == str(nested) for c in self.commands()))
        self.assertEqual(hidden.read_bytes(), self.bad)

    def test_firefox_profiles_under_library_are_inspected(self):
        profile = self.put("Users/tester/Library/Application Support/Firefox/Profiles/abc.default/cert9.db", b"NSS fixture")
        shimdir = self.base / "bin"
        shimdir.mkdir()
        certutil = shimdir / "certutil"
        certutil.write_text("#!/bin/sh\necho 'NSS inspection fixture' >&2\nexit 1\n")
        certutil.chmod(0o755)
        self.env["PATH"] = str(shimdir) + os.pathsep + self.env["PATH"]
        output = self.invoke("--no-keychains", expected=2)
        self.assertIn(str(profile.parent), output)
        self.assertIn("Cannot list NSS", output)

    def test_keychain_undo_does_not_duplicate_undeleted_certificates(self):
        self.env["MOCK_SECURITY_REFUSE_DELETE"] = "1"
        self.apply(expected=2)
        before_undo = self.system.read_bytes()
        self.undo()
        self.assertEqual(self.system.read_bytes(), before_undo)
        self.assertFalse(any(c[0] == "add-certificates" for c in self.commands()))

    def test_successful_security_exit_with_certificate_remaining_is_failure(self):
        self.env["MOCK_SECURITY_NOOP_DELETE"] = "1"
        output = self.apply(expected=2)
        self.assertIn("Unexpected certificate set", output)
        self.assertEqual(self.system.read_bytes(), self.bad + self.good)
        self.assertEqual(self.login.read_bytes(), self.bad + self.good)

    def test_unrelated_keychain_certificates_are_checked_and_recoverable(self):
        self.env["MOCK_SECURITY_DELETE_ALL"] = "1"
        output = self.apply(expected=2)
        self.assertIn("Unexpected certificate set", output)
        self.env.pop("MOCK_SECURITY_DELETE_ALL")
        self.undo()
        import re
        for store in (self.system, self.login):
            blocks = re.findall(rb"-----BEGIN CERTIFICATE-----\n.*?-----END CERTIFICATE-----\n", store.read_bytes(), re.S)
            self.assertEqual(sorted(fingerprint(block) for block in blocks), sorted([self.bad_sha, self.good_sha]))

    def test_other_owners_login_keychain_is_report_only(self):
        shimdir = self.base / "owner-bin"
        shimdir.mkdir()
        uid_shim = shimdir / "id"
        uid_shim.write_text("#!/bin/sh\nif [ \"$1\" = -u ]; then printf '99999\\n'; else exec /usr/bin/id \"$@\"; fi\n")
        uid_shim.chmod(0o755)
        self.env["PATH"] = str(shimdir) + os.pathsep + self.env["PATH"]
        output = self.apply(expected=3)
        self.assertIn("belongs to uid", output)
        self.assertIn("User trust settings", output)
        self.assertIn("sudo -u '#", output)
        self.assertEqual(self.login.read_bytes(), self.bad + self.good)
        self.assertFalse(any(c[0] == "delete-certificate" and c[-1] == str(self.login) for c in self.commands()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
