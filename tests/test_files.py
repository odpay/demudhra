#!/usr/bin/env python3
"""Drive the shipped shell scripts against disposable filesystems."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import unittest

from generate import SCRIPTS

REPO = Path(__file__).resolve().parents[1]
SHELL = shlex.split(os.environ.get("DEMUDHRA_TEST_SHELL", "dash"))


def command(args, **kwargs):
    kwargs.setdefault("timeout", 45)
    return subprocess.run([str(x) for x in args], check=True, capture_output=True, **kwargs)


def fingerprint(pem):
    der = command(["openssl", "x509", "-outform", "DER"], input=pem).stdout
    return hashlib.sha256(der).hexdigest()


def generate_cert(directory, stem, subject="/CN=Same certificate subject"):
    path = directory / (stem + ".pem")
    command([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", directory / (stem + ".key"), "-out", path,
        "-days", "1", "-subj", subject,
    ])
    return path.read_bytes()


def snapshot(root):
    """Include names, bytes, symlink destinations and permission bits."""
    result = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        name = str(path.relative_to(root))
        if stat.S_ISLNK(info.st_mode):
            result[name] = ("symlink", os.readlink(path))
        elif stat.S_ISREG(info.st_mode):
            result[name] = ("file", hashlib.sha256(path.read_bytes()).hexdigest(),
                            stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)
    return result


class Sandbox(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_dir = tempfile.TemporaryDirectory(prefix="demudhra-certs-")
        directory = Path(cls.fixture_dir.name)
        subjects = getattr(cls, "subjects", ("/CN=Same certificate subject",) * 2)
        cls.bad = generate_cert(directory, "target", subjects[0])
        cls.good = generate_cert(directory, "unrelated", subjects[1])
        cls.bad_sha = fingerprint(cls.bad)
        cls.good_sha = fingerprint(cls.good)

    @classmethod
    def tearDownClass(cls):
        cls.fixture_dir.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="demudhra-files-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "root"
        self.root.mkdir()
        self.backups = self.base / "backups with space"
        self.overrides = self.base / "fingerprints.tsv"
        self.overrides.write_text(
            f"{self.bad_sha}\tdefault-root\tCN=Same certificate subject\thttps://example.invalid/fixture\n"
        )
        self.env = os.environ.copy()
        for variable in ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
                         "CURL_CA_BUNDLE", "AWS_CA_BUNDLE", "JAVA_HOME"):
            self.env.pop(variable, None)
        self.env.update({
            "DEMUDHRA_TESTING": "1",
            "DEMUDHRA_TEST_ROOT": str(self.root),
            "DEMUDHRA_TEST_FINGERPRINTS": str(self.overrides),
            "HOME": str(self.root / "home/tester"),
            "LC_ALL": "C",
        })
        self.put("etc/os-release", b"ID=debian\nVERSION_ID=13\n")

    def put(self, relative, contents):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        return path

    def invoke(self, *args, script="demudhra-linux.sh", expected=0):
        result = subprocess.run(
            SHELL + [str(SCRIPTS / script), *args], env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            timeout=45, start_new_session=True, stdin=subprocess.DEVNULL,
        )
        if self.env.get("DEMUDHRA_TEST_TRANSCRIPT"):
            with Path(self.env["DEMUDHRA_TEST_TRANSCRIPT"]).open("a") as trace:
                trace.write("$ " + shlex.join(SHELL + [str(SCRIPTS / script), *args]) + "\n")
                trace.write(f"exit={result.returncode}\n{result.stdout}\n")
        self.assertEqual(result.returncode, expected, result.stdout)
        return result.stdout

    def apply(self, *args, **kwargs):
        return self.invoke("--apply", "--backup-dir", str(self.backups), *args, **kwargs)

    def undo(self, index=-1):
        scripts = sorted(self.backups.rglob("undo.sh"), key=lambda p: p.stat().st_mtime_ns)
        self.assertTrue(scripts, "apply must create an executable, reviewable undo.sh")
        command(SHELL + [str(scripts[index])], env=self.env)

    def assert_contents_or_removed(self, path, expected):
        self.assertEqual(path.read_bytes() if path.exists() else b"", expected)


class FileBehaviour(Sandbox):
    def plant_bundles(self):
        good_crlf = self.good.replace(b"\n", b"\r\n")
        bad_crlf = self.bad.replace(b"\n", b"\r\n")
        before = b"# preamble\r\n" + good_crlf + b"# between\r\n" + bad_crlf + b"# no final newline"
        after = b"# preamble\r\n" + good_crlf + b"# between\r\n# no final newline"
        locations = [
            "etc/ssl/certs/ca-certificates.crt",
            "etc/pki/tls/certs/ca-bundle.crt",
            "usr/local/share/ca-certificates/mixed.crt",
            "home/tester/.venv/lib/python3.13/site-packages/certifi/cacert.pem",
            "opt/conda/lib/python3.13/site-packages/certifi/cacert.pem",
            "usr/lib/python3.13/site-packages/pip/_vendor/certifi/cacert.pem",
            "home/tester/project/node_modules/example/cacert.pem",
            "opt/ruby/ssl/cert.pem",
            "opt/custom/cacert.pem",
            "home/tester/has space/certificates.pem",
        ]
        paths = [(self.put(location, before), after) for location in locations]
        paths.append((self.put("usr/share/ca-certificates/target.crt", self.bad), b""))
        paths.append((self.put("etc/ssl/certs/keep.pem", self.good.rstrip(b"\n")), self.good.rstrip(b"\n")))
        return paths

    def test_dry_run_apply_backup_undo_and_idempotence(self):
        paths = self.plant_bundles()
        original = snapshot(self.root)
        output = self.invoke("--verbose", expected=10)
        self.assertRegex(output.lower(), r"warning.*test|test.*warning")
        self.assertIn(self.bad_sha, output.lower())
        for path, _ in paths[:-1]:
            self.assertIn(str(path), output)
        self.assertEqual(snapshot(self.root), original, "dry run changed files")
        self.assertFalse(self.backups.exists(), "dry run created backups")
        output = self.apply()
        self.assertRegex(output.lower(), r"found")
        self.assertRegex(output.lower(), r"removed")
        self.assertRegex(output.lower(), r"back.*up")
        for path, expected in paths:
            self.assert_contents_or_removed(path, expected)
        after = snapshot(self.root)
        self.apply()
        self.assertEqual(snapshot(self.root), after, "second apply must be idempotent")
        self.undo()
        self.assertEqual(snapshot(self.root), original, "undo did not restore exact original bytes and metadata")

    def test_missing_final_newline_in_preserved_certificate(self):
        before = b"# start\n" + self.bad + self.good.rstrip(b"\n")
        path = self.put("opt/end/cacert.pem", before)
        self.apply()
        self.assertEqual(path.read_bytes(), b"# start\n" + self.good.rstrip(b"\n"))
        self.undo()
        self.assertEqual(path.read_bytes(), before)

    def test_openssl_trusted_certificate_blocks(self):
        trusted_bad = command(["openssl", "x509", "-trustout", "-addtrust", "serverAuth"], input=self.bad).stdout
        trusted_good = command(["openssl", "x509", "-trustout", "-addtrust", "serverAuth"], input=self.good).stdout
        path = self.put("opt/trusted/cacert.pem", trusted_good + trusted_bad)
        self.invoke(expected=10)
        self.apply()
        self.assertEqual(path.read_bytes(), trusted_good)

    def test_der_certificates(self):
        der = command(["openssl", "x509", "-outform", "DER"], input=self.bad).stdout
        path = self.put("usr/local/share/ca-certificates/target.der", der)
        output = self.invoke(expected=10)
        self.assertIn(str(path), output)
        self.apply()
        self.assert_contents_or_removed(path, b"")
        self.undo()
        self.assertEqual(path.read_bytes(), der)

    def test_unreadable_file_is_reported(self):
        if os.geteuid() == 0:
            self.skipTest("root can read mode-0000 files")
        path = self.put("opt/unreadable/cacert.pem", self.bad)
        path.chmod(0)
        self.addCleanup(path.chmod, 0o600)
        output = self.invoke()
        self.assertIn("not readable (run as root to include)", output)
        self.assertIn(str(path), output)
        self.assertRegex(output.lower(), r"read|permission|denied")

    def test_malformed_bundle_is_not_rewritten(self):
        before = self.bad + b"-----BEGIN CERTIFICATE-----\ninvalid base64\n-----END CERTIFICATE-----\n"
        path = self.put("opt/malformed/cacert.pem", before)
        output = self.invoke("--dry-run")
        self.assertIn("failed=0", output)
        self.assertNotIn("Malformed", output)
        self.apply()
        self.assertEqual(path.read_bytes(), before)

    def test_empty_bundle_deletion_is_backed_up_and_undoable(self):
        pure = self.put("opt/pure/cacert.pem", self.bad)
        empty = self.put("opt/empty/cacert.pem", b"")
        annotated = self.put("opt/annotated/cacert.pem", b"# keep this header\n" + self.bad)
        before = snapshot(self.root)
        self.apply()
        self.assertFalse(pure.exists())
        self.assertTrue(empty.exists())
        self.assertEqual(empty.read_bytes(), b"")
        self.assertEqual(annotated.read_bytes(), b"# keep this header\n")
        self.undo()
        self.assertEqual(snapshot(self.root), before)

    def test_grouped_output_limits_paths_unless_verbose(self):
        paths = [self.put(f"opt/group/cert-{index}.pem", self.bad) for index in range(7)]
        output = self.invoke("--dry-run", expected=10)
        self.assertEqual(sum(str(path) in output for path in paths), 5, output)
        self.assertIn("Other: 7 certs in 7 places", output)
        self.assertNotIn("remove them? [y/N]", output)
        verbose = self.invoke("--dry-run", "--verbose", expected=10)
        self.assertTrue(all(str(path) in verbose for path in paths), verbose)

    def test_test_root_never_follows_external_symlink(self):
        external = self.base / "outside.pem"
        external.write_bytes(self.bad)
        link = self.root / "etc/ssl/certs/escape.pem"
        link.parent.mkdir(parents=True)
        link.symlink_to(external)
        self.apply(expected=2)
        self.assertEqual(external.read_bytes(), self.bad)
        self.assertTrue(link.is_symlink())

    def test_all_skip_flags_leave_bytes_unchanged(self):
        self.plant_bundles()
        original = snapshot(self.root)
        self.apply("--no-system", "--no-java", "--no-nss", "--no-python",
                   "--no-node", "--no-ruby", "--no-bundles", "--no-keychains")
        self.assertEqual(snapshot(self.root), original)

    def test_skips_protect_canonical_files_reached_through_aliases(self):
        python = self.put("opt/conda/lib/site-packages/certifi/cacert.pem", self.bad)
        alias = self.root / "etc/ssl/certs/python.pem"
        alias.parent.mkdir(parents=True)
        alias.symlink_to(python)
        system = self.put("usr/share/ca-certificates/target.crt", self.bad)
        generic = self.root / "opt/system-alias.pem"
        generic.symlink_to(system)
        before = snapshot(self.root)
        self.apply("--no-python", "--no-system")
        self.assertEqual(snapshot(self.root), before)

    def test_backup_aliases_and_old_backup_locations_are_never_scanned(self):
        target = self.put("opt/cacert.pem", self.bad)
        user = self.root / "home/user"
        user.mkdir(parents=True)
        self.backups = user / ".." / "user" / "backups"
        self.apply()
        originals = [p for p in self.backups.rglob("cacert.pem") if p.is_file()]
        self.assertEqual(len(originals), 1)
        self.assertEqual(originals[0].read_bytes(), self.bad)
        after = snapshot(self.root)
        self.apply()
        self.assertEqual(snapshot(self.root), after)
        self.invoke("--apply", "--backup-dir", str(self.root / "different-backups"))
        self.assertEqual(snapshot(self.root), after)
        self.assertEqual(originals[0].read_bytes(), self.bad)
        self.undo()
        self.assertEqual(target.read_bytes(), self.bad)

    def test_quoted_paths_have_exact_safe_undo_commands(self):
        target = self.put("opt/has ' and $ characters/cacert.pem", self.good + self.bad)
        self.backups = self.base / "backups ' with $ characters"
        self.apply()
        self.assertEqual(target.read_bytes(), self.good)
        self.undo()
        self.assertEqual(target.read_bytes(), self.good + self.bad)

    def test_help_version_and_unknown_option(self):
        output = self.invoke("--help")
        for flag in ("--apply", "--all-emudhra", "--list", "--backup-dir", "--no-java"):
            self.assertIn(flag, output)
        self.assertIn("G1", output)
        self.invoke("--version")
        self.invoke("--unknown-option", expected=1)
        self.invoke("--backup-dir", expected=1)

    def test_list_uses_selected_real_set(self):
        self.env.pop("DEMUDHRA_TEST_FINGERPRINTS")
        data = json.loads((REPO / "data/certs.json").read_text())
        output = self.invoke("--list")
        for row in data:
            if row["group"].startswith("default-"):
                self.assertIn(row["sha256"].lower(), output.lower())
                self.assertIn(row["subject"], output)
            else:
                self.assertNotIn(row["sha256"].lower(), output.lower())
        output = self.invoke("--all-emudhra", "--list")
        for row in data:
            if row["group"] == "opt-in-cross-sign":
                self.assertNotIn(row["sha256"], output.lower())
            else:
                self.assertIn(row["sha256"].lower(), output.lower())
                self.assertIn(row["subject"], output)
        output = self.invoke("--include-aaa", "--list")
        self.assertIn("d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4", output.lower())

    def test_real_certificates_default_then_all_and_aaa_excluded(self):
        self.env.pop("DEMUDHRA_TEST_FINGERPRINTS")
        data = json.loads((REPO / "data/certs.json").read_text())
        self.assertEqual(len(data), 43)
        blocks = []
        optional = []
        for row in data:
            pem = (REPO / "tests/fixtures" / row["pem_path"]).read_bytes()
            self.assertEqual(fingerprint(pem), row["sha256"].lower())
            if row["group"] != "opt-in-cross-sign":
                blocks.append(pem)
            if row["group"] == "all-emudhra-root":
                optional.append(pem)
        aaa = (REPO / "tests/fixtures/pem/aaa-certificate-services-sectigo.pem").read_bytes()
        self.assertEqual([row["group"] for row in data if row["sha256"] == fingerprint(aaa)], ["opt-in-cross-sign"])
        prefix = b"# real certificate regression fixtures\n"
        original = prefix + b"".join(blocks) + aaa
        path = self.put("opt/real/cacert.pem", original)
        before = snapshot(self.root)
        self.invoke(expected=10)
        self.assertEqual(snapshot(self.root), before)
        self.apply()
        expected_default = prefix + b"".join(optional) + aaa
        self.assertEqual(path.read_bytes(), expected_default)
        self.invoke()
        default_snapshot = snapshot(self.root)
        self.apply()
        self.assertEqual(snapshot(self.root), default_snapshot, "real default apply must be idempotent")
        self.invoke("--all-emudhra", expected=10)
        self.assertEqual(snapshot(self.root), default_snapshot, "real all-selection dry run changed files")
        self.apply("--all-emudhra")
        self.assertEqual(path.read_bytes(), prefix + aaa)
        self.invoke("--all-emudhra")
        all_snapshot = snapshot(self.root)
        self.apply("--all-emudhra")
        self.assertEqual(snapshot(self.root), all_snapshot, "real all-selection apply must be idempotent")
        self.undo()
        self.assertEqual(path.read_bytes(), expected_default)
        self.undo(index=0)
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(snapshot(self.root), before, "real-PEM undo changed bytes or metadata")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("--shell", default=os.environ.get("DEMUDHRA_TEST_SHELL", "dash"))
    options, remaining = parser.parse_known_args()
    SHELL = shlex.split(options.shell)
    unittest.main(argv=[__file__, *remaining], verbosity=2)
