#!/usr/bin/env python3
"""Exercise real NSS and Java tools against disposable stores."""
import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import time
import unittest

import test_files
from test_files import REPO, Sandbox, command, fingerprint, generate_cert, snapshot

USERSPACE = Path("/tmp/demudhra-userspace")


def find_tool(name, fallback):
    return shutil.which(name) or (str(fallback) if fallback.exists() else None)


CERTUTIL = find_tool("certutil", USERSPACE / "usr/bin/certutil")
KEYTOOL = find_tool("keytool", USERSPACE / "usr/lib/jvm/java-21-openjdk-amd64/bin/keytool")


def real_fixtures():
    directory = REPO / "tests/fixtures/pem"
    return {alias: (directory / name).read_bytes() for alias, name in (
        ("target ECC G3", "emsign-ecc-root-ca-g3.pem"),
        ("optional G1", "emsign-root-ca-g1.pem"),
        ("unrelated AAA", "aaa-certificate-services-sectigo.pem"),
    )}


class NSSBehaviour(Sandbox):
    subjects = ("/CN=NSS target", "/CN=NSS unrelated")

    @unittest.skipUnless(CERTUTIL, "certutil unavailable; ambiguity test NOT RUN")
    def test_same_subject_nss_alias_ambiguity_refuses_changes(self):
        self.env["PATH"] = str(Path(CERTUTIL).parent) + os.pathsep + self.env["PATH"]
        first = generate_cert(self.base, "older")
        # Different validity times reproduce NSS's newest-by-subject lookup.
        time.sleep(1.1)
        generate_cert(self.base, "newer")
        self.overrides.write_text(f"{fingerprint(first)}\tdefault-root\tTest\thttps://example.invalid\n")
        directory = self.root / "home/tester/.pki/nssdb"
        directory.mkdir(parents=True)
        database = "sql:" + str(directory)
        command([CERTUTIL, "-N", "-d", database, "--empty-password"], env=self.env)
        for name in ("older", "newer"):
            command([CERTUTIL, "-A", "-d", database, "-n", name, "-t", "C,,",
                     "-i", self.base / (name + ".pem")], env=self.env)
        original = snapshot(self.root)
        for output in (self.invoke(expected=2), self.apply(expected=2)):
            self.assertIn("Ambiguous NSS nickname", output)
        self.assertEqual(snapshot(self.root), original)
        self.assertFalse(self.backups.exists())

    @unittest.skipUnless(CERTUTIL, "certutil unavailable; real NSS tests NOT RUN")
    def test_real_nss_sql_database_dry_apply_undo_idempotence(self):
        self.env["PATH"] = str(Path(CERTUTIL).parent) + os.pathsep + self.env["PATH"]
        for relative in ("home/tester/.mozilla/firefox/fixture.default",
                         "home/tester/.pki/nssdb"):
            directory = self.root / relative
            directory.mkdir(parents=True)
            database = "sql:" + str(directory)
            command([CERTUTIL, "-N", "-d", database, "--empty-password"], env=self.env)
            for alias, pem in (("target with spaces", self.bad), ("unrelated with spaces", self.good)):
                source = self.base / (alias + ".pem")
                source.write_bytes(pem)
                command([CERTUTIL, "-A", "-d", database, "-n", alias,
                         "-t", "C,,", "-i", source], env=self.env)
        original = snapshot(self.root)
        output = self.invoke("--verbose", expected=10)
        self.assertIn("target with spaces", output)
        self.assertEqual(snapshot(self.root), original, "NSS inspection changed database bytes")
        self.apply()
        for relative in ("home/tester/.mozilla/firefox/fixture.default",
                         "home/tester/.pki/nssdb"):
            database = "sql:" + str(self.root / relative)
            result = subprocess.run([CERTUTIL, "-L", "-d", database, "-n", "target with spaces", "-a"],
                                    env=self.env, capture_output=True, timeout=45)
            self.assertNotEqual(result.returncode, 0, "matching NSS certificate remains")
            pem = command([CERTUTIL, "-L", "-d", database, "-n", "unrelated with spaces", "-a"], env=self.env).stdout
            self.assertEqual(fingerprint(pem), self.good_sha)
        after = snapshot(self.root)
        self.apply()
        self.assertEqual(snapshot(self.root), after)
        self.undo()
        self.assertEqual(snapshot(self.root), original, "NSS undo changed store bytes")


    @unittest.skipUnless(CERTUTIL, "certutil unavailable; real NSS race test NOT RUN")
    def test_real_nss_concurrent_import_is_preserved(self):
        directory = self.root / "home/tester/.pki/nssdb"
        directory.mkdir(parents=True)
        database = "sql:" + str(directory)
        source = self.base / "target.pem"
        source.write_bytes(self.bad)
        extra = self.base / "concurrent.pem"
        extra.write_bytes(self.good)
        command([CERTUTIL, "-N", "-d", database, "--empty-password"], env=self.env)
        command([CERTUTIL, "-A", "-d", database, "-n", "target", "-t", "C,,", "-i", source], env=self.env)
        shim_dir = self.base / "race-shim"
        shim_dir.mkdir()
        shim = shim_dir / "certutil"
        shim.write_text("""#!/usr/bin/env python3
import os
import subprocess
import sys
if sys.argv[1] == "-D" and not os.path.exists(os.environ["NSS_RACE_MARKER"]):
    subprocess.run([os.environ["REAL_CERTUTIL"], "-A", "-d", os.environ["NSS_RACE_DATABASE"],
                    "-n", "concurrent unrelated", "-t", "C,,", "-i", os.environ["NSS_RACE_CERT"]], check=True, timeout=45)
    open(os.environ["NSS_RACE_MARKER"], "w").close()
os.execv(os.environ["REAL_CERTUTIL"], [os.environ["REAL_CERTUTIL"], *sys.argv[1:]])
""")
        shim.chmod(0o755)
        self.env.update({"PATH": str(shim_dir) + os.pathsep + self.env["PATH"],
                         "REAL_CERTUTIL": CERTUTIL, "NSS_RACE_DATABASE": database,
                         "NSS_RACE_CERT": str(extra), "NSS_RACE_MARKER": str(self.base / "raced")})
        self.apply(expected=2)
        for alias, expected in (("target", self.bad_sha), ("concurrent unrelated", self.good_sha)):
            pem = command([CERTUTIL, "-L", "-d", database, "-n", alias, "-a"], env=self.env).stdout
            self.assertEqual(fingerprint(pem), expected, "concurrent NSS certificate import was lost")


    @unittest.skipUnless(CERTUTIL, "certutil unavailable; real certificate NSS test NOT RUN")
    def test_real_emudhra_and_aaa_nss_selection(self):
        self.env.pop("DEMUDHRA_TEST_FINGERPRINTS")
        self.env["PATH"] = str(Path(CERTUTIL).parent) + os.pathsep + self.env["PATH"]
        directory = self.root / "home/tester/.pki/nssdb"
        directory.mkdir(parents=True)
        database = "sql:" + str(directory)
        command([CERTUTIL, "-N", "-d", database, "--empty-password"], env=self.env)
        fixtures = real_fixtures()
        for alias, pem in fixtures.items():
            source = self.base / (alias + ".pem")
            source.write_bytes(pem)
            command([CERTUTIL, "-A", "-d", database, "-n", alias, "-t", "C,,", "-i", source], env=self.env)
        before = snapshot(self.root)
        self.invoke(expected=10)
        self.assertEqual(snapshot(self.root), before)
        self.apply()
        listing = command([CERTUTIL, "-L", "-d", database], env=self.env).stdout.decode()
        self.assertNotIn("target ECC G3", listing)
        self.assertIn("optional G1", listing)
        self.assertIn("unrelated AAA", listing)
        self.apply("--all-emudhra")
        listing = command([CERTUTIL, "-L", "-d", database], env=self.env).stdout.decode()
        self.assertNotIn("optional G1", listing)
        aaa = command([CERTUTIL, "-L", "-d", database, "-n", "unrelated AAA", "-a"], env=self.env).stdout
        self.assertEqual(fingerprint(aaa), fingerprint(fixtures["unrelated AAA"]))
        self.invoke("--all-emudhra")
        self.undo()
        self.undo(index=0)
        self.assertEqual(snapshot(self.root), before)


class JavaBehaviour(Sandbox):
    def setUp(self):
        super().setUp()
        if not KEYTOOL:
            self.skipTest("keytool unavailable; real Java tests NOT RUN")
        self.env["PATH"] = str(Path(KEYTOOL).parent) + os.pathsep + self.env["PATH"]
        check = subprocess.run([KEYTOOL, "-help"], env=self.env, capture_output=True, timeout=45)
        if check.returncode:
            self.skipTest("keytool cannot run: " + check.stderr.decode(errors="replace").splitlines()[0])

    def make_store(self, relative, password="changeit", storetype="JKS"):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        for alias, pem in (("target with spaces", self.bad), ("unrelated with spaces", self.good)):
            source = self.base / (alias + ".pem")
            source.write_bytes(pem)
            command([KEYTOOL, "-importcert", "-noprompt", "-keystore", path,
                     "-storepass", password, "-storetype", storetype,
                     "-alias", alias, "-file", source], env=self.env)
        return path

    def test_real_java_cacerts_dry_apply_undo_idempotence(self):
        stores = [self.make_store("etc/ssl/certs/java/cacerts"),
                  self.make_store("usr/lib/jvm/fixture/lib/security/cacerts", storetype="PKCS12")]
        original = snapshot(self.root)
        output = self.invoke("--verbose", expected=10)
        self.assertIn("target with spaces", output)
        self.assertEqual(snapshot(self.root), original, "Java inspection changed store bytes")
        self.apply()
        for store in stores:
            result = subprocess.run([KEYTOOL, "-list", "-keystore", str(store),
                                     "-storepass", "changeit", "-alias", "target with spaces"],
                                    env=self.env, capture_output=True, timeout=45)
            self.assertNotEqual(result.returncode, 0, "matching Java certificate remains")
            pem = command([KEYTOOL, "-exportcert", "-rfc", "-keystore", store,
                           "-storepass", "changeit", "-alias", "unrelated with spaces"], env=self.env).stdout
            self.assertEqual(fingerprint(pem), self.good_sha)
        after = snapshot(self.root)
        self.apply()
        self.assertEqual(snapshot(self.root), after)
        self.undo()
        self.assertEqual(snapshot(self.root), original, "Java undo did not restore original keystore")

    def test_concurrent_java_alias_replacement_is_not_deleted(self):
        store = self.make_store("opt/jdk/lib/security/cacerts")
        good = self.base / "concurrent.pem"
        good.write_bytes(self.good)
        shim_dir = self.base / "java-shim"
        shim_dir.mkdir()
        shim = shim_dir / "keytool"
        shim.write_text("""#!/bin/sh
"$RACE_KEYTOOL" "$@"
status=$?
case " $* " in *' -list '*)
    count=0
    [ ! -e "$RACE_MARKER" ] || count=$(cat "$RACE_MARKER")
    count=$((count + 1))
    printf '%s\n' "$count" > "$RACE_MARKER"
    if [ "$count" = 1 ]; then
        "$RACE_KEYTOOL" -delete -alias 'target with spaces' -keystore "$RACE_STORE" -storepass changeit >/dev/null 2>&1
        "$RACE_KEYTOOL" -importcert -noprompt -alias 'target with spaces' -keystore "$RACE_STORE" -storepass changeit -file "$RACE_GOOD" >/dev/null 2>&1
    fi;;
esac
exit "$status"
""")
        shim.chmod(0o755)
        self.env.update(RACE_KEYTOOL=KEYTOOL, RACE_STORE=str(store), RACE_GOOD=str(good),
                        RACE_MARKER=str(self.base / "raced"))
        self.env["PATH"] = str(shim_dir) + os.pathsep + self.env["PATH"]
        output = self.apply(expected=2)
        self.assertIn("changed", output.lower())
        pem = command([KEYTOOL, "-exportcert", "-rfc", "-alias", "target with spaces",
                       "-keystore", store, "-storepass", "changeit"]).stdout
        self.assertEqual(fingerprint(pem), self.good_sha)

    def test_custom_java_password_reports_partial_failure(self):
        path = self.make_store("opt/custom-jdk/lib/security/cacerts", password="custom-secret")
        before = path.read_bytes()
        output = self.apply(expected=2)
        self.assertIn(str(path), output)
        self.assertRegex(output.lower(), r"password|inspect|read|keytool")
        self.assertEqual(path.read_bytes(), before)


    def test_real_emudhra_and_aaa_java_selection(self):
        self.env.pop("DEMUDHRA_TEST_FINGERPRINTS")
        store = self.root / "etc/ssl/certs/java/cacerts"
        store.parent.mkdir(parents=True)
        fixtures = real_fixtures()
        for alias, pem in fixtures.items():
            source = self.base / (alias + ".pem")
            source.write_bytes(pem)
            command([KEYTOOL, "-importcert", "-noprompt", "-keystore", store,
                     "-storepass", "changeit", "-alias", alias, "-file", source], env=self.env)
        before = snapshot(self.root)
        self.invoke(expected=10)
        self.assertEqual(snapshot(self.root), before)
        self.apply()
        listing = command([KEYTOOL, "-list", "-keystore", store, "-storepass", "changeit"], env=self.env).stdout.decode().lower()
        self.assertNotIn("target ecc g3", listing)
        self.assertIn("optional g1", listing)
        self.assertIn("unrelated aaa", listing)
        self.apply("--all-emudhra")
        listing = command([KEYTOOL, "-list", "-keystore", store, "-storepass", "changeit"], env=self.env).stdout.decode().lower()
        self.assertNotIn("optional g1", listing)
        aaa = command([KEYTOOL, "-exportcert", "-rfc", "-keystore", store,
                       "-storepass", "changeit", "-alias", "unrelated AAA"], env=self.env).stdout
        self.assertEqual(fingerprint(aaa), fingerprint(fixtures["unrelated AAA"]))
        self.invoke("--all-emudhra")
        self.undo()
        self.undo(index=0)
        self.assertEqual(snapshot(self.root), before)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("--shell", default=os.environ.get("DEMUDHRA_TEST_SHELL", "dash"))
    options, remaining = parser.parse_known_args()
    test_files.SHELL = shlex.split(options.shell)
    unittest.main(argv=[__file__, *remaining], verbosity=2)
