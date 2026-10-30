"""Exercise confirmation, scan boundaries, and safe restoration on temp trees."""
import errno
import os
from pathlib import Path
import pty
import select
import signal
import shlex
import shutil
import subprocess
import time
import unittest

from test_files import REPO, SHELL, SCRIPTS, Sandbox, snapshot


class Workflow(Sandbox):
    def terminal(self, args, answers, before_answer=None):
        child, fd = pty.fork()
        if child == 0:
            os.execvpe(SHELL[0], SHELL + [str(SCRIPTS / 'demudhra-linux.sh'),
                       '--backup-dir', str(self.backups), *args], self.env)
        output = b''
        sent = 0
        deadline = time.monotonic() + 40
        status = None
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([fd], [], [], .1)
                if ready:
                    try:
                        data = os.read(fd, 65536)
                    except OSError as exc:
                        if exc.errno == errno.EIO:
                            break
                        raise
                    if not data:
                        break
                    output += data
                    if sent < len(answers) and output.count(b'[y/N]') > sent:
                        if before_answer and sent == 0:
                            before_answer()
                        os.write(fd, answers[sent].encode() + b'\n')
                        sent += 1
                done, status_value = os.waitpid(child, os.WNOHANG)
                if done:
                    status = status_value
                    break
            else:
                self.fail('PTY command exceeded 40 seconds\n' + output.decode(errors='replace'))
        finally:
            os.close(fd)
            if status is None:
                done, status_value = os.waitpid(child, os.WNOHANG)
                if not done:
                    os.kill(child, signal.SIGKILL)
                    _, status_value = os.waitpid(child, 0)
                status = status_value
        return os.waitstatus_to_exitcode(status), output.decode(errors='replace')

    def test_prompt_yes_no_and_empty(self):
        path = self.put('opt/prompt.pem', self.good + self.bad)
        before = snapshot(self.root)
        for answer in ('n', ''):
            code, out = self.terminal([], [answer])
            self.assertEqual(code, 11, out)
            self.assertEqual(out.count('remove them? [y/N]'), 1, out)
            self.assertEqual(snapshot(self.root), before)
            self.assertFalse(self.backups.exists())
        code, out = self.terminal([], ['y'])
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count('remove them? [y/N]'), 1, out)
        self.assertEqual(path.read_bytes(), self.good)
        self.undo()
        self.assertEqual(snapshot(self.root), before)

    def test_changed_bundle_after_confirmation_is_not_overwritten(self):
        path = self.put('etc/ssl/certs/ca-certificates.crt', self.good + self.bad)
        source = self.put('usr/local/share/ca-certificates/remove.crt', self.bad)
        shim = self.base / 'no-op-regeneration'
        shim.write_text('#!/bin/sh\nexit 0\n')
        shim.chmod(0o755)
        self.env['DEMUDHRA_TEST_REGEN'] = str(shim)
        changed = self.good + self.bad + b'# concurrent change\n'
        code, out = self.terminal([], ['y'], before_answer=lambda: path.write_bytes(changed))
        self.assertEqual(code, 2, out)
        self.assertIn('Changed during scan', out)
        self.assertEqual(path.read_bytes(), changed)
        self.assertEqual(source.read_bytes(), self.bad)
        self.assertFalse(self.backups.exists())

    def test_changed_system_survivor_prevents_all_removal(self):
        survivor = self.put('etc/ssl/certs/keep.pem', self.good)
        target = self.put('opt/target.pem', self.bad + self.good)
        changed = b'# concurrent change\n' + self.good
        code, out = self.terminal([], ['y'], before_answer=lambda: survivor.write_bytes(changed))
        self.assertEqual(code, 2, out)
        self.assertIn('Changed during scan', out)
        self.assertEqual(survivor.read_bytes(), changed)
        self.assertEqual(target.read_bytes(), self.bad + self.good)
        self.assertFalse(self.backups.exists())

    def test_dry_run_never_prompts_even_in_terminal(self):
        path = self.put('opt/explicit.pem', self.bad)
        for args in (['--dry-run'], ['--dry-run', '--yes']):
            code, out = self.terminal(args, [])
            self.assertEqual(code, 10, out)
            self.assertNotIn('remove them? [y/N]', out)
            self.assertIn('dry run: nothing changed.', out)
        self.assertFalse(self.backups.exists())
        self.assertEqual(path.read_bytes(), self.bad)

    def test_nonterminal_dry_run_ends_with_plain_message(self):
        path = self.put('opt/explicit.pem', self.bad)
        out = self.invoke('--dry-run', expected=10)
        self.assertNotIn('remove them? [y/N]', out)
        self.assertTrue(out.splitlines()[-1].startswith('dry run: nothing changed.'), out)
        self.assertEqual(path.read_bytes(), self.bad)
        self.assertFalse(self.backups.exists())

    def test_scan_summary_follows_groups_and_verbose_diagnostics(self):
        self.put('opt/explicit.pem', self.bad)
        out = self.invoke('--dry-run', '--verbose', expected=10)
        lines = out.splitlines()
        summary = next(i for i, line in enumerate(lines) if line.startswith('Summary:'))
        for label in ('OS trust store:', 'Java:', 'Firefox/Chrome NSS:', 'Python:', 'Node:', 'Other:',
                      'Skipped malformed certificate files:'):
            self.assertLess(next(i for i, line in enumerate(lines) if line.startswith(label)), summary, out)

    def test_no_terminal_reports_and_yes_removes(self):
        path = self.put('opt/no-tty.pem', self.bad)
        out = self.invoke(expected=10)
        self.assertIn('No terminal was available', out)
        self.assertIn('--yes', out)
        self.assertNotIn('remove them? [y/N]', out)
        self.assertEqual(path.read_bytes(), self.bad)
        out = self.invoke('--yes', '--backup-dir', str(self.backups))
        self.assertNotIn('remove them? [y/N]', out)
        self.assertFalse(path.exists())
        self.assertIn(str(path), out)
        path.write_bytes(self.bad)
        code, out = self.terminal(['--yes'], [])
        self.assertEqual(code, 0, out)
        self.assertNotIn('remove them? [y/N]', out)
        self.assertFalse(path.exists())

    def test_container_snap_overlay_mount_and_backup_prunes(self):
        paths = ['var/lib/docker/overlay2/a/diff/etc/ssl/cert.pem',
                 'var/lib/containers/storage/overlay/a/diff/ca.pem',
                 'var/lib/containerd/a/ca.crt', 'var/lib/lxc/a/cert.pem',
                 'var/lib/snapd/snaps/cert.pem', 'snap/core/1/cert.pem',
                 'nix/store/a/cert.pem', 'opt/overlay/a/cert.pem',
                 'opt/mounted/cert.pem', 'opt/merged/cert.pem']
        for path in paths:
            self.put(path, self.bad)
        self.put('proc/self/mountinfo', b'1 0 0:1 / /opt/mounted ro - squashfs /a ro\n2 0 0:2 / /opt/merged rw - overlay overlay rw\n')
        self.put('home/old-backup/.demudhra-backup', b'backup\n')
        self.put('home/old-backup/cert.pem', self.bad)
        before = snapshot(self.root)
        out = self.apply()
        self.assertIn('images', out)
        self.assertIn('snaps are not touched', out)
        self.assertIn('found=0', out)
        self.assertEqual(snapshot(self.root), before)

    def test_symlink_top_level_directory_and_alias_to_pruned_tree(self):
        path = self.put('private/etc/ssl/cert.pem', self.good + self.bad)
        (self.root / 'etc/os-release').unlink()
        (self.root / 'etc').rmdir()
        (self.root / 'etc').symlink_to(self.root / 'private/etc')
        self.put('var/lib/docker/image/cert.pem', self.bad)
        alias = self.root / 'opt/alias.pem'
        alias.parent.mkdir(parents=True)
        alias.symlink_to(self.root / 'var/lib/docker/image/cert.pem')
        self.apply()
        self.assertEqual(path.read_bytes(), self.good)
        self.assertEqual(alias.read_bytes(), self.bad)

    def test_symlinked_var_store_pruning_includes_physical_aliases(self):
        target = self.put('private/var/lib/docker/image/cert.pem', self.bad)
        snap = self.put('private/var/lib/snapd/mount/cert.pem', self.bad)
        (self.root / 'var').symlink_to(self.root / 'private/var')
        self.env['SSL_CERT_FILE'] = str(target)
        before = snapshot(self.root)
        out = self.apply()
        self.assertIn('found=0', out)
        self.assertEqual(snapshot(self.root), before)
        self.assertEqual(snap.read_bytes(), self.bad)

    def test_confirmed_apply_reuses_discovery(self):
        self.put('opt/one.pem', self.good + self.bad)
        bindir = self.base / 'find-bin'
        bindir.mkdir()
        trace = self.base / 'find-calls'
        find = bindir / 'find'
        find.write_text('#!/bin/sh\nprintf "find\\n" >> "$FIND_TRACE"\nexec ' +
                        shlex.quote(shutil.which('find')) + ' "$@"\n')
        find.chmod(0o755)
        self.env.update(PATH=str(bindir) + os.pathsep + self.env['PATH'], FIND_TRACE=str(trace))
        self.invoke('--dry-run', expected=10)
        dry_calls = trace.read_text().splitlines()
        trace.write_text('')
        self.apply()
        self.assertEqual(trace.read_text().splitlines(), dry_calls)

    def test_nonroot_unreadable_directories_are_not_failures(self):
        if os.geteuid() == 0:
            self.skipTest('needs nonroot permissions')
        hidden = self.root / 'opt/private'
        hidden.mkdir(parents=True)
        hidden.chmod(0)
        self.addCleanup(hidden.chmod, 0o700)
        out = self.invoke()
        self.assertIn('not readable (run as root to include)', out)
        self.assertIn('failed=0', out)
        self.assertIn('unreadable=1', out)
        self.put('opt/readable.pem', self.bad)
        self.invoke(expected=10)

    def test_needs_root_leaves_target_and_changes_user_target(self):
        if os.geteuid() == 0:
            self.skipTest('needs nonroot permissions')
        protected = self.put('opt/protected.pem', self.bad)
        protected.chmod(0o400)
        self.addCleanup(protected.chmod, 0o600)
        user = self.put('home/tester/cert.pem', self.good + self.bad)
        out = self.invoke('--yes', '--backup-dir', str(self.backups), expected=4)
        self.assertIn('NEEDS ROOT: ' + str(protected), out)
        self.assertIn('sudo sh', out)
        hint = next(line for line in out.splitlines() if line.startswith('Run after reviewing'))
        self.assertEqual(hint.count('--yes'), 1, hint)
        self.assertEqual(protected.read_bytes(), self.bad)
        self.assertEqual(user.read_bytes(), self.good)

    def test_sudo_reexec_requires_confirmation_and_passes_yes(self):
        if os.geteuid() == 0:
            self.skipTest('needs nonroot permissions')
        target = self.put('opt/protected.pem', self.bad)
        target.chmod(0o400)
        self.addCleanup(target.chmod, 0o600)
        bindir = self.base / 'bin'
        bindir.mkdir()
        sudo = bindir / 'sudo'
        sudo.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$SUDO_LOG"\nexit 0\n')
        sudo.chmod(0o755)
        logfile = self.base / 'sudo-args'
        self.env['PATH'] = str(bindir) + os.pathsep + self.env['PATH']
        self.env['SUDO_LOG'] = str(logfile)
        code, out = self.terminal([], ['y', 'y'])
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count('remove them? [y/N]'), 1)
        self.assertIn('these need root. re-run with sudo? [y/N]', out)
        arguments = logfile.read_text().splitlines()
        self.assertEqual(arguments[:2], ['sh', str(SCRIPTS / 'demudhra-linux.sh')])
        self.assertEqual(arguments[-1], '--yes')

    def test_undo_copy_failure_retains_target(self):
        target = self.put('opt/cert.pem', self.good + self.bad)
        self.apply()
        bindir = self.base / 'broken-bin'
        bindir.mkdir()
        fake = bindir / 'cp'
        fake.write_text('#!/bin/sh\nexit 1\n')
        fake.chmod(0o755)
        undo = next(self.backups.rglob('undo.sh'))
        env = dict(self.env, PATH=str(bindir) + os.pathsep + self.env['PATH'])
        result = subprocess.run(SHELL + [str(undo)], env=env, capture_output=True, timeout=45)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_bytes(), self.good)

    def test_tree_undo_failed_second_or_third_move_keeps_targets_present(self):
        target = self.put('etc/ssl/certs/ca-certificates.crt', self.good + self.bad)
        other = self.put('etc/ssl/certs/other.pem', self.good)
        third = self.put('etc/ssl/certs/subdir/third.pem', self.good)
        shim = self.base / 'no-op-regeneration'
        shim.write_text('#!/bin/sh\nexit 0\n')
        shim.chmod(0o755)
        self.env['DEMUDHRA_TEST_REGEN'] = str(shim)
        bindir = self.base / 'failing-move-bin'
        bindir.mkdir()
        fake = bindir / 'mv'
        fake.write_text('#!/bin/sh\n'
                        'n=0\n'
                        '[ ! -f "$MOVE_COUNT" ] || n=$(cat "$MOVE_COUNT")\n'
                        'n=$((n+1))\n'
                        'printf "%s\\n" "$n" > "$MOVE_COUNT"\n'
                        '[ "$n" -lt "$FAIL_AT" ] || exit 1\n'
                        'exec /bin/mv "$@"\n')
        fake.chmod(0o755)
        counter = self.base / 'move-count'
        before = snapshot(self.root)
        for fail_at in (2, 3):
            with self.subTest(fail_at=fail_at):
                self.apply()
                scripts = sorted(self.backups.rglob('undo.sh'), key=lambda p: p.stat().st_mtime_ns)
                if counter.exists():
                    counter.unlink()
                env = dict(self.env, PATH=str(bindir) + os.pathsep + self.env['PATH'],
                           MOVE_COUNT=str(counter), FAIL_AT=str(fail_at))
                result = subprocess.run(SHELL + [str(scripts[-1])], env=env,
                                        capture_output=True, text=True, timeout=45)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue(target.parent.is_dir(), 'tree undo removed the live trust directory')
                self.assertTrue(target.is_file())
                self.assertEqual(other.read_bytes(), self.good)
                self.assertEqual(third.read_bytes(), self.good)
                self.assertIn('target directory retained', result.stderr)
                self.undo()
                self.assertEqual(snapshot(self.root), before)

    def test_tree_undo_staging_copy_failure_preserves_current_tree(self):
        self.put('etc/ssl/certs/ca-certificates.crt', self.good + self.bad)
        self.put('etc/ssl/certs/subdir/survivor.pem', self.good)
        shim = self.base / 'no-op-regeneration'
        shim.write_text('#!/bin/sh\nexit 0\n')
        shim.chmod(0o755)
        self.env['DEMUDHRA_TEST_REGEN'] = str(shim)
        self.apply()
        before = snapshot(self.root)
        bindir = self.base / 'failing-tree-copy-bin'
        bindir.mkdir()
        fake = bindir / 'cp'
        fake.write_text('#!/bin/sh\nexit 1\n')
        fake.chmod(0o755)
        undo = next(self.backups.rglob('undo.sh'))
        env = dict(self.env, PATH=str(bindir) + os.pathsep + self.env['PATH'])
        result = subprocess.run(SHELL + [str(undo)], env=env,
                                capture_output=True, text=True, timeout=45)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('target retained', result.stderr)
        self.assertEqual(snapshot(self.root), before)

    def test_tree_undo_restores_directory_modes_symlinks_and_removes_extras(self):
        target = self.put('etc/ssl/certs/ca-certificates.crt', self.good + self.bad)
        survivor = self.put('etc/ssl/certs/subdir/survivor.pem', self.good)
        alias = target.parent / 'survivor.0'
        alias.symlink_to('subdir/survivor.pem')
        target.parent.chmod(0o751)
        survivor.parent.chmod(0o755)
        before = snapshot(self.root)
        shim = self.base / 'no-op-regeneration'
        shim.write_text('#!/bin/sh\nexit 0\n')
        shim.chmod(0o755)
        self.env['DEMUDHRA_TEST_REGEN'] = str(shim)
        self.apply()
        self.put('etc/ssl/certs/stale.pem', self.good)
        target.parent.chmod(0o700)
        survivor.parent.chmod(0o700)
        self.undo()
        self.assertEqual(target.parent.stat().st_mode & 0o777, 0o751)
        self.assertEqual(survivor.parent.stat().st_mode & 0o777, 0o755)
        self.assertEqual(snapshot(self.root), before)

    def test_test_override_requires_explicit_testing(self):
        self.env.pop('DEMUDHRA_TESTING')
        out = self.invoke('--list')
        self.assertNotIn(self.bad_sha, out)
        self.assertNotIn('TEST_FINGERPRINTS is active', out)

    def test_aaa_is_removed_only_when_opted_in(self):
        self.env.pop('DEMUDHRA_TEST_FINGERPRINTS')
        aaa = (REPO / 'tests/fixtures/pem/aaa-certificate-services-sectigo.pem').read_bytes()
        path = self.put('opt/aaa.pem', aaa)
        self.invoke('--dry-run')
        self.invoke('--all-emudhra', '--dry-run')
        self.assertEqual(path.read_bytes(), aaa)
        self.invoke('--include-aaa', '--dry-run', expected=10)
        self.apply('--include-aaa')
        self.assertFalse(path.exists())
        self.undo()
        self.assertEqual(path.read_bytes(), aaa)


if __name__ == '__main__':
    unittest.main(verbosity=2)
