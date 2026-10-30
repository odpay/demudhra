#!/usr/bin/env python3
"""Capture the site's terminal transcript from a real run in a disposable test root.

Builds an instrumented copy of demudhra-linux.sh, runs it under dash in a pty
with DEMUDHRA_TESTING=1 and DEMUDHRA_TEST_ROOT pointing at a copy of --seed-root,
answers y at the prompt, and writes the raw pty bytes to site/transcript.raw.
Native regeneration is replaced by a no-op shim. Nothing outside the temporary
directory is read for removal or changed. Never use --yes against a real system.
"""
import argparse, os, pathlib, pty, select, shutil, sys, tempfile, time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from generate import platform_script  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--seed-root', type=pathlib.Path, required=True,
                    help='fake filesystem tree to copy (for example a fake Debian root)')
    ap.add_argument('--output', type=pathlib.Path, default=ROOT / 'site/transcript.raw')
    args = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix='demudhra-capture-') as tmp:
        base = pathlib.Path(tmp)
        root = base / 'root'
        shutil.copytree(args.seed_root, root, symlinks=True)
        (base / 'scripts/data').mkdir(parents=True)
        script = base / 'scripts/demudhra-linux.sh'
        script.write_text(platform_script('linux', release=False))
        shutil.copyfile(ROOT / 'data/fingerprints.tsv', base / 'scripts/data/fingerprints.tsv')
        regen = base / 'regen'
        regen.write_text('#!/bin/sh\nexit 0\n'); regen.chmod(0o755)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(root / 'home/dev'), 'LC_ALL': 'C', 'TERM': 'xterm',
               'DEMUDHRA_TESTING': '1', 'DEMUDHRA_TEST_ROOT': str(root),
               'DEMUDHRA_TEST_REGEN': str(regen), 'DEMUDHRA_TEST_DEFAULT_SCAN': '1'}
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(base)
            os.execvpe('dash', ['dash', str(script), '--backup-dir', str(base / 'backups')], env)
        out, sent, end = b'', False, time.time() + 60
        while time.time() < end:
            ready, _, _ = select.select([fd], [], [], .1)
            if ready:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    break
                if not data:
                    break
                out += data
                if not sent and b'[y/N]' in out:
                    time.sleep(.3); os.write(fd, b'y\n'); sent = True
        _, status = os.waitpid(pid, 0)
        text = out.decode(errors='replace')
        text = text.replace(str(base / 'backups'), '/home/dev/demudhra-backups').replace(str(root), '')
        args.output.write_text(text)
        sys.stdout.write(text)
        print('\nexit =', os.waitstatus_to_exitcode(status))


if __name__ == '__main__':
    main()
