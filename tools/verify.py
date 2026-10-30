#!/usr/bin/env python3
"""Drive the public CLIs in disposable trees and retain each command's output."""
import argparse
import importlib
import unittest
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SUITES = ['files', 'stores', 'entrypoint', 'macos', 'debian_regeneration', 'distro', 'workflow', 'discovery']
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--shell', action='append', help='shell command; repeat for additional interpreters (default dash)')
parser.add_argument('--suite', action='append', choices=SUITES, help='suite; repeat to select several (default all)')
parser.add_argument('--batch-size', type=int, default=0, help='cases per command; 0 runs each complete suite (use smaller batches on loaded hosts)')
parser.add_argument('--output', type=Path, default=ROOT / '.build/verification', help='retained log/JSON directory')
parser.add_argument('--shellcheck', default=shutil.which('shellcheck'), help='shellcheck executable; required for full verification')
parser.add_argument('--timeout', type=int, default=45, help='maximum seconds per command (default 45)')
args = parser.parse_args()
if not 0 < args.timeout <= 45:
    parser.error('--timeout must be between 1 and 45 seconds')
if args.batch_size < 0:
    parser.error('--batch-size must be nonnegative')
args.output.mkdir(parents=True, exist_ok=True)
commands = [([sys.executable, 'tools/generate.py', '--check', '--verify-pems'], None)]
if args.shellcheck:
    commands.append(([args.shellcheck, '-s', 'sh', *[str(p.relative_to(ROOT)) for p in sorted(ROOT.glob('demudhra*.sh'))],
                     *[str(p.relative_to(ROOT)) for p in sorted((ROOT/'src').glob('*.sh'))],
                     *[str(p.relative_to(ROOT)) for p in sorted((ROOT/'tests/containers').glob('*.sh'))]], None))
else:
    parser.error('shellcheck is required; install it or pass --shellcheck PATH')
shells = []
for requested in args.shell or ['dash']:
    words = shlex.split(requested)
    if not words:
        parser.error('--shell must name an executable')
    executable = shutil.which(words[0])
    if not executable and words[0] == 'busybox':
        executable = next((str(path) for path in (
            Path('/bin/busybox'), Path('/usr/bin/busybox'),
            Path('/tmp/demudhra-userspace/usr/bin/busybox'))
            if path.is_file() and os.access(path, os.X_OK)), None)
    if not executable:
        parser.error(f'shell executable not found: {words[0]}; pass an absolute --shell path')
    words[0] = str(Path(executable).absolute())
    shells.append(shlex.join(words))
for shell in shells:
    for suite in args.suite or SUITES:
        command = [sys.executable, f'tests/test_{suite}.py']
        if suite in ('files', 'stores'):
            command += ['--shell', shell]
        if args.batch_size:
            sys.path.insert(0, str(ROOT / 'tests'))
            module = importlib.import_module(f'test_{suite}')
            def cases(test):
                if isinstance(test, unittest.TestSuite):
                    return [name for child in test for name in cases(child)]
                return [test.id().split('.', 1)[1]]
            names = cases(unittest.defaultTestLoader.loadTestsFromModule(module))
            for start in range(0, len(names), args.batch_size):
                commands.append((command + names[start:start + args.batch_size], shell))
        else:
            commands.append((command, shell))
results = []
for index, (command, shell) in enumerate(commands, 1):
    log = args.output / f'{index:02d}.log'
    print('RUN ' + shlex.join(command), flush=True)
    env = os.environ.copy()
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['DEMUDHRA_TEST_SHELL'] = shell or shells[0]
    with log.open('w') as stream:
        stream.write('$ ' + shlex.join(command) + '\n')
        stream.flush()
        try:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=args.timeout)
            exit_code = result.returncode
        except subprocess.TimeoutExpired:
            stream.write(f'\nFAIL: command exceeded {args.timeout} seconds\n')
            exit_code = 124
    body = log.read_text(errors='replace')
    # Unittest can exit zero despite unavailable store tools or platform steps.
    skipped = 'skipped=' in body or '... skipped ' in body
    status = 'FAIL' if exit_code else ('INCOMPLETE' if skipped else 'PASS')
    results.append({'command': command, 'status': status, 'exit_code': exit_code,
                    'timeout_seconds': args.timeout, 'shell': shell, 'log': str(log)})
    print(f'{status} {log}', flush=True)
    if exit_code:
        print(body, file=sys.stderr)
report = {'utc': datetime.now(timezone.utc).isoformat(), 'results': results,
          'not_run': ['six native distro containers', 'real macOS apply', 'live published release download', 'real-system apply']}
(args.output/'results.json').write_text(json.dumps(report, indent=2)+'\n')
print('Evidence retained at ' + str(args.output.resolve()))
raise SystemExit(0 if all(r['status']=='PASS' for r in results) else 1)
