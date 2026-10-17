"""Run one CI command without letting any of its output reach the public job log.

Usage: python ci/guard.py --label LABEL [--cwd DIR] -- COMMAND [ARGS...]

stdout and stderr go to $GUARD_LOG_DIR/<label>.log, which seal.py encrypts. The
console receives only one status line:

    STAGE <label> PASS|FAIL exit=<code> seconds=<s> log_sha256=<hex>

Compiler diagnostics, tracebacks and failure tails often quote source lines, so
nothing from the command is ever echoed. That also keeps problem matchers from
turning it into annotations. The command gets no stdin. On Windows it runs with its
own hidden console, so direct console writes (CONOUT$) cannot reach the step log; on
POSIX it runs in a new session without a controlling terminal. Exit status: the
command's own, or 1 when it could not start.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

LABEL = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')


def Main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--label', required=True)
    parser.add_argument('--cwd', type=Path)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not LABEL.match(args.label) or not command:
        print('STAGE invalid-guard-invocation FAIL exit=2', flush=True)
        return 2
    directory = Path(os.environ.get('GUARD_LOG_DIR') or Path(os.environ.get('RUNNER_TEMP', '.')) / 'guard-logs')
    directory.mkdir(parents=True, exist_ok=True)
    log = directory / f'{args.label}.log'
    options = dict(stdin=subprocess.DEVNULL, cwd=args.cwd)
    if os.name == 'nt':
        options['creationflags'] = subprocess.CREATE_NO_WINDOW
    else:
        options['start_new_session'] = True
    started = time.monotonic()
    with log.open('ab') as stream:
        stream.write(f'$ {command!r} (cwd={args.cwd})\n'.encode('utf-8'))
        stream.flush()
        try:
            code = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, **options).returncode
        except OSError as error:
            # The message can name paths inside the private checkout; keep it in the log only.
            stream.write(f'guard: could not start: {type(error).__name__}: {error}\n'.encode('utf-8'))
            code = 1
    seconds = round(time.monotonic() - started, 1)
    digest = hashlib.sha256(log.read_bytes()).hexdigest()
    with (directory / 'stages.jsonl').open('a', encoding='utf-8') as record:
        record.write(json.dumps(dict(label=args.label, exit_code=code, seconds=seconds, log_sha256=digest)) + '\n')
    print(f'STAGE {args.label} {"PASS" if code == 0 else "FAIL"} exit={code} seconds={seconds} log_sha256={digest}', flush=True)
    return code


if __name__ == '__main__':
    sys.exit(Main())
