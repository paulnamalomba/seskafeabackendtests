"""Log self-check: prove the guard hides output and the audit detects leaks.

Usage:
  python ci/canary.py guarded   # compile a canary source with an error, through the guard
  python ci/canary.py planted   # sensitivity control: echo a canary line unguarded

Tokens are HMAC-SHA256(CANARY_KEY, "<run id>:<role>") and are never printed by
the guarded path. audit.py regenerates the same tokens and canary source from the
key and run id. In canary mode it expects the guarded token in 0 log lines and the
planted token and planted source line at least once; in qualify mode it expects
neither.
"""
import hashlib
import hmac
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def Token(role, run_id=None, key=None):
    key = (key or os.environ['CANARY_KEY']).encode('utf-8')
    run_id = run_id or os.environ['GITHUB_RUN_ID']
    return hmac.new(key, f'{run_id}:{role}'.encode('utf-8'), hashlib.sha256).hexdigest()[:32]


def CanarySource(run_id=None, key=None):
    """A Python file with a syntax error whose diagnostic quotes the line holding the guarded token."""
    guarded, planted = Token('guarded', run_id, key), Token('planted', run_id, key)
    return '\n'.join([
        '# Canary source for the CI log self-check; not part of any product.',
        f'PLANTED_CANARY_LINE = "line planted on purpose for the audit sensitivity check {planted}"',
        f'guarded_canary_value = "{guarded}" +',
        '',
    ])


def Main():
    role = sys.argv[1] if len(sys.argv) > 1 else ''
    directory = Path(os.environ.get('RUNNER_TEMP', '.')) / 'canary'
    directory.mkdir(parents=True, exist_ok=True)
    if role == 'guarded':
        source = directory / 'canary_source.py'
        source.write_text(CanarySource(), encoding='utf-8')
        result = subprocess.run([sys.executable, str(HERE / 'guard.py'), '--label', 'canary-compile', '--',
                                 sys.executable, '-m', 'py_compile', str(source)], capture_output=True, text=True)
        print(result.stdout.strip(), flush=True)  # the guard's single STAGE line
        log = Path(os.environ.get('GUARD_LOG_DIR') or directory.parent / 'guard-logs') / 'canary-compile.log'
        captured = log.is_file() and Token('guarded') in log.read_text(encoding='utf-8', errors='replace')
        print(f'CANARY guarded compile_failed={result.returncode != 0} captured_in_encrypted_log={captured}', flush=True)
        return 0 if result.returncode != 0 and captured else 1
    if role == 'planted':
        line = CanarySource().splitlines()[1]
        print(line, flush=True)  # deliberately unguarded: the audit must find this line
        return 0
    print('usage: canary.py guarded|planted', flush=True)
    return 2


if __name__ == '__main__':
    sys.exit(Main())
