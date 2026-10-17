"""Shallow-fetch one private backend commit with the read-only deploy key.

Usage (always under the guard, so git's messages stay in the encrypted log):
  python ci/guard.py --label private-checkout -- python ci/private_checkout.py [--ref SHA] --path DIR

actions/checkout would print git's "HEAD is now at <sha> <subject>" line and the
fetch summary to the public log. Run through the guard, this script keeps every
git message in the guard log instead. The key comes from BACKEND_DEPLOY_KEY. It
is written to a private file in RUNNER_TEMP for the fetch only, and deleted
afterwards. GitHub's SSH host keys are pinned in ci/github_known_hosts, taken
from api.github.com/meta.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
REMOTE = 'git@github.com:paulnamalomba/seskafeabackend.git'


def Run(*command, env=None):
    print('+', ' '.join(map(str, command)), flush=True)
    subprocess.run([str(item) for item in command], env=env, check=True)


def Slashed(path):
    return str(path).replace('\\', '/')


def Main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ref', default=os.environ.get('BACKEND_REF', ''), help='defaults to $BACKEND_REF')
    parser.add_argument('--path', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.ref):
        print('--ref must be a full 40-character commit SHA', flush=True)
        return 2
    key = os.environ.get('BACKEND_DEPLOY_KEY', '')
    if 'PRIVATE KEY' not in key:
        print('BACKEND_DEPLOY_KEY is not set', flush=True)
        return 2
    ssh = shutil.which('ssh')
    if not ssh:
        print('ssh was not found', flush=True)
        return 2
    path = args.path.resolve()
    if path.exists() and any(path.iterdir()):
        print(f'{path} is not empty', flush=True)
        return 2
    directory = Path(tempfile.mkdtemp(prefix='deploy-', dir=os.environ.get('RUNNER_TEMP')))
    keyFile = directory / 'id'
    try:
        keyFile.write_text(key.strip() + '\n', encoding='ascii', newline='\n')
        if os.name == 'nt':
            user = f'{os.environ["USERDOMAIN"]}\\{os.environ["USERNAME"]}'
            subprocess.run(['icacls', str(keyFile), '/inheritance:r', '/grant:r', f'{user}:F'], check=True)
        else:
            keyFile.chmod(0o600)
        environment = dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_SSH_COMMAND=(
            f'"{Slashed(ssh)}" -i "{Slashed(keyFile)}" -o IdentitiesOnly=yes -o BatchMode=yes '
            f'-o StrictHostKeyChecking=yes -o CheckHostIP=no -o "UserKnownHostsFile={Slashed(HERE / "github_known_hosts")}"'))
        environment.pop('BACKEND_DEPLOY_KEY')
        Run('git', 'init', '-q', path)
        Run('git', '-C', path, 'fetch', '--depth', '1', '--no-tags', REMOTE, args.ref, env=environment)
        Run('git', '-C', path, '-c', 'advice.detachedHead=false', 'checkout', '-q', '--detach', 'FETCH_HEAD')
        head = subprocess.run(['git', '-C', str(path), 'rev-parse', 'HEAD'], capture_output=True, text=True, check=True).stdout.strip()
        if head != args.ref:
            print(f'checked out {head}, not {args.ref}', flush=True)
            return 1
        print('checked out', head, flush=True)
        return 0
    finally:
        shutil.rmtree(directory, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(Main())
