"""Decrypt and extract data that an earlier job sealed to ci/exchange.recipient.

Usage (under the guard): python ci/unseal.py --input FILE.tar.xz.age --output DIR [--identity-env EXCHANGE_IDENTITY]

The identity comes from the named environment variable (a workflow secret). It
is written to a private temporary file for the decryption only, then deleted.
Members must be regular files or directories inside DIR, and every file must
match the archive's MANIFEST.json. DIR must not exist yet.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from seal import Age  # noqa: E402


def Main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--identity-env', default='EXCHANGE_IDENTITY')
    args = parser.parse_args()
    identity = os.environ.get(args.identity_env, '')
    if 'AGE-SECRET-KEY-' not in identity:
        print(f'{args.identity_env} is not set', flush=True)
        return 2
    if args.output.exists():
        print(f'{args.output} already exists', flush=True)
        return 2
    with tempfile.TemporaryDirectory(dir=os.environ.get('RUNNER_TEMP')) as directory:
        key = Path(directory) / 'identity'
        key.write_text(identity.strip() + '\n', encoding='ascii')
        if os.name != 'nt':
            key.chmod(0o600)
        result = subprocess.run([str(Age()), '-d', '-i', str(key), str(args.input)], capture_output=True)
    if result.returncode:
        print(f'UNSEAL {args.input.name} FAIL exit={result.returncode}', flush=True)
        return 1
    output = args.output.resolve()
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode='r:xz') as stream:
        members = stream.getmembers()
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or not (member.isfile() or member.isdir()):
                print(f'UNSEAL {args.input.name} FAIL unsafe member', flush=True)
                return 1
        output.mkdir(parents=True)
        stream.extractall(output, members=members, filter='data')
    manifest = json.loads((output / 'MANIFEST.json').read_text(encoding='utf-8'))
    for entry in manifest['files']:
        path = output / entry['path']
        if not path.is_file() or path.stat().st_size != entry['bytes'] or hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
            print(f'UNSEAL {args.input.name} FAIL manifest mismatch', flush=True)
            return 1
    print(f'UNSEAL {args.input.name} files={len(manifest["files"])}', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(Main())
