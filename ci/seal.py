"""Archive CI outputs and encrypt them to the owner's age recipient.

Usage: python ci/seal.py --name NAME --output DIR [--base DIR] PATH...

Writes DIR/NAME.tar.xz.age. Only the holder of the matching age identity can read
it; the job itself can encrypt but never decrypt. PATH entries that do not exist
are skipped, so the seal step can run after a failure. The archive carries
MANIFEST.json, with every file's size and SHA-256, for integrity checks after
decryption. The pinned age binary for this platform is downloaded and verified
from ci/tools.json. The console gets one line with the encrypted size and hash.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent


def Platform():
    if sys.platform == 'win32':
        return 'windows-x64'
    if sys.platform == 'darwin':
        return 'macos-arm64'
    return 'linux-x64'


def Age():
    """The pinned age binary for this platform, verified by SHA-256 before extraction."""
    pin = json.loads((HERE / 'tools.json').read_text(encoding='utf-8'))['age']['archives'][Platform()]
    cache = Path(os.environ.get('RUNNER_TEMP', tempfile.gettempdir())) / 'pinned-age'
    binary = cache / pin['binary']
    if binary.is_file():
        return binary
    cache.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(pin['url'], timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != pin['sha256']:
        raise SystemExit('Pinned age archive differs from ci/tools.json')
    if pin['url'].endswith('.zip'):
        zipfile.ZipFile(io.BytesIO(data)).extractall(cache)
    else:
        tarfile.open(fileobj=io.BytesIO(data), mode='r:gz').extractall(cache, filter='data')
    if os.name != 'nt':
        binary.chmod(0o755)
    return binary


def Sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def Main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--base', type=Path, default=Path('.'))
    parser.add_argument('paths', nargs='+')
    args = parser.parse_args()
    base = args.base.resolve()
    files = []
    for entry in args.paths:
        path = Path(entry)
        if any(character in entry for character in '*?['):
            anchor = Path(path.anchor) if path.is_absolute() else base
            matches = sorted(anchor.glob(str(path.relative_to(path.anchor)) if path.is_absolute() else entry))
        else:
            matches = [path if path.is_absolute() else base / path]
        for match in matches:
            if match.is_file():
                files.append(match)
            elif match.is_dir():
                files.extend(sorted(item for item in match.rglob('*') if item.is_file() and not item.is_symlink()))
    files = sorted(set(files))

    def Arcname(path):
        try:
            return path.resolve().relative_to(base).as_posix()
        except ValueError:
            return 'external/' + path.resolve().as_posix().lstrip('/').replace(':', '')

    manifest = dict(schema=1, created=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), platform=Platform(),
                    machine=platform.machine(), run_id=os.environ.get('GITHUB_RUN_ID'),
                    files=[dict(path=Arcname(path), bytes=path.stat().st_size, sha256=Sha256(path)) for path in files])
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / f'{args.name}.tar.xz'
    with tarfile.open(archive, 'w:xz', preset=1) as stream:
        data = json.dumps(manifest, indent=2).encode('utf-8')
        info = tarfile.TarInfo('MANIFEST.json')
        info.size = len(data)
        stream.addfile(info, io.BytesIO(data))
        for path in files:
            stream.add(path, arcname=Arcname(path), recursive=False)
    sealed = archive.with_name(archive.name + '.age')
    recipient = HERE / 'results.recipient'
    result = subprocess.run([str(Age()), '-R', str(recipient), '-o', str(sealed), str(archive)], capture_output=True)
    archive.unlink()
    if result.returncode:
        print(f'SEAL {args.name} FAIL exit={result.returncode}', flush=True)
        return 1
    print(f'SEAL {args.name} files={len(files)} bytes={sealed.stat().st_size} sha256={Sha256(sealed)}', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(Main())
