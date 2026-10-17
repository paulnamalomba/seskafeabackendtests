"""Cache keys for the PETSc stack and the modern Linux reference, written to $GITHUB_OUTPUT.

Usage (under the guard, after the private checkout):
  python ci/keys.py --backend DIR --platform P --profile P --tier commit|engine|stack

It reads the private checkout but writes only hashes and names:
- stack_key: stack-v1-<runner image>-<platform>-<profile>-<PETSc lock commit>.
  The PETSc commit pins the toolchain, MPI and dependency sources; the runner
  image covers the compilers it provides.
- reference_key and reference_fallback: the Linux reference for this engine
  source identity (SourceEvidence.Identity, which excludes tools and tests),
  case catalogue and PETSc commit. A commit-tier run can use a full reference
  (the fallback); an engine run needs the full one. A stack run rebuilds the
  reference from source, so its key also names the run.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

REFERENCE_PLATFORM = 'linux-x64-debug'


def Keys(backend, platform, profile, tier, image, run_id):
    sys.path.insert(0, str(backend / 'tools'))
    from SourceEvidence import Identity
    petsc = json.loads((backend / 'cmake/DependencyLock.json').read_text(encoding='utf-8'))['petsc_commit']
    source = Identity(backend)['source_tree_sha256']
    catalog = hashlib.sha256((backend / 'tests/fixtures/cases.json').read_bytes()).hexdigest()
    base = f'reference-v1-{REFERENCE_PLATFORM}-{petsc}-{source[:24]}-{catalog[:24]}'
    reference = f'{base}-full' if tier == 'engine' else f'{base}-commit' if tier == 'commit' else f'{base}-full-run{run_id}'
    return dict(stack_key=f'stack-v1-{image}-{platform}-{profile}-{petsc}', reference_key=reference,
                reference_fallback=f'{base}-full' if tier == 'commit' else reference)


def Main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--backend', type=Path, required=True)
    parser.add_argument('--platform', choices=('windows-x64', 'macos-arm64', 'linux-x64'), required=True)
    parser.add_argument('--profile', choices=('debug', 'opt'), required=True)
    parser.add_argument('--tier', choices=('commit', 'engine', 'stack'), required=True)
    args = parser.parse_args()
    keys = Keys(args.backend.resolve(), args.platform, args.profile, args.tier, os.environ.get('ImageOS', 'unknown'),
                os.environ.get('GITHUB_RUN_ID', '0'))
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
        for name, value in keys.items():
            stream.write(f'{name}={value}\n')
    print('KEYS ' + ' '.join(f'{name}={value}' for name, value in keys.items()), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(Main())
