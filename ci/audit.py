"""Scan a finished run's public logs for private source text and canary tokens.

Usage: python ci/audit.py --run-id ID --mode canary|qualify --logs LOGS.zip --report OUT.json [--source DIR]

Compilers and tracebacks quote source lines with prefixes ("38 |   ...", "error: ...")
and suffixes, so matching uses token shingles as well as whole lines:
- Index: from the private checkout's own code (seska/src, seska/include,
  seska/blvm, seska/info, src, tests, tools, cmake), every
  normalized line of at least 20 non-space characters, and every window of
  SHINGLE whitespace-separated tokens spanning at least 20 characters. Each is
  hashed with a fresh random salt that is never stored.
- Exclusions: anything that also occurs in this public harness (its workflows
  and scripts) is removed, because the runner legitimately echoes those.
- Search: each log line (timestamp prefix removed) is tested as a whole line,
  as every token suffix, and as every SHINGLE-token window. The canary tokens
  are searched for as plain substrings.

The report is sealed by the workflow. It holds the counts and, for each hit,
the log file, line number and matched text, so a hit can be triaged locally
after decryption. The console gets one status line with counts only.

Expectations:
- qualify: an indexed private checkout, and no source text, canary token or
  canary line.
- canary: the guarded token absent; the planted token and planted line present
  (the sensitivity control); no private source text.
Exit status 0 when the expectations hold, otherwise 1.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import zipfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from canary import CanarySource, Token  # noqa: E402

# SESKA's own code; the imported third-party packages (seska/packages) and example inputs are public or data.
ROOTS = ('seska/src', 'seska/include', 'seska/blvm', 'seska/info', 'src', 'tests', 'tools', 'cmake')
TEXT = {'.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx', '.inl', '.f', '.for', '.f90', '.f95', '.py', '.ps1',
        '.cmake', '.txt', '.json', '.yml', '.yaml', '.md', '.in', '.sh', '.cu', '.cuh'}
STAMP = re.compile(r'^\ufeff?\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z ')
MINIMUM = 20
SHINGLE = 5


def Tokens(line):
    return line.split()


def Long(text):
    return sum(not character.isspace() for character in text) >= MINIMUM


def Pieces(tokens, suffixes=False):
    """Whole line, token windows and (for log lines) token suffixes that are long enough to be distinctive."""
    if not tokens:
        return
    whole = ' '.join(tokens)
    if Long(whole):
        yield whole
    for start in range(0, max(0, len(tokens) - SHINGLE) + 1):
        window = ' '.join(tokens[start:start + SHINGLE])
        if len(tokens) >= SHINGLE and Long(window):
            yield window
    if suffixes:
        for start in range(1, len(tokens)):
            suffix = ' '.join(tokens[start:])
            if Long(suffix):
                yield suffix


def Lines(root, tops=None, everything=False):
    paths = []
    for top in tops or ('',):
        base = root / top
        if base.is_dir():
            paths += sorted(path for path in base.rglob('*') if path.is_file())
    for path in paths:
        if '.git' in path.parts or path.stat().st_size > 4 << 20:
            continue
        if everything or path.suffix.lower() in TEXT or path.name == 'CMakeLists.txt':
            yield from path.read_text(encoding='utf-8', errors='replace').splitlines()


def Main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--mode', choices=('canary', 'qualify'), required=True)
    parser.add_argument('--logs', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--source', type=Path)
    args = parser.parse_args()
    salt = os.urandom(16)

    def Digest(text):
        return hashlib.sha256(salt + text.encode('utf-8', errors='replace')).digest()

    public = {Digest(piece) for line in Lines(HERE.parent, everything=True) for piece in Pieces(Tokens(line))}
    source = set()
    if args.source:
        source = {Digest(piece) for line in Lines(args.source, ROOTS) for piece in Pieces(Tokens(line))} - public
    canaryText = CanarySource(args.run_id)
    canaryPieces = {Digest(piece) for line in canaryText.splitlines() for piece in Pieces(Tokens(line))} - public
    source -= canaryPieces
    guarded, planted = Token('guarded', args.run_id), Token('planted', args.run_id)
    hits = dict(source_text=[], canary_line=[], guarded_token=[], planted_token=[])
    files = 0
    with zipfile.ZipFile(args.logs) as logs:
        for member in logs.infolist():
            if member.is_dir():
                continue
            files += 1
            for number, raw in enumerate(logs.read(member).decode('utf-8', errors='replace').splitlines(), 1):
                line = STAMP.sub('', raw)
                where = dict(file=member.filename, line=number)
                if guarded in line:
                    hits['guarded_token'].append(where)
                if planted in line:
                    hits['planted_token'].append(where)
                found = {}
                for piece in Pieces(Tokens(line), suffixes=True):
                    digest = Digest(piece)
                    if digest in source:
                        found.setdefault('source_text', piece)
                    elif digest in canaryPieces:
                        found.setdefault('canary_line', piece)
                for kind, piece in found.items():
                    hits[kind].append(dict(where, text=piece))
    # Fail closed: a qualify audit without an indexed private checkout proves nothing.
    sourceChecked = bool(args.source) and args.source.is_dir() and len(source) > 0
    if args.mode == 'canary':
        passed = not hits['source_text'] and not hits['guarded_token'] and hits['planted_token'] and hits['canary_line']
    else:
        passed = sourceChecked and not any(hits.values())
    report = dict(run_id=args.run_id, mode=args.mode, log_files=files, source_pieces_indexed=len(source),
                  public_pieces_excluded=len(public), source_checked=sourceChecked,
                  counts={key: len(value) for key, value in hits.items()}, hits=hits, passed=bool(passed))
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    counts = ' '.join(f'{key}={len(value)}' for key, value in hits.items())
    print(f'AUDIT mode={args.mode} log_files={files} source_checked={sourceChecked} source_pieces_indexed={len(source)} {counts} '
          f'{"PASS" if passed else "FAIL"}',
          flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(Main())
