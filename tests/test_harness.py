"""Local checks of the guard, seal, canary and audit behaviour (no network except the pinned age download)."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

CI = Path(__file__).resolve().parents[1] / 'ci'
sys.path.insert(0, str(CI))
import canary  # noqa: E402

SECRET_LINE = 'double privateStiffnessFactor = computeSecretModulus(element, gaussPoint);'


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.environment = dict(os.environ, RUNNER_TEMP=str(self.root), GUARD_LOG_DIR=str(self.root / 'guard-logs'),
                                CANARY_KEY='unit-test-key', GITHUB_RUN_ID='4242')

    def tearDown(self):
        self.directory.cleanup()

    def Run(self, *arguments):
        return subprocess.run([sys.executable, *map(str, arguments)], capture_output=True, text=True, env=self.environment)

    def test_guard_prints_only_the_stage_line_and_keeps_output_in_its_log(self):
        result = self.Run(CI / 'guard.py', '--label', 'leaky', '--', sys.executable, '-c',
                          f'import sys; print({SECRET_LINE!r}); sys.stderr.write("trace\\n"); sys.exit(3)')
        self.assertEqual(result.returncode, 3)
        self.assertNotIn('privateStiffnessFactor', result.stdout + result.stderr)
        self.assertRegex(result.stdout.strip(), r'^STAGE leaky FAIL exit=3 seconds=[0-9.]+ log_sha256=[0-9a-f]{64}$')
        log = (self.root / 'guard-logs/leaky.log').read_text(encoding='utf-8')
        self.assertIn(SECRET_LINE, log)
        self.assertIn('trace', log)

    def test_seal_round_trip_with_the_owner_identity(self):
        identity = Path(os.environ['USERPROFILE'] if os.name == 'nt' else os.environ['HOME']) / '.config/seskafea/ci-results.agekey'
        if not identity.is_file():
            self.skipTest('owner identity not present on this machine')
        payload = self.root / 'payload'
        (payload / 'inner').mkdir(parents=True)
        (payload / 'inner/result.txt').write_text(SECRET_LINE, encoding='utf-8')
        result = self.Run(CI / 'seal.py', '--name', 'unit', '--output', self.root / 'sealed', '--base', self.root, 'payload', 'missing-path')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('privateStiffnessFactor', result.stdout)
        sealed = self.root / 'sealed/unit.tar.xz.age'
        self.assertNotIn(b'privateStiffnessFactor', sealed.read_bytes())
        age = next((self.root / 'pinned-age').rglob('age.exe' if os.name == 'nt' else 'age'))
        plain = subprocess.run([str(age), '-d', '-i', str(identity), str(sealed)], capture_output=True, check=True).stdout
        with tarfile.open(fileobj=io.BytesIO(plain), mode='r:xz') as archive:
            manifest = json.loads(archive.extractfile('MANIFEST.json').read())
            self.assertEqual([item['path'] for item in manifest['files']], ['payload/inner/result.txt'])
            self.assertEqual(archive.extractfile('payload/inner/result.txt').read().decode(), SECRET_LINE)

    def test_canary_guarded_step_hides_the_token_but_captures_it(self):
        result = self.Run(CI / 'canary.py', 'guarded')
        self.assertEqual(result.returncode, 0, result.stdout)
        token = canary.Token('guarded', '4242', 'unit-test-key')
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertIn('captured_in_encrypted_log=True', result.stdout)

    def Logs(self, lines):
        archive = self.root / 'logs.zip'
        with zipfile.ZipFile(archive, 'w') as stream:
            stream.writestr('1_windows (debug).txt', '\n'.join(f'2026-10-17T12:00:00.0000000Z {line}' for line in lines))
        return archive

    def Audit(self, mode, lines, source=True):
        tree = self.root / 'source/src/seskaIntegration'
        tree.mkdir(parents=True, exist_ok=True)
        (tree / 'Secret.cpp').write_text('#include <x>\n    ' + SECRET_LINE + '\n', encoding='utf-8')
        arguments = [CI / 'audit.py', '--run-id', '4242', '--mode', mode, '--logs', self.Logs(lines), '--report', self.root / 'report.json']
        if source:
            arguments += ['--source', self.root / 'source']
        result = self.Run(*arguments)
        return result, json.loads((self.root / 'report.json').read_text(encoding='utf-8'))

    def test_audit_passes_a_clean_qualify_log(self):
        result, report = self.Audit('qualify', ['STAGE qualify PASS exit=0 seconds=1.0 log_sha256=' + '0' * 64])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(report['counts'], dict(source_text=0, canary_line=0, guarded_token=0, planted_token=0))

    def test_audit_detects_quoted_private_source_text(self):
        for quoted in ('   38 |     ' + SECRET_LINE, 'error: ' + SECRET_LINE + ' <- here', SECRET_LINE):
            with self.subTest(quoted=quoted):
                result, report = self.Audit('qualify', [quoted])
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertEqual(report['counts']['source_text'], 1)
                self.assertNotIn('privateStiffnessFactor', result.stdout)

    def test_qualify_audit_fails_closed_without_the_private_source(self):
        result, report = self.Audit('qualify', ['STAGE qualify PASS exit=0'], source=False)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertFalse(report['source_checked'])

    def test_private_checkout_refuses_a_partial_ref_and_a_missing_key(self):
        environment = dict(self.environment)
        environment.pop('BACKEND_DEPLOY_KEY', None)
        for ref, key in (('abc', 'x'), ('a' * 40, None)):
            env = dict(environment, BACKEND_REF=ref)
            if key:
                env['BACKEND_DEPLOY_KEY'] = '-----BEGIN OPENSSH PRIVATE KEY-----'
            result = subprocess.run([sys.executable, str(CI / 'private_checkout.py'), '--path', str(self.root / 'clone')],
                                    capture_output=True, text=True, env=env)
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertFalse((self.root / 'clone').exists())

    def test_audit_ignores_text_that_is_public_in_this_harness(self):
        result, report = self.Audit('qualify', ['Run python harness/ci/guard.py --label pip -- python -m pip install --only-binary=:all:'])
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_canary_audit_requires_the_planted_line_and_rejects_the_guarded_token(self):
        planted = canary.CanarySource('4242', 'unit-test-key').splitlines()[1]
        result, report = self.Audit('canary', [planted], source=False)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual((report['counts']['planted_token'], report['counts']['canary_line']), (1, 1))
        result, report = self.Audit('canary', ['nothing planted here'], source=False)
        self.assertEqual(result.returncode, 1)
        guarded = canary.Token('guarded', '4242', 'unit-test-key')
        result, report = self.Audit('canary', [planted, 'leak ' + guarded], source=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report['counts']['guarded_token'], 1)


if __name__ == '__main__':
    unittest.main()
