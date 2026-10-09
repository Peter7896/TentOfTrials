"""Exercise the generator with real safe encryption and synthetic build results.

No module build, bundled executable, or Git mutation is allowed in these tests.
"""
import hashlib
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import build
from tools import safe_logd

SOURCE = 'cafebabe' + '12345678' * 4
TREE = 'abcdef12' * 5
REQUIRE_CLEAN_SOURCE = build.require_clean_source

class SafeDiagnosticsIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / 'repo'
        self.root.mkdir()
        self.diag = self.root / 'diagnostic'
        for mocked in (
            patch.object(build, 'ROOT', self.root),
            patch.object(build, 'DIAGNOSTIC_DIR', self.diag),
            patch.object(build, 'current_source_commit', return_value=SOURCE),
            patch.object(build, 'current_source_tree', return_value=TREE),
            patch.object(build, 'require_clean_source'),
            patch.object(build, 'commit_diagnostic_artifacts', return_value=True),
            patch.object(build.subprocess, 'run', side_effect=AssertionError('no executable or git mutation')),
            patch.object(build.Path, 'home', return_value=self.root.parent / 'fixture-home'),
            patch.object(build.tempfile, 'gettempdir', return_value=str(self.root.parent / 'fixture-temp')),
            patch.object(build.getpass, 'getuser', return_value='fixture-user'),
            patch.object(build.platform, 'node', return_value='fixture-host'),
        ):
            mocked.start()
            self.addCleanup(mocked.stop)
        self.metadata = self.diag / 'build-cafebabe.json'

    def generate(self, output='synthetic compiler output', success=True):
        return build.generate_logd([('backend', success, 0.2, output,
                                     str(self.root / 'backend/target/backend') if success else None)],
                                   source_commit=SOURCE)

    def unpack(self):
        report = json.loads(self.metadata.read_text())
        archive = self.root / report['diagnostic_logd']
        return report, safe_logd.unpack_diagnostic_texts(archive, report['password'])

    def test_generated_log_is_real_and_source_bound(self):
        self.assertTrue(self.generate())
        report, texts = self.unpack()
        self.assertEqual(report['source_commit'], SOURCE)
        self.assertEqual(report['source_tree'], TREE)
        self.assertFalse(report['source_dirty'])
        self.assertEqual(report['commit'], SOURCE[:8])
        self.assertIn('source_commit: ' + SOURCE, texts['build-summary.txt'])
        self.assertIn('source_tree: ' + TREE, texts['build-summary.txt'])
        self.assertEqual(set(texts), set(safe_logd.REQUIRED_FILES))
        for name, text in texts.items():
            self.assertEqual(report['files'][name]['sha256'], hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(report['format'], safe_logd.FORMAT)
        self.assertNotIn('encryptly', report['decrypt_command'].lower())

    def test_logs_summary_and_json_redact_known_values(self):
        output = f'{self.root} fixture-user fixture-host API_KEY=synthetic-secret'
        self.assertTrue(self.generate(output))
        report, texts = self.unpack()
        combined = json.dumps(report) + '\n'.join(texts.values())
        for private in (str(self.root), 'fixture-user', 'fixture-host', 'synthetic-secret'):
            self.assertNotIn(private, combined)
        self.assertEqual(report['modules'][0]['artifact'], 'backend/target/backend')

    def test_short_identity_does_not_destroy_ordinary_words(self):
        with patch.object(build.getpass, 'getuser', return_value='me'):
            self.assertEqual(build.redact_diagnostic_text('metadata memory user=me'),
                             'metadata memory user=<redacted-identity>')

    def test_windows_case_and_slash_spellings(self):
        # A path's textual spelling can differ from this host's separator/case.
        with patch.object(build.Path, 'home', return_value=Path('C:/Users/Alice')):
            output = build.redact_diagnostic_text(r'c:\users\alice\secret C:/Users/ALICE/secret')
            self.assertNotIn('alice', output.lower())

    def test_system_snapshot_never_runs_system_commands(self):
        text = build.collect_system_info()
        self.assertIn('python:', text)
        for forbidden in ('hostname:', 'user:', '--- disk ---', 'SHELL=', 'HOME='):
            self.assertNotIn(forbidden, text)

    def test_failed_module_still_generates_actual_encrypted_log(self):
        self.assertTrue(self.generate('synthetic compilation failure', success=False))
        report, texts = self.unpack()
        self.assertEqual(report['failed'], 1)
        self.assertIn('synthetic compilation failure', texts['build.log'])

    def test_chunked_archive_reassembles_and_decrypts(self):
        with patch.object(build, 'DIAGNOSTIC_CHUNK_SIZE', 128):
            self.assertTrue(self.generate('long log ' * 50))
        report = json.loads(self.metadata.read_text())
        self.assertTrue(report['chunked'])
        self.assertGreater(len(report['diagnostic_logd']), 1)
        self.assertFalse((self.diag / 'build-cafebabe.logd').exists())
        reassembled = self.root / 'reassembled.logd'
        reassembled.write_bytes(b''.join((self.root / name).read_bytes()
                                        for name in report['diagnostic_logd']))
        texts = safe_logd.unpack_diagnostic_texts(reassembled, report['password'])
        self.assertIn('long log ' * 50, texts['build.log'])

    def test_existing_source_material_is_preserved(self):
        self.assertTrue(self.generate())
        before = {p.name: p.read_bytes() for p in self.diag.iterdir()}
        self.assertFalse(self.generate('changed'))
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.diag.iterdir()})

    def test_redirected_diagnostic_directory_is_rejected(self):
        outside = self.root.parent / 'outside'
        outside.mkdir()
        try:
            self.diag.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('symlink creation unavailable')
        self.assertFalse(self.generate())
        self.assertEqual(list(outside.iterdir()), [])

    def test_changed_source_or_dirty_source_is_rejected(self):
        self.assertFalse(build.generate_logd([], source_commit='deadbeef' + '0'*32))
        self.assertFalse(build.generate_logd([], source_tree='0'*40))
        with patch.object(build, 'require_clean_source', side_effect=ValueError('dirty source')):
            self.assertFalse(self.generate())
        self.assertFalse(self.diag.exists())

    def test_oversize_logs_fail_explicitly_with_failure_json(self):
        with patch.object(safe_logd, 'MAX_FILE_BYTES', 100):
            self.assertFalse(self.generate('full compiler output ' * 100))
        report = json.loads(self.metadata.read_text())
        self.assertIsNone(report['diagnostic_logd'])
        self.assertIsNone(report['password'])
        self.assertIsNone(report['modules'][0]['full_output'])
        self.assertIn('size limit', report['diagnostic_logd_error'])
        self.assertEqual(list(self.diag.glob('*.logd')), [])

    def test_untracked_source_is_rejected_by_real_guard(self):
        status = subprocess.CompletedProcess([], 0, stdout="?? new_source.go\n", stderr="")
        with patch.object(build.subprocess, "run", return_value=status) as command:
            with self.assertRaisesRegex(ValueError, "untracked"):
                REQUIRE_CLEAN_SOURCE()
            self.assertIn("--untracked-files=all", command.call_args.args[0])

    def test_clean_rejects_symlink_directory_before_module_cleanup(self):
        outside = self.root.parent / "outside"
        outside.mkdir()
        evidence = outside / "build-cafebabe.json"
        evidence.write_text("preserve")
        try:
            self.diag.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable")
        with patch.object(build.sys, "argv", ["build.py", "--clean", "-m", "backend"]), \
                patch.object(build, "check_prerequisites", return_value=[]), \
                patch.object(build, "clean_module") as clean:
            self.assertEqual(build.main(), 1)
            clean.assert_not_called()
        self.assertEqual(evidence.read_text(), "preserve")

    def test_clean_rejects_symlink_entry(self):
        self.diag.mkdir()
        outside = self.root.parent / "outside"
        outside.write_text("preserve")
        try:
            (self.diag / "build-cafebabe.json").symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable")
        with patch.object(build.sys, "argv", ["build.py", "--clean", "-m", "backend"]), \
                patch.object(build, "check_prerequisites", return_value=[]), \
                patch.object(build, "clean_module") as clean:
            self.assertEqual(build.main(), 1)
            clean.assert_not_called()
        self.assertEqual(outside.read_text(), "preserve")

    def test_large_log_has_honest_preview_and_full_cli_output(self):
        output = 'synthetic full output 诊断\n' * 50000
        self.assertGreater(len(output.encode()), 1024*1024)
        self.assertTrue(self.generate(output))
        report = json.loads(self.metadata.read_text())
        module = report['modules'][0]
        self.assertTrue(module['output_truncated'])
        self.assertEqual(module['output_byte_count'], len(output.encode()))
        self.assertLessEqual(len(module['output'].encode()), 16*1024)
        self.assertLess(self.metadata.stat().st_size, safe_logd.MAX_METADATA_BYTES)
        destination = self.root / 'unpacked'
        self.assertEqual(safe_logd.main(['unpack', str(self.root / report['diagnostic_logd']),
                                       str(destination), '--metadata', str(self.metadata)]), 0)
        self.assertIn(output, (destination / 'build.log').read_text())

if __name__ == '__main__':
    unittest.main()
