import os
import unittest
from unittest.mock import patch
from build import diagnostic_paths_for_commit, split_diagnostic_logd
from pathlib import Path

class TestDiagnosticRedaction(unittest.TestCase):
    def test_diagnostic_paths_for_commit(self):
        logd_path, metadata_path, commit_id = diagnostic_paths_for_commit()
        self.assertTrue(logd_path.exists())
        self.assertTrue(metadata_path.exists())
        self.assertIsNotNone(commit_id)

    def test_split_diagnostic_logd(self):
        logd_path, _, _ = diagnostic_paths_for_commit()
        chunks = split_diagnostic_logd(logd_path)
        self.assertGreaterEqual(len(chunks), 1)
        for chunk in chunks:
            self.assertTrue(chunk.exists())

    def test_diagnostic_redaction(self):
        logd_path, metadata_path, _ = diagnostic_paths_for_commit()
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        self.assertNotIn('home', metadata)
        self.assertNotIn('repo', metadata)
        self.assertNotIn('temp', metadata)
        self.assertNotIn('machine', metadata)
        self.assertNotIn('username', metadata)

    def test_artifact_pairing(self):
        logd_path, metadata_path, _ = diagnostic_paths_for_commit()
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        self.assertIn('logd', metadata)
        self.assertEqual(metadata['logd'], str(logd_path.name))

if __name__ == '__main__':
    unittest.main()