#!/usr/bin/env python3

import json
import tempfile
import unittest
from pathlib import Path

from legacy_migration import MigrationConfig, MigrationEngine, MigrationStatus, MigrationType


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


class DryRunRestoreValidationTest(unittest.TestCase):
    def make_engine(self, migration_id: str, backup_dir: Path) -> MigrationEngine:
        return MigrationEngine(
            MigrationConfig(
                migration_id=migration_id,
                migration_type=MigrationType.DATA,
                from_version=1,
                to_version=2,
                source_connection="dry-run-source",
                target_connection="dry-run-target",
                backup_dir=str(backup_dir),
                dry_run=True,
                create_backup=False,
            )
        )

    def test_success_reports_rows_checksums_and_does_not_write_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup_root = root / "backups"
            backup_path = backup_root / "migration_MIG001"
            backup_path.mkdir(parents=True)
            (backup_path / "users.jsonl").write_text('{"id": 1}\n', encoding="utf-8")
            write_json(
                backup_path / "manifest.json",
                {
                    "migration_id": "MIG001",
                    "from_version": 1,
                    "to_version": 2,
                    "row_count": 1,
                    "checksums": {"users": "abc123"},
                    "files": [{"path": "users.jsonl"}],
                },
            )
            config_path = root / "dry-run.json"
            target_path = root / "target.sqlite"
            write_json(
                config_path,
                {
                    "migration_id": "MIG001",
                    "backup_dir": str(backup_root),
                    "target_schema_version": 1,
                    "target_connection": str(target_path),
                },
            )

            result = self.make_engine("MIG001", backup_root).dry_run_restore_validation(str(config_path))

            self.assertEqual(result.status, MigrationStatus.COMPLETED)
            self.assertFalse(result.metadata["would_modify_target"])
            self.assertEqual(result.total_records, 1)
            self.assertEqual(result.checksums, {"users": "abc123"})
            self.assertFalse(target_path.exists())

    def test_missing_backup_returns_structured_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup_root = root / "backups"
            config_path = root / "dry-run.json"
            write_json(
                config_path,
                {
                    "migration_id": "MIG404",
                    "backup_dir": str(backup_root),
                    "target_schema_version": 1,
                },
            )

            result = self.make_engine("MIG404", backup_root).dry_run_restore_validation(str(config_path))

            self.assertEqual(result.status, MigrationStatus.FAILED)
            self.assertEqual(result.errors[0]["phase"], "backup_check")
            self.assertIn("does not exist", result.errors[0]["error"])

    def test_schema_mismatch_returns_structured_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup_root = root / "backups"
            backup_path = backup_root / "migration_MIG002"
            backup_path.mkdir(parents=True)
            write_json(
                backup_path / "manifest.json",
                {
                    "migration_id": "MIG002",
                    "from_version": 1,
                    "to_version": 2,
                    "files": [],
                },
            )
            config_path = root / "dry-run.json"
            write_json(
                config_path,
                {
                    "migration_id": "MIG002",
                    "backup_dir": str(backup_root),
                    "target_schema_version": 2,
                },
            )

            result = self.make_engine("MIG002", backup_root).dry_run_restore_validation(str(config_path))

            self.assertEqual(result.status, MigrationStatus.FAILED)
            self.assertEqual(result.errors[0]["phase"], "schema_check")
            self.assertEqual(result.errors[0]["expected_schema_version"], 1)
            self.assertEqual(result.errors[0]["target_schema_version"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
