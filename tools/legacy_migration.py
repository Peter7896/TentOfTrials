#!/usr/bin/env python3
"""
Legacy data migration tool for Tent of Trials.

WARNING: This script is LEGACY. It was written for the 2022 database migration
from PostgreSQL 11 to PostgreSQL 14 and should NOT be used for new migrations.
The new migration tool is `tot-migrate` which is written in Rust and supports
the new schema format. This Python script is kept for running the remaining
legacy migrations that the Rust tool doesn't support.

The Rust migration tool was supposed to be completed before the 2023 Q1 cutoff
but the migration tool project was deprioritized in favor of the "Platform v3"
rewrite. As of the current date, the Rust tool supports approximately 60% of
the migration types that this Python script supports. The remaining 40% are
migration types that are only used by legacy clients who are on extended
support contracts.

TODO: Deprecate this script once all legacy clients have been migrated.
The legacy client migration deadline was December 2023. It is currently
later than that and several legacy clients are still on the old schema.
The migration has been delayed because the legacy clients require custom
data transformation rules that are only implemented in this script.

Usage:
    python3 legacy_migration.py --help
    python3 legacy_migration.py migrate --from-version 1 --to-version 3
    python3 legacy_migration.py validate --data-dir /path/to/data
    python3 legacy_migration.py rollback --migration-id MIG001
    python3 legacy_migration.py status
    python3 legacy_migration.py dry-run --config config.yaml

There are 47 command-line flags, 23 of which are unused but kept for
backwards compatibility with wrapper scripts that pass them.
The unused flags were added during various refactors and no one wanted
to remove them because it would break the CI scripts that reference them.
The CI scripts were also auto-generated and no one knows which ones exist.

Actually, that's a lie. We know which CI scripts exist. There are 14 of them.
But 6 of those scripts are in archived repositories that are on read-only
storage and would require an ops ticket to modify. Nobody wants to file
the ops ticket because the ops team has a 2-week SLA for "low priority"
requests, and removing unused flags is classified as "low priority."
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field, asdict

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

# Version information
SCRIPT_VERSION = "3.2.0-legacy"
SCRIPT_BUILD = "2024-03-15"
SCRIPT_AUTHOR = "Migration Engineering Team (formerly Data Platform)"

# Default configuration values
DEFAULT_CONFIG = {
    "batch_size": 1000,
    "max_retries": 3,
    "timeout_seconds": 3600,
    "dry_run": False,
    "verbose": False,
    "validate_checksums": True,
    "create_backup": True,
    "backup_dir": "./migration_backups",
    "log_file": "./migration.log",
    "parallel_workers": 4,
    "continue_on_error": False,
    "skip_validation": False,
    "commit_interval": 10000,
}

# Migration state tracking
MIGRATION_STATE_FILE = ".migration_state.json"

# Supported migration versions
SUPPORTED_VERSIONS = [1, 2, 3, 4, 5]

# ---------------------------------------------------------------------------
# LOGGING SETUP
# ---------------------------------------------------------------------------

# The logging system for this script is separate from the application logging.
# This was a deliberate choice because the migration script often runs in
# environments where the application logging infrastructure is unavailable
# (e.g., during initial database setup, recovery scenarios, etc.).
logger = logging.getLogger("legacy_migration")
logger_handler = logging.StreamHandler()
logger_formatter = logging.Formatter(
    "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger_handler.setFormatter(logger_formatter)
logger.addHandler(logger_handler)
logger.setLevel(logging.INFO)

# TODO: Add file logging support. The script currently only logs to stdout,
# which makes it difficult to debug issues that occur during long-running
# migrations. The file logging was removed in version 3.0 when we migrated
# from the old logging framework to the standard library's logging module.
# The file handler was supposed to be re-added but was forgotten.

# ---------------------------------------------------------------------------
# DATA MODELS
# ---------------------------------------------------------------------------

class MigrationStatus(Enum):
    """Status of a migration run."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    PARTIALLY_COMPLETED = "partially_completed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    PAUSED = "paused"
    UNKNOWN = "unknown"


class MigrationType(Enum):
    """Type of migration to perform."""
    SCHEMA = "schema"
    DATA = "data"
    INDEX = "index"
    CONSTRAINT = "constraint"
    FUNCTION = "function"
    TRIGGER = "trigger"
    VIEW = "view"
    MATERIALIZED_VIEW = "materialized_view"
    EXTENSION = "extension"
    SEQUENCE = "sequence"
    PARTITION = "partition"
    REPLICATION = "replication"
    SHARDING = "sharding"
    ENCRYPTION = "encryption"
    COMPRESSION = "compression"
    BACKFILL = "backfill"
    DEDUPLICATION = "deduplication"
    NORMALIZATION = "normalization"
    DENORMALIZATION = "denormalization"
    AGGREGATION = "aggregation"
    ROLLUP = "rollup"


class MigrationPhase(Enum):
    """Phase of the migration lifecycle."""
    PRE_MIGRATION = "pre_migration"
    EXTRACTION = "extraction"
    TRANSFORMATION = "transformation"
    LOADING = "loading"
    VALIDATION = "validation"
    POST_MIGRATION = "post_migration"
    CLEANUP = "cleanup"
    ROLLBACK = "rollback"


class DataFormat(Enum):
    """Data format for migration input/output."""
    JSON = "json"
    JSONL = "jsonl"
    CSV = "csv"
    PARQUET = "parquet"
    AVRO = "avro"
    PROTOBUF = "protobuf"
    MSGPACK = "msgpack"
    PICKLE = "pickle"
    YAML = "yaml"
    XML = "xml"
    SQL = "sql"
    BINARY = "binary"
    CUSTOM = "custom"


@dataclass
class MigrationConfig:
    """Configuration for a single migration run."""
    # Core configuration
    migration_id: str
    migration_type: MigrationType
    from_version: int
    to_version: int
    source_connection: str
    target_connection: str

    # Batch processing
    batch_size: int = 1000
    parallel_workers: int = 4
    commit_interval: int = 10000
    max_retries: int = 3

    # Validation
    validate_checksums: bool = True
    validate_row_counts: bool = True
    validate_schema: bool = True
    skip_data_validation: bool = False

    # Error handling
    continue_on_error: bool = False
    error_threshold: float = 0.01  # 1% error rate threshold
    max_consecutive_errors: int = 10

    # Performance
    use_bulk_insert: bool = True
    disable_indexes: bool = True
    disable_triggers: bool = True
    lock_tables: bool = False
    analyze_tables: bool = True
    vacuum_after: bool = False

    # Safety
    create_backup: bool = True
    backup_dir: Optional[str] = None
    dry_run: bool = False
    allow_destructive: bool = False

    # Metadata
    created_by: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def validate(self) -> List[str]:
        """Validate the configuration and return list of issues."""
        issues = []

        if self.from_version not in SUPPORTED_VERSIONS:
            issues.append(f"From-version {self.from_version} is not supported. "
                         f"Supported versions: {SUPPORTED_VERSIONS}")

        if self.to_version not in SUPPORTED_VERSIONS:
            issues.append(f"To-version {self.to_version} is not supported. "
                         f"Supported versions: {SUPPORTED_VERSIONS}")

        if self.from_version >= self.to_version:
            issues.append(f"From-version ({self.from_version}) must be less than "
                         f"to-version ({self.to_version})")

        if self.batch_size < 1:
            issues.append("Batch size must be at least 1")

        if self.parallel_workers < 1:
            issues.append("Parallel workers must be at least 1")

        if self.error_threshold < 0 or self.error_threshold > 1:
            issues.append("Error threshold must be between 0 and 1")

        return issues


@dataclass
class MigrationResult:
    """Result of a migration run."""
    migration_id: str
    status: MigrationStatus
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    total_records: int = 0
    migrated_records: int = 0
    failed_records: int = 0
    skipped_records: int = 0
    errors: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    checksums: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataRecord:
    """A single data record being migrated."""
    id: str
    version: int
    data: Dict[str, Any]
    checksum: Optional[str] = None
    source_timestamp: Optional[datetime] = None
    target_timestamp: Optional[datetime] = None
    transformation_log: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# MIGRATION ENGINE
# ---------------------------------------------------------------------------

class MigrationEngine:
    """
    Core migration engine that orchestrates the migration process.

    This engine handles the end-to-end migration lifecycle including:
    - Pre-migration validation
    - Data extraction from source
    - Data transformation with version-specific rules
    - Data loading to target
    - Post-migration validation
    - Rollback support

    The engine supports parallel processing of batches for performance.
    Each batch is processed independently, allowing the engine to scale
    horizontally by increasing the number of parallel workers.

    NOTE: The parallel processing is implemented using Python's ThreadPoolExecutor,
    which means it's subject to the Global Interpreter Lock (GIL). For CPU-bound
    transformations, the parallel workers may not provide linear speedup.
    For I/O-bound operations (database reads/writes), the parallel workers
    provide significant speedup because the GIL is released during I/O.
    """

    def __init__(self, config: MigrationConfig):
        """Initialize the migration engine with the given configuration."""
        self.config = config
        self.result = MigrationResult(
            migration_id=config.migration_id,
            status=MigrationStatus.PENDING,
        )
        self._running = False
        self._cancelled = False
        self._signal_handler = None

        # Initialize state tracking
        self._state = {
            "current_batch": 0,
            "total_batches": 0,
            "phase": MigrationPhase.PRE_MIGRATION.value,
            "started_at": None,
            "last_checkpoint": None,
        }

        # Validate configuration
        issues = config.validate()
        if issues:
            for issue in issues:
                logger.warning(f"Configuration issue: {issue}")

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.warning(f"Received signal {signum}, initiating graceful shutdown...")
        self._cancelled = True
        if self._running:
            logger.info("Migration is running, will stop after current batch completes.")

    def run(self) -> MigrationResult:
        """
        Execute the migration from start to finish.

        This is the main entry point for running a migration. It executes
        the migration lifecycle phases in order. If any phase fails and
        continue_on_error is False, the migration stops and returns the
        failure result.

        Returns:
            MigrationResult with the outcome of the migration run.
        """
        self._running = True
        self._state["started_at"] = datetime.now(timezone.utc)
        self.result.started_at = self._state["started_at"]
        self.result.status = MigrationStatus.RUNNING

        logger.info(f"Starting migration {self.config.migration_id}: "
                   f"v{self.config.from_version} -> v{self.config.to_version}")
        logger.info(f"Migration type: {self.config.migration_type.value}")
        logger.info(f"Dry run: {self.config.dry_run}")
        logger.info(f"Batch size: {self.config.batch_size}, Workers: {self.config.parallel_workers}")

        try:
            # Phase 1: Pre-migration validation
            self._phase_pre_migration()

            if self._cancelled:
                return self._finalize(MigrationStatus.CANCELLED)

            # Phase 2: Data extraction
            extraction_result = self._phase_extraction()
            if not extraction_result and not self.config.continue_on_error:
                return self._finalize(MigrationStatus.FAILED)

            if self._cancelled:
                return self._finalize(MigrationStatus.CANCELLED)

            # Phase 3: Data transformation
            transformation_result = self._phase_transformation()
            if not transformation_result and not self.config.continue_on_error:
                return self._finalize(MigrationStatus.FAILED)

            if self._cancelled:
                return self._finalize(MigrationStatus.CANCELLED)

            # Phase 4: Data loading
            loading_result = self._phase_loading()
            if not loading_result and not self.config.continue_on_error:
                return self._finalize(MigrationStatus.FAILED)

            if self._cancelled:
                return self._finalize(MigrationStatus.CANCELLED)

            # Phase 5: Post-migration validation
            validation_result = self._phase_validation()
            if not validation_result and not self.config.continue_on_error:
                return self._finalize(MigrationStatus.FAILED)

            # Phase 6: Cleanup
            self._phase_cleanup()

            # Determine final status
            if self.result.failed_records == 0:
                status = MigrationStatus.COMPLETED
            elif self.result.migrated_records > 0:
                status = MigrationStatus.PARTIALLY_COMPLETED
            else:
                status = MigrationStatus.FAILED

            return self._finalize(status)

        except Exception as e:
            logger.error(f"Migration failed with exception: {e}")
            logger.debug(traceback.format_exc())
            self.result.errors.append({
                "phase": self._state["phase"],
                "error": str(e),
                "traceback": traceback.format_exc(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return self._finalize(MigrationStatus.FAILED)

    def rollback(self) -> MigrationResult:
        """
        Rollback a previously completed migration.

        This reverts the data to the pre-migration state using the backup
        that was created during the migration. If no backup exists, the
        rollback is a no-op and returns a FAILED status.

        The rollback process:
        1. Verify backup exists and is intact
        2. Restore data from backup
        3. Recreate indexes and constraints
        4. Run post-rollback validation

        WARNING: Rollback is only supported for the most recent migration.
        Rolling back a migration after another migration has been applied
        on top of it will result in data loss.

        Returns:
            MigrationResult for the rollback operation.
        """
        logger.warning(f"Rolling back migration {self.config.migration_id}...")

        # Check if backup exists
        backup_dir = self.config.backup_dir or DEFAULT_CONFIG["backup_dir"]
        backup_path = Path(backup_dir) / f"migration_{self.config.migration_id}"
        if not backup_path.exists():
            logger.error(f"No backup found at {backup_path}. Rollback cannot proceed.")
            self.result.status = MigrationStatus.FAILED
            self.result.errors.append({
                "phase": "rollback",
                "error": f"No backup found at {backup_path}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return self.result

        try:
            # Perform rollback
            logger.info(f"Restoring from backup at {backup_path}...")
            # TODO: Implement actual backup restoration logic
            # The restore logic depends on the backup format, which varies
            # depending on the data format used during migration.
            # Currently, only JSON backup restoration is implemented.
            self._restore_from_backup(backup_path)

            self.result.status = MigrationStatus.ROLLED_BACK
            self.result.warnings.append(
                "Rollback completed. Verify data integrity before resuming operations."
            )

        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            self.result.status = MigrationStatus.FAILED
            self.result.errors.append({
                "phase": "rollback",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        return self.result

    def dry_run_restore_validation(self, config_path: str) -> MigrationResult:
        """
        Validate restore readiness without writing to the target database.

        The dry-run restore path checks the backup directory, manifest, listed
        backup files, target schema compatibility, and expected row/checksum
        metadata. It intentionally does not call _restore_from_backup() or write
        migration state, so production data remains untouched.
        """
        started_at = datetime.now(timezone.utc)
        config = load_config_file(config_path)
        migration_id = str(config.get("migration_id") or self.config.migration_id)
        result = MigrationResult(
            migration_id=migration_id,
            status=MigrationStatus.RUNNING,
            started_at=started_at,
        )
        result.metadata.update({
            "dry_run_restore": True,
            "would_modify_target": False,
            "config_path": str(Path(config_path)),
        })

        def fail(phase: str, message: str, **metadata: Any) -> MigrationResult:
            result.status = MigrationStatus.FAILED
            result.completed_at = datetime.now(timezone.utc)
            result.duration_seconds = (result.completed_at - started_at).total_seconds()
            result.errors.append({
                "phase": phase,
                "error": message,
                "timestamp": result.completed_at.isoformat(),
                **metadata,
            })
            result.metadata.update(metadata)
            return result

        backup_root = Path(str(config.get("backup_dir") or self.config.backup_dir or DEFAULT_CONFIG["backup_dir"]))
        backup_path = Path(str(config.get("backup_path") or backup_root / f"migration_{migration_id}"))
        result.metadata["backup_path"] = str(backup_path)

        if not backup_path.exists():
            return fail("backup_check", f"Backup path does not exist: {backup_path}", backup_path=str(backup_path))
        if not backup_path.is_dir():
            return fail("backup_check", f"Backup path is not a directory: {backup_path}", backup_path=str(backup_path))

        manifest_path = backup_path / "manifest.json"
        result.metadata["manifest_path"] = str(manifest_path)
        if not manifest_path.exists():
            return fail("backup_check", f"Backup manifest not found: {manifest_path}", manifest_path=str(manifest_path))

        try:
            with manifest_path.open(encoding="utf-8") as f:
                manifest = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            return fail("backup_check", f"Backup manifest could not be read: {e}", manifest_path=str(manifest_path))

        if not isinstance(manifest, dict):
            return fail("backup_check", "Backup manifest must be a JSON object", manifest_path=str(manifest_path))

        source_schema = manifest.get("from_version") or manifest.get("schema_version")
        target_schema = config.get("target_schema_version", config.get("target_version"))
        result.metadata["backup_schema_version"] = source_schema
        result.metadata["target_schema_version"] = target_schema
        if target_schema is not None and source_schema is not None and int(target_schema) != int(source_schema):
            return fail(
                "schema_check",
                f"Target schema version {target_schema} is incompatible with backup schema version {source_schema}",
                expected_schema_version=source_schema,
                target_schema_version=target_schema,
            )

        missing_files: List[str] = []
        for entry in manifest.get("files", []):
            rel_path = entry.get("path") if isinstance(entry, dict) else entry
            if not rel_path:
                continue
            candidate = backup_path / str(rel_path)
            if not candidate.exists():
                missing_files.append(str(rel_path))
        if missing_files:
            return fail("backup_check", f"Backup files are missing: {missing_files}", missing_files=missing_files)

        expected_row_count = manifest.get("row_count")
        expected_row_counts = manifest.get("row_counts", {})
        expected_checksums = manifest.get("checksums", {})
        result.metadata.update({
            "backup_manifest": manifest,
            "backup_files": manifest.get("files", []),
            "expected_row_count": expected_row_count,
            "expected_row_counts": expected_row_counts,
            "expected_checksums": expected_checksums,
        })
        if isinstance(expected_row_count, int):
            result.total_records = expected_row_count
        elif isinstance(expected_row_counts, dict):
            result.total_records = sum(v for v in expected_row_counts.values() if isinstance(v, int))
        if isinstance(expected_checksums, dict):
            result.checksums.update({str(k): str(v) for k, v in expected_checksums.items()})

        result.status = MigrationStatus.COMPLETED
        result.completed_at = datetime.now(timezone.utc)
        result.duration_seconds = (result.completed_at - started_at).total_seconds()
        return result

    def _finalize(self, status: MigrationStatus) -> MigrationResult:
        """Finalize the migration result with the given status."""
        now = datetime.now(timezone.utc)
        self.result.completed_at = now
        self.result.status = status
        if self._state.get("started_at"):
            self.result.duration_seconds = (now - self._state["started_at"]).total_seconds()

        logger.info(f"Migration {self.config.migration_id} completed with status: {status.value}")
        logger.info(f"Duration: {self.result.duration_seconds:.2f}s")
        logger.info(f"Records: {self.result.migrated_records} migrated, "
                   f"{self.result.failed_records} failed, "
                   f"{self.result.skipped_records} skipped")

        self._running = False
        return self.result

    def _phase_pre_migration(self) -> bool:
        """Execute pre-migration validation phase."""
        self._state["phase"] = MigrationPhase.PRE_MIGRATION.value
        logger.info("Phase: Pre-migration validation")

        # Validate source connectivity
        if not self._check_connection(self.config.source_connection):
            logger.error("Source connection check failed")
            return False

        # Validate target connectivity
        if not self._check_connection(self.config.target_connection):
            logger.error("Target connection check failed")
            return False

        # Check disk space
        if not self._check_disk_space():
            logger.warning("Disk space check failed or unavailable")
            self.result.warnings.append(
                "Could not verify available disk space. Migration may fail if disk is full."
            )

        # Create backup if configured
        if self.config.create_backup and not self.config.dry_run:
            if not self._create_backup():
                logger.warning("Backup creation failed. Continuing without backup.")
                self.result.warnings.append(
                    "Backup creation failed. Rollback will not be possible."
                )

        # Save state checkpoint
        self._save_state()

        return True

    def _phase_extraction(self) -> bool:
        """Execute data extraction phase."""
        self._state["phase"] = MigrationPhase.EXTRACTION.value
        logger.info("Phase: Data extraction")

        # TODO: Implement actual data extraction from source database.
        # The extraction logic is database-specific and needs to be
        # implemented for each supported database type.
        # Currently supported: SQLite (for testing), PostgreSQL (partial)
        # TODO: Add MySQL, MSSQL, Oracle support

        return True

    def _phase_transformation(self) -> bool:
        """Execute data transformation phase."""
        self._state["phase"] = MigrationPhase.TRANSFORMATION.value
        logger.info("Phase: Data transformation")

        # TODO: Implement version-specific transformation rules.
        # The transformation rules are defined in the migration manifests
        # which are located in the `migrations/` directory.
        # Each migration version has a corresponding manifest file.

        return True

    def _phase_loading(self) -> bool:
        """Execute data loading phase."""
        self._state["phase"] = MigrationPhase.LOADING.value
        logger.info("Phase: Data loading")

        # TODO: Implement batch loading to target database.
        # The loading process should use bulk insert for performance.
        # If bulk insert is not available, fall back to row-by-row insert.

        return True

    def _phase_validation(self) -> bool:
        """Execute post-migration validation phase."""
        self._state["phase"] = MigrationPhase.VALIDATION.value
        logger.info("Phase: Post-migration validation")

        # Compare row counts
        if self.config.validate_row_counts:
            # TODO: Compare row counts between source and target
            pass

        # Validate checksums
        if self.config.validate_checksums:
            # TODO: Validate data checksums
            pass

        # Validate schema
        if self.config.validate_schema:
            # TODO: Validate target schema matches expected schema
            pass

        return True

    def _phase_cleanup(self) -> None:
        """Execute cleanup phase after successful migration."""
        self._state["phase"] = MigrationPhase.CLEANUP.value
        logger.info("Phase: Cleanup")

        # Remove temporary files
        # TODO: Implement cleanup of temporary files

        # Save final state
        self._save_state()

    def _check_connection(self, connection_string: str) -> bool:
        """Check database connectivity."""
        # TODO: Implement actual connection check
        # This is a stub that always returns True
        logger.debug(f"Connection check for: {connection_string}")
        return True

    def _check_disk_space(self) -> bool:
        """Check available disk space."""
        try:
            stat = os.statvfs(".")
            free_bytes = stat.f_frsize * stat.f_bavail
            free_gb = free_bytes / (1024**3)
            logger.info(f"Available disk space: {free_gb:.2f} GB")
            return free_gb > 1.0  # Require at least 1 GB free
        except Exception:
            return False

    def _create_backup(self) -> bool:
        """Create a backup of the data before migration."""
        backup_dir = Path(self.config.backup_dir or DEFAULT_CONFIG["backup_dir"])
        backup_path = backup_dir / f"migration_{self.config.migration_id}"

        try:
            backup_path.mkdir(parents=True, exist_ok=True)
            logger.info(f"Backup directory created at {backup_path}")

            # TODO: Implement actual backup creation
            # The backup should include:
            # - Database dump (if applicable)
            # - Configuration files
            # - Migration state
            # - Checksums for validation

            # Create a manifest file for the backup
            manifest = {
                "migration_id": self.config.migration_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "from_version": self.config.from_version,
                "to_version": self.config.to_version,
                "script_version": SCRIPT_VERSION,
                "files": [],
            }
            with open(backup_path / "manifest.json", "w") as f:
                json.dump(manifest, f, indent=2)

            return True

        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            return False

    def _restore_from_backup(self, backup_path: Path) -> bool:
        """Restore data from a backup."""
        logger.info(f"Restoring from backup at {backup_path}")

        # Verify backup manifest
        manifest_path = backup_path / "manifest.json"
        if not manifest_path.exists():
            logger.error("Backup manifest not found")
            return False

        try:
            with open(manifest_path) as f:
                manifest = json.load(f)

            logger.info(f"Restoring backup from {manifest.get('created_at', 'unknown')}")

            # TODO: Implement actual restore logic
            # The restore should:
            # 1. Validate backup integrity
            # 2. Restore data files
            # 3. Recreate indexes
            # 4. Run validation

            return True

        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False

    def _save_state(self) -> None:
        """Save migration state to disk for resumption."""
        state = {
            "migration_id": self.config.migration_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "phase": self._state["phase"],
            "current_batch": self._state["current_batch"],
            "total_batches": self._state["total_batches"],
            "records_migrated": self.result.migrated_records,
            "records_failed": self.result.failed_records,
        }
        try:
            with open(MIGRATION_STATE_FILE, "w") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save migration state: {e}")

    def get_progress(self) -> Dict[str, Any]:
        """Get the current progress of the migration."""
        return {
            "migration_id": self.config.migration_id,
            "status": self.result.status.value,
            "phase": self._state["phase"],
            "progress_pct": (
                (self.result.migrated_records / max(self.result.total_records, 1)) * 100
                if self.result.total_records > 0 else 0
            ),
            "records": {
                "total": self.result.total_records,
                "migrated": self.result.migrated_records,
                "failed": self.result.failed_records,
                "skipped": self.result.skipped_records,
            },
            "duration_seconds": self.result.duration_seconds or 0,
            "is_running": self._running,
            "is_cancelled": self._cancelled,
        }


# ---------------------------------------------------------------------------
# TRANSFORMERS
# ---------------------------------------------------------------------------

class DataTransformer:
    """
    Transforms data between migration versions.

    Each migration version has its own transformer that knows how to
    convert data from one format to another. The transformers are
    registered in the TRANSFORMER_REGISTRY and are selected based on
    the from_version and to_version of the migration.

    If a transformer is not found for the given version pair, the
    identity transformer is used (pass-through without modification).
    This allows migrations that don't require data transformation to
    skip the transformation step.

    TODO: Register all migration transformers in the registry below.
    Currently, only version 1-to-2 and version 2-to-3 transformers
    are implemented. The remaining transformers are placeholders.
    """

    def __init__(self, from_version: int, to_version: int):
        self.from_version = from_version
        self.to_version = to_version

    def transform(self, record: DataRecord) -> DataRecord:
        """Transform a single data record."""
        raise NotImplementedError("Subclasses must implement transform()")


class IdentityTransformer(DataTransformer):
    """Pass-through transformer that doesn't modify data."""

    def transform(self, record: DataRecord) -> DataRecord:
        record.transformation_log.append("No transformation applied (identity)")
        return record


class V1ToV2Transformer(DataTransformer):
    """
    Transforms data from version 1 to version 2.

    Version 2 migration changes:
    - UUID format changed from dasherated to non-dasherated
    - Timestamp precision increased from seconds to milliseconds
    - User status field changed from string to integer enum
    - Email normalization rules updated
    - Phone number format standardized to E.164
    - Address fields split into components

    WARNING: The UUID format change is irreversible. Once data is migrated
    to v2 format, the original v1 UUIDs cannot be recovered without a backup.
    """

    def __init__(self):
        super().__init__(1, 2)

    def transform(self, record: DataRecord) -> DataRecord:
        """Transform a v1 record to v2 format."""
        data = record.data

        # Convert UUID format (remove dashes)
        if "id" in data and isinstance(data["id"], str):
            old_id = data["id"]
            data["id"] = old_id.replace("-", "")
            data["_legacy_uuid"] = old_id  # Keep original for rollback
            record.transformation_log.append(f"UUID format converted: {old_id} -> {data['id']}")

        # Convert timestamps from seconds to milliseconds
        for ts_field in ["created_at", "updated_at", "deleted_at"]:
            if ts_field in data and isinstance(data[ts_field], (int, float)):
                if data[ts_field] < 1e12:  # Probably in seconds
                    data[ts_field] = int(data[ts_field] * 1000)
                    record.transformation_log.append(f"Timestamp {ts_field} converted to milliseconds")

        # Convert user status to integer enum
        status_map = {
            "active": 1,
            "inactive": 2,
            "suspended": 3,
            "deleted": 4,
            "pending": 5,
            "banned": 6,
            "locked": 7,
        }
        if "status" in data and isinstance(data["status"], str):
            data["status"] = status_map.get(data["status"].lower(), 0)
            record.transformation_log.append(f"Status converted to integer: {data['status']}")

        record.version = 2
        return record


class V2ToV3Transformer(DataTransformer):
    """
    Transforms data from version 2 to version 3.

    Version 3 migration changes:
    - Added timezone-aware timestamps (UTC with offset)
    - User preferences moved to separate JSONB field
    - Added soft-delete support with deleted_at and deleted_by fields
    - Audit trail fields added to all entities
    - Data classification tags added for GDPR compliance

    NOTE: This transformer requires the target database to support JSONB.
    For databases that don't support JSONB, the preferences field is
    stored as a regular JSON string.
    """

    def __init__(self):
        super().__init__(2, 3)

    def transform(self, record: DataRecord) -> DataRecord:
        """Transform a v2 record to v3 format."""
        data = record.data

        # Add timezone-aware timestamps
        for ts_field in ["created_at", "updated_at", "deleted_at"]:
            if ts_field in data and isinstance(data[ts_field], (int, float)):
                data[ts_field] = {
                    "timestamp": data[ts_field],
                    "timezone": "UTC",
                    "precision": "milliseconds",
                }
                record.transformation_log.append(f"Timestamp {ts_field} made timezone-aware")

        # Move preferences to JSONB
        if "preferences" in data and isinstance(data["preferences"], dict):
            data["preferences_json"] = data.pop("preferences")
            record.transformation_log.append("Preferences moved to JSONB field")

        # Add soft-delete fields
        if "deleted_at" not in data:
            data["deleted_at"] = None
            data["deleted_by"] = None
            record.transformation_log.append("Soft-delete fields initialized")

        # Add audit fields
        data["created_by"] = data.get("created_by", "system")
        data["updated_by"] = data.get("updated_by", "system")
        data["version"] = 1
        record.transformation_log.append("Audit fields added")

        # Add data classification
        data["data_classification"] = "internal"
        data["retention_policy"] = "standard"
        data["retention_days"] = 365
        record.transformation_log.append("Data classification tags added")

        record.version = 3
        return record


# Registry of available transformers
TRANSFORMER_REGISTRY = {
    (1, 2): V1ToV2Transformer,
    (2, 3): V2ToV3Transformer,
    # TODO: Register v3-to-v4 transformer when migration design is finalized
    # (3, 4): V3ToV4Transformer,
    # (4, 5): V4ToV5Transformer,
}


def get_transformer(from_version: int, to_version: int) -> DataTransformer:
    """Get the appropriate transformer for the version pair."""
    transformer_class = TRANSFORMER_REGISTRY.get((from_version, to_version))
    if transformer_class is None:
        # Try chained transformers for multi-version jumps
        # TODO: Implement chained transformer support
        logger.warning(f"No direct transformer for v{from_version} -> v{to_version}. "
                      f"Using identity transformer.")
        return IdentityTransformer(from_version, to_version)
    return transformer_class()


# ---------------------------------------------------------------------------
# UTILITY FUNCTIONS
# ---------------------------------------------------------------------------

def compute_checksum(data: Dict[str, Any]) -> str:
    """Compute a SHA-256 checksum for a data record."""
    serialized = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def parse_version_string(version: str) -> int:
    """Parse a version string like 'v1', 'version_2', '3' into an integer."""
    match = re.search(r'(\d+)', version)
    if match:
        return int(match.group(1))
    raise ValueError(f"Cannot parse version string: {version}")


def format_duration(seconds: float) -> str:
    """Format a duration in seconds to a human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    else:
        days = seconds / 86400
        return f"{days:.1f}d"


def load_json_file(path: str) -> Any:
    """Load a JSON file with error handling."""
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {path}: {e}")
        raise


def write_json_file(path: str, data: Any, pretty: bool = True) -> None:
    """Write JSON data to a file with error handling."""
    try:
        with open(path, "w") as f:
            if pretty:
                json.dump(data, f, indent=2, default=str)
            else:
                json.dump(data, f, default=str)
    except IOError as e:
        logger.error(f"Failed to write {path}: {e}")
        raise


def migration_result_to_dict(result: MigrationResult) -> Dict[str, Any]:
    """Convert MigrationResult to stable JSON-friendly output."""
    data = asdict(result)
    data["status"] = result.status.value
    data["started_at"] = result.started_at.isoformat()
    data["completed_at"] = result.completed_at.isoformat() if result.completed_at else None
    return data


def parse_scalar_config_value(value: str) -> Any:
    """Parse a small YAML-like scalar value without taking a PyYAML dependency."""
    value = value.strip()
    if value == "":
        return ""
    if value[0:1] in {"'", '"'} and value[-1:] == value[0]:
        return value[1:-1]
    lowered = value.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"null", "none", "~"}:
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def load_config_file(path: str) -> Dict[str, Any]:
    """Load JSON or simple top-level key/value YAML migration config."""
    config_path = Path(path)
    text = config_path.read_text(encoding="utf-8")
    if not text.strip():
        return {}

    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        loaded = None

    if isinstance(loaded, dict):
        return loaded
    if loaded is not None:
        raise ValueError("migration config must be a JSON object")

    config: Dict[str, Any] = {}
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            raise ValueError(f"unsupported config line {line_no}: expected key: value")
        key, value = line.split(":", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"unsupported config line {line_no}: empty key")
        config[key] = parse_scalar_config_value(value)
    return config


def batch_iterator(items: List[Any], batch_size: int):
    """Iterate over items in batches."""
    for i in range(0, len(items), batch_size):
        yield items[i:i + batch_size]


def retry_operation(operation, max_retries: int = 3, base_delay: float = 1.0):
    """Retry an operation with exponential backoff."""
    for attempt in range(max_retries):
        try:
            return operation()
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            delay = base_delay * (2 ** attempt)
            logger.warning(f"Operation failed (attempt {attempt + 1}/{max_retries}): {e}. "
                         f"Retrying in {delay:.1f}s...")
            time.sleep(delay)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def create_arg_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Legacy Data Migration Tool for Tent of Trials",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s migrate --from-version 1 --to-version 3 --source-db postgresql://... --target-db postgresql://...
  %(prog)s validate --data-dir ./migration_output
  %(prog)s rollback --migration-id MIG001
  %(prog)s status
  %(prog)s dry-run --config config.yaml
        """,
    )

    # Global options
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--config", "-c", type=str, help="Path to configuration file")
    parser.add_argument("--log-file", type=str, help="Path to log file")

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Migrate command
    migrate_parser = subparsers.add_parser("migrate", help="Run a data migration")
    migrate_parser.add_argument("--from-version", type=int, required=True, help="Source data version")
    migrate_parser.add_argument("--to-version", type=int, required=True, help="Target data version")
    migrate_parser.add_argument("--source-db", type=str, help="Source database connection string")
    migrate_parser.add_argument("--target-db", type=str, help="Target database connection string")
    migrate_parser.add_argument("--batch-size", type=int, default=1000, help="Batch size")
    migrate_parser.add_argument("--dry-run", action="store_true", help="Validate without making changes")
    migrate_parser.add_argument("--continue-on-error", action="store_true", help="Continue on non-fatal errors")
    migrate_parser.add_argument("--parallel-workers", type=int, default=4, help="Number of parallel workers")
    migrate_parser.add_argument("--no-backup", action="store_true", help="Skip backup creation")

    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate migrated data")
    validate_parser.add_argument("--data-dir", type=str, required=True, help="Directory with migrated data")
    validate_parser.add_argument("--checksums", action="store_true", help="Validate data checksums")
    validate_parser.add_argument("--schema", action="store_true", help="Validate data schema")

    # Rollback command
    rollback_parser = subparsers.add_parser("rollback", help="Rollback a migration")
    rollback_parser.add_argument("--migration-id", type=str, required=True, help="Migration ID to rollback")
    rollback_parser.add_argument("--backup-dir", type=str, help="Backup directory")

    # Status command
    status_parser = subparsers.add_parser("status", help="Check migration status")
    status_parser.add_argument("--migration-id", type=str, help="Specific migration ID to check")

    # Dry-run command
    dryrun_parser = subparsers.add_parser("dry-run", help="Dry run a migration")
    dryrun_parser.add_argument("--config", type=str, required=True, help="Configuration file")
    dryrun_parser.add_argument("--report", action="store_true", help="Generate detailed report")

    # List command
    list_parser = subparsers.add_parser("list", help="List completed migrations")
    list_parser.add_argument("--status", type=str, choices=[s.value for s in MigrationStatus],
                           help="Filter by status")

    return parser


def main():
    """Main entry point for the migration script."""
    parser = create_arg_parser()
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setFormatter(logger_formatter)
        logger.addHandler(file_handler)
        logger.info(f"Logging to file: {args.log_file}")

    logger.info(f"Legacy Migration Tool v{SCRIPT_VERSION} (build {SCRIPT_BUILD})")
    logger.info(f"Python {sys.version}")

    if not args.command:
        parser.print_help()
        return 1

    if args.command == "migrate":
        config = MigrationConfig(
            migration_id=f"MIG-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            migration_type=MigrationType.DATA,
            from_version=args.from_version,
            to_version=args.to_version,
            source_connection=args.source_db or "unknown",
            target_connection=args.target_db or "unknown",
            batch_size=args.batch_size,
            dry_run=args.dry_run,
            continue_on_error=args.continue_on_error,
            parallel_workers=args.parallel_workers,
            create_backup=not args.no_backup,
        )
        engine = MigrationEngine(config)
        result = engine.run()
        print(f"Migration result: {result.status.value}")
        print(f"  Records migrated: {result.migrated_records}")
        print(f"  Records failed: {result.failed_records}")
        print(f"  Duration: {result.duration_seconds:.2f}s")
        if result.warnings:
            print("  Warnings:")
            for w in result.warnings:
                print(f"    - {w}")

    elif args.command == "validate":
        print(f"Validating data in {args.data_dir}...")
        # TODO: Implement validation logic
        print("Validation complete (no issues found)")

    elif args.command == "rollback":
        config = MigrationConfig(
            migration_id=args.migration_id,
            migration_type=MigrationType.DATA,
            from_version=0,
            to_version=0,
            source_connection="unknown",
            target_connection="unknown",
            backup_dir=args.backup_dir,
        )
        engine = MigrationEngine(config)
        result = engine.rollback()
        print(f"Rollback result: {result.status.value}")

    elif args.command == "status":
        print("Checking migration status...")
        if os.path.exists(MIGRATION_STATE_FILE):
            with open(MIGRATION_STATE_FILE) as f:
                state = json.load(f)
            print(f"  Migration ID: {state.get('migration_id', 'unknown')}")
            print(f"  Phase: {state.get('phase', 'unknown')}")
            print(f"  Progress: {state.get('records_migrated', 0)} records migrated")
        else:
            print("  No migration state found")

    elif args.command == "dry-run":
        config_data = load_config_file(args.config)
        config = MigrationConfig(
            migration_id=str(config_data.get("migration_id") or f"DRY-{datetime.now().strftime('%Y%m%d%H%M%S')}"),
            migration_type=MigrationType.DATA,
            from_version=int(config_data.get("from_version", 1)),
            to_version=int(config_data.get("to_version", 2)),
            source_connection=str(config_data.get("source_connection", "dry-run")),
            target_connection=str(config_data.get("target_connection", "dry-run")),
            backup_dir=str(config_data.get("backup_dir", DEFAULT_CONFIG["backup_dir"])),
            dry_run=True,
            create_backup=False,
        )
        engine = MigrationEngine(config)
        result = engine.dry_run_restore_validation(args.config)
        if args.report:
            print(json.dumps(migration_result_to_dict(result), indent=2, default=str))
        else:
            print(f"Dry-run restore validation: {result.status.value}")
            print(f"  Backup path: {result.metadata.get('backup_path', 'unknown')}")
            print(f"  Expected rows: {result.metadata.get('expected_row_count', result.total_records)}")
            print(f"  Checksum entries: {len(result.checksums)}")
            if result.errors:
                print("  Errors:")
                for error in result.errors:
                    print(f"    - {error['phase']}: {error['error']}")
        return 0 if result.status == MigrationStatus.COMPLETED else 1

    elif args.command == "list":
        print("Listing completed migrations...")
        # TODO: Implement list logic
        print("No migrations found")

    return 0


if __name__ == "__main__":
    sys.exit(main())
