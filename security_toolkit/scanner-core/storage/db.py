"""SQLite-backed metadata storage (spec §39-§42): scanner.sqlite holds
Scan/Task/Target/Issue metadata for search; the actual raw tool output and
full result JSON live on the filesystem (spec §41-§42) -- this file only
ever stores what the API needs to answer list/status queries quickly.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from storage.models import Finding, ScanRecord, ScanTarget, Severity, TaskRecord, TaskStatus, Technology

_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    scope_host TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES targets(id),
    status TEXT NOT NULL DEFAULT 'pending',
    start_time TEXT NOT NULL DEFAULT '',
    end_time TEXT NOT NULL DEFAULT '',
    result_dir TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id),
    module TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    start_time TEXT NOT NULL DEFAULT '',
    end_time TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    result_file TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tasks_scan ON tasks(scan_id);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL DEFAULT '',
    task_id TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    scanner TEXT NOT NULL DEFAULT '',
    finding TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'info',
    host TEXT NOT NULL DEFAULT '',
    port INTEGER,
    protocol TEXT NOT NULL DEFAULT '',
    service TEXT NOT NULL DEFAULT '',
    technology TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL DEFAULT '',
    raw_ref TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);

CREATE TABLE IF NOT EXISTS technologies (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL DEFAULT '',
    product TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    port INTEGER,
    evidence TEXT NOT NULL DEFAULT '',
    source_scanner TEXT NOT NULL DEFAULT '',
    cpe TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_technologies_scan ON technologies(scan_id);
"""


class ScannerDB:
    """spec review finding (2026-09-05): the Orchestrator's execute_task()
    runs inside FastAPI BackgroundTasks, which dispatches sync callables to
    a thread pool -- so multiple scans/tasks running concurrently can each
    call into this class's methods from a different OS thread, all sharing
    this one sqlite3.Connection (check_same_thread=False only disables the
    same-thread check; it does not make concurrent multi-statement use of
    ONE connection safe). Without serialization, concurrent writers can
    still race on WAL and surface as sqlite3.OperationalError('database is
    locked') under real load. _lock below is the single choke point every
    public method acquires around its execute()+commit() calls."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # RLock, not Lock: get_scan()/list_scans() call get_target() internally
        # while already holding the lock, from the same thread.
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- targets ----------------------------------------------------------
    def save_target(self, target: ScanTarget) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO targets (id, value, scope_host) VALUES (?, ?, ?)",
                (target.id, target.value, target.scope_host),
            )
            self._conn.commit()

    def get_target(self, target_id: str) -> ScanTarget | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, value, scope_host FROM targets WHERE id = ?", (target_id,)
            ).fetchone()
            return ScanTarget(id=row["id"], value=row["value"], scope_host=row["scope_host"]) if row else None

    def get_target_by_value(self, value: str) -> ScanTarget | None:
        with self._lock:
            row = self._conn.execute("SELECT id, value, scope_host FROM targets WHERE value = ?", (value,)).fetchone()
            return ScanTarget(id=row["id"], value=row["value"], scope_host=row["scope_host"]) if row else None

    def list_targets(self) -> list[ScanTarget]:
        with self._lock:
            rows = self._conn.execute("SELECT id, value, scope_host FROM targets ORDER BY created_at DESC").fetchall()
            return [ScanTarget(id=r["id"], value=r["value"], scope_host=r["scope_host"]) for r in rows]

    # -- scans --------------------------------------------------------------
    def save_scan(self, scan: ScanRecord) -> None:
        with self._lock:
            self.save_target(scan.target)
            self._conn.execute(
                """INSERT OR REPLACE INTO scans (id, target_id, status, start_time, end_time, result_dir)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (scan.id, scan.target.id, scan.status.value, scan.start_time, scan.end_time, scan.result_dir),
            )
            self._conn.commit()

    def update_scan_status(self, scan_id: str, status: TaskStatus, *, end_time: str = "") -> None:
        # spec review finding (2026-09-06): end_time="" used to mean "leave
        # whatever was there before" -- fine as long as a scan only ever
        # moved forward through statuses once, but that's no longer true
        # (a scan reopened from completed/failed back to running, see
        # Orchestrator.create_task(), needs its stale end_time actually
        # cleared, not left showing a finish time while status says running).
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET status = ?, end_time = ? WHERE id = ?", (status.value, end_time, scan_id)
            )
            self._conn.commit()

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, target_id, status, start_time, end_time, result_dir FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            if row is None:
                return None
            target = self.get_target(row["target_id"])
            return ScanRecord(
                id=row["id"], target=target, status=TaskStatus(row["status"]),
                start_time=row["start_time"], end_time=row["end_time"], result_dir=row["result_dir"],
            )

    def list_scans(self, *, target_id: str | None = None) -> list[ScanRecord]:
        with self._lock:
            if target_id:
                rows = self._conn.execute(
                    "SELECT id FROM scans WHERE target_id = ? ORDER BY created_at DESC", (target_id,)
                ).fetchall()
            else:
                rows = self._conn.execute("SELECT id FROM scans ORDER BY created_at DESC").fetchall()
            return [self.get_scan(r["id"]) for r in rows]

    # -- tasks --------------------------------------------------------------
    def save_task(self, task: TaskRecord) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO tasks (id, scan_id, module, status, start_time, end_time, error, result_file)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (task.id, task.scan_id, task.module, task.status.value, task.start_time,
                 task.end_time, task.error, task.result_file),
            )
            self._conn.commit()

    def update_task_status(
        self, task_id: str, status: TaskStatus, *, end_time: str = "", error: str = "", result_file: str = ""
    ) -> None:
        with self._lock:
            self._conn.execute(
                """UPDATE tasks SET status = ?,
                   end_time = COALESCE(NULLIF(?, ''), end_time),
                   error = COALESCE(NULLIF(?, ''), error),
                   result_file = COALESCE(NULLIF(?, ''), result_file)
                   WHERE id = ?""",
                (status.value, end_time, error, result_file, task_id),
            )
            self._conn.commit()

    def get_task(self, task_id: str) -> TaskRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, scan_id, module, status, start_time, end_time, error, result_file "
                "FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()
            return TaskRecord(**self._task_row_to_kwargs(row)) if row else None

    def list_tasks_for_scan(self, scan_id: str) -> list[TaskRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, scan_id, module, status, start_time, end_time, error, result_file "
                "FROM tasks WHERE scan_id = ? ORDER BY start_time ASC", (scan_id,)
            ).fetchall()
            return [TaskRecord(**self._task_row_to_kwargs(r)) for r in rows]

    @staticmethod
    def _task_row_to_kwargs(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "scan_id": row["scan_id"], "module": row["module"],
            "status": TaskStatus(row["status"]), "start_time": row["start_time"], "end_time": row["end_time"],
            "error": row["error"], "result_file": row["result_file"],
        }

    # -- findings (Issues) ----------------------------------------------------
    def save_finding(self, finding: Finding) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO findings
                   (id, scan_id, task_id, target, scanner, finding, severity, host, port,
                    protocol, service, technology, evidence, timestamp, raw_ref)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (finding.id, finding.scan_id, finding.task_id, finding.target, finding.scanner,
                 finding.finding, finding.severity.value, finding.host, finding.port, finding.protocol,
                 finding.service, finding.technology, finding.evidence, finding.timestamp, finding.raw_ref),
            )
            self._conn.commit()

    def list_findings(self, *, scan_id: str | None = None) -> list[Finding]:
        with self._lock:
            if scan_id:
                rows = self._conn.execute(
                    "SELECT * FROM findings WHERE scan_id = ? ORDER BY timestamp ASC", (scan_id,)
                ).fetchall()
            else:
                rows = self._conn.execute("SELECT * FROM findings ORDER BY timestamp ASC").fetchall()
            return [
                Finding(
                    id=r["id"], scan_id=r["scan_id"], task_id=r["task_id"], target=r["target"], scanner=r["scanner"],
                    finding=r["finding"], severity=Severity(r["severity"]), host=r["host"], port=r["port"],
                    protocol=r["protocol"], service=r["service"], technology=r["technology"],
                    evidence=r["evidence"], timestamp=r["timestamp"], raw_ref=r["raw_ref"],
                )
                for r in rows
            ]

    # -- technologies (spec §16 Technology Detection) ---------------------------
    def save_technology(self, tech: Technology) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO technologies
                   (id, scan_id, product, version, category, host, port, evidence, source_scanner, cpe)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (tech.id, tech.scan_id, tech.product, tech.version, tech.category, tech.host, tech.port,
                 tech.evidence, tech.source_scanner, json.dumps(tech.cpe, ensure_ascii=False)),
            )
            self._conn.commit()

    def list_technologies(self, *, scan_id: str | None = None) -> list[Technology]:
        with self._lock:
            if scan_id:
                rows = self._conn.execute("SELECT * FROM technologies WHERE scan_id = ?", (scan_id,)).fetchall()
            else:
                rows = self._conn.execute("SELECT * FROM technologies").fetchall()
            return [
                Technology(
                    id=r["id"], scan_id=r["scan_id"], product=r["product"], version=r["version"],
                    category=r["category"], host=r["host"], port=r["port"], evidence=r["evidence"],
                    source_scanner=r["source_scanner"], cpe=json.loads(r["cpe"]),
                )
                for r in rows
            ]
