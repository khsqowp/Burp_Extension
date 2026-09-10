"""SQLite-backed persistent storage for the Proxy · HTTP History list.

Per the Chromium 자동 HTTP History 기능명세서: History isn't just an
in-memory list any more -- every captured record (a completed response OR
an "응답 없음" failure) gets written to a local SQLite database in the
user's own per-account app-data folder, survives a normal or crashed exit,
and is capped at a retention limit (oldest-first eviction) so storage can't
grow unbounded forever.

A record's durable `seq` (the number shown in the "#" column) is assigned
here, by SQLite's own AUTOINCREMENT, not by whatever transient counter the
mitmproxy addon thread happened to be using -- that's what keeps restored
rows and newly-captured rows from ever colliding on the same number across
a restart (AUTOINCREMENT never reuses an id, even after old rows are
evicted).
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import sqlite3
import sys
import time
from dataclasses import asdict
from pathlib import Path

import app_logging
from models import Finding, FlowRecord

_logger = app_logging.get_logger("history_store")

DEFAULT_MAX_RECORDS = 10_000
DEFAULT_MAX_BYTES = 500 * 1024 * 1024  # 500MB, combined stored request+response body size

_SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    method TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    path TEXT NOT NULL,
    url TEXT NOT NULL,
    status INTEGER,
    req_headers TEXT NOT NULL,
    req_body TEXT NOT NULL,
    resp_headers TEXT NOT NULL,
    resp_body TEXT NOT NULL,
    mime TEXT NOT NULL DEFAULT '',
    content_length INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    findings_json TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL DEFAULT 'legacy_unknown',
    scheme TEXT NOT NULL DEFAULT '',
    has_query INTEGER NOT NULL DEFAULT 0,
    file_extension TEXT NOT NULL DEFAULT '',
    started_at REAL,
    duration_ms REAL,
    has_findings INTEGER NOT NULL DEFAULT 0
);
"""

# spec §10: 필터용 메타데이터 컬럼 -- 기존 DB에는 ALTER TABLE로 추가하고,
# source가 없던 과거 행은 'legacy_unknown'으로 남는다 (새로 추측해서 채우지
# 않음). (컬럼명, DDL 타입/기본값) 튜플로 유지해 _migrate_schema가 그대로
# 재사용한다.
_NEW_COLUMNS: list[tuple[str, str]] = [
    ("source", "TEXT NOT NULL DEFAULT 'legacy_unknown'"),
    ("scheme", "TEXT NOT NULL DEFAULT ''"),
    ("has_query", "INTEGER NOT NULL DEFAULT 0"),
    ("file_extension", "TEXT NOT NULL DEFAULT ''"),
    ("started_at", "REAL"),
    ("duration_ms", "REAL"),
    ("has_findings", "INTEGER NOT NULL DEFAULT 0"),
]


def _existing_columns(conn: sqlite3.Connection) -> set[str]:
    return {row[1] for row in conn.execute("PRAGMA table_info(history)").fetchall()}


def _needs_migration(conn: sqlite3.Connection) -> bool:
    existing = _existing_columns(conn)
    return any(name not in existing for name, _ in _NEW_COLUMNS)


def _migrate_schema(conn: sqlite3.Connection) -> None:
    existing = _existing_columns(conn)
    missing = [(name, decl) for name, decl in _NEW_COLUMNS if name not in existing]
    if not missing:
        return
    for name, decl in missing:
        conn.execute(f"ALTER TABLE history ADD COLUMN {name} {decl}")
    conn.commit()


def default_db_path() -> Path:
    """%LOCALAPPDATA%\\ProxyScanner\\history\\history.sqlite3 (spec: 단일 EXE
    휴대용 배포 §7). One-time migration: an earlier build kept this at
    %LOCALAPPDATA%\\proxy_scanner\\history.sqlite3 (lowercase, no history\\
    subfolder) -- if that old file exists and the new location doesn't yet,
    move it over instead of silently starting an empty History."""
    if platform.system() == "Windows":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = str(Path.home() / ".local" / "share")
    new_path = Path(base) / "ProxyScanner" / "history" / "history.sqlite3"
    old_path = Path(base) / "proxy_scanner" / "history.sqlite3"
    if old_path.is_file() and not new_path.is_file():
        try:
            new_path.parent.mkdir(parents=True, exist_ok=True)
            old_path.replace(new_path)
        except OSError:
            # fall through -- HistoryStore.__init__ will just create a fresh db at new_path
            app_logging.log_exception(_logger, "tool_failed", "레거시 History DB 이전 실패", sys.exc_info())
    return new_path


class HistoryStore:
    def __init__(
        self, path: Path | None = None,
        max_records: int = DEFAULT_MAX_RECORDS, max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        self.path = path or default_db_path()
        self.max_records = max_records
        self.max_bytes = max_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.corrupted_backup: Path | None = None
        self.premigration_backup: Path | None = None
        self._backup_before_migration_if_needed()
        self._conn = self._open()
        # spec §11 성능 검증 finding: _enforce_retention() used to run a full
        # SELECT COUNT(*) + SUM(LENGTH(...)) table scan on EVERY single
        # add() -- fine at first, but with req_body/resp_body growing the
        # table over a session, this made every insert progressively slower
        # (measured: ~5.7ms/insert average, 57s total for 10,000 inserts in
        # a single session -- pure O(n^2) accumulation, not a one-time cost).
        # Paying for one real scan here at startup and then tracking the
        # running totals in Python turns every insert back into O(1).
        self._cached_count, self._cached_total_bytes = self._conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(req_body) + LENGTH(resp_body)), 0) FROM history"
        ).fetchone()

    def _backup_before_migration_if_needed(self) -> None:
        """spec §10: 마이그레이션 전 백업을 만들고 실패 시 기존 DB를
        보존한다. Only copies (never moves) the file, and only when the
        existing DB is actually missing one of the new columns -- a brand
        new DB is created straight from the final _SCHEMA and never needs
        this at all."""
        if not self.path.is_file():
            return
        try:
            probe = sqlite3.connect(str(self.path))
            try:
                if not _needs_migration(probe):
                    return
            finally:
                probe.close()
        except sqlite3.DatabaseError:
            return  # corrupted -- _open()'s own recovery path handles this, not migration
        backup = self.path.with_name(self.path.name + f".premigration-{int(time.time())}.bak")
        try:
            shutil.copy2(str(self.path), str(backup))
            self.premigration_backup = backup
            app_logging.log_event(
                _logger, "INFO", "history_migration_backup_created", "History DB 마이그레이션 전 백업 생성",
                backup_path=str(backup),
            )
        except OSError:
            app_logging.log_exception(_logger, "tool_failed", "History DB 마이그레이션 전 백업 실패", sys.exc_info())

    def _new_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), check_same_thread=False)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(_SCHEMA)
        except sqlite3.DatabaseError:
            # Close before propagating -- Windows won't let a later
            # shutil.move() rename this file while a handle to it is still
            # open, so a corrupted-file recovery attempt right after this
            # would otherwise fail too.
            conn.close()
            raise
        try:
            _migrate_schema(conn)
        except sqlite3.DatabaseError:
            # A migration failure must NEVER be treated as "corrupted file"
            # by _open()'s caller -- that path moves the original DB aside
            # and starts empty, which is exactly what spec §10 says never to
            # do here. The pre-migration backup already exists on disk; the
            # DB itself just keeps running without the new columns (History
            # still works, only the new filter metadata is degraded/absent)
            # instead of losing anything.
            app_logging.log_exception(_logger, "tool_failed", "History DB 마이그레이션 실패 -- 기존 DB 보존", sys.exc_info())
        return conn

    def _open(self) -> sqlite3.Connection:
        try:
            conn = self._new_connection()
            conn.execute("SELECT COUNT(*) FROM history")  # sanity probe -- forces a real read
            return conn
        except sqlite3.DatabaseError:
            # Corrupted file -- move it aside (not delete outright, in case
            # the user wants to inspect/recover it later) and start clean so
            # the program keeps working instead of failing to launch.
            backup = self.path.with_name(self.path.name + f".corrupt-{int(time.time())}")
            app_logging.log_exception(_logger, "tool_failed", "History DB 손상 감지 -- 새로 생성", sys.exc_info())
            try:
                shutil.move(str(self.path), str(backup))
                self.corrupted_backup = backup
            except OSError:
                app_logging.log_exception(_logger, "tool_failed", "손상된 History DB 백업 이동 실패", sys.exc_info())
            return self._new_connection()

    def add(self, record: FlowRecord) -> tuple[int, list[int]]:
        """Inserts one record and returns (durable global seq SQLite just
        assigned it, seqs evicted by retention enforcement) -- the caller
        must overwrite record.seq with the first value AND remove the
        evicted seqs from its own in-memory view (Treeview/self.records),
        or the on-screen list silently drifts from what's actually in the
        DB until the next restart (design review finding, spec 4.3)."""
        findings_json = json.dumps([asdict(f) for f in record.findings], ensure_ascii=False)
        cur = self._conn.execute(
            "INSERT INTO history (ts, method, host, port, path, url, status, req_headers, req_body, "
            "resp_headers, resp_body, mime, content_length, error, findings_json, "
            "source, scheme, has_query, file_extension, started_at, duration_ms, has_findings) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                record.ts, record.method, record.host, record.port, record.path, record.url, record.status,
                record.req_headers, record.req_body, record.resp_headers, record.resp_body,
                record.mime, record.content_length, record.error, findings_json,
                record.source, record.scheme, int(record.has_query), record.file_extension,
                record.started_at, record.duration_ms, int(record.has_findings),
            ),
        )
        self._conn.commit()
        seq = cur.lastrowid
        self._cached_count += 1
        self._cached_total_bytes += len(record.req_body) + len(record.resp_body)
        evicted = self._enforce_retention()
        return seq, evicted

    def _enforce_retention(self) -> list[int]:
        """Uses the running self._cached_count/_cached_total_bytes totals
        instead of a fresh SELECT COUNT/SUM scan -- that scan used to run on
        every single add() and got slower as the table grew (O(n) per
        insert = O(n^2) over a session; see the comment in __init__)."""
        evicted: list[int] = []
        while self._cached_count > self.max_records or self._cached_total_bytes > self.max_bytes:
            oldest = self._conn.execute(
                "SELECT seq, LENGTH(req_body) + LENGTH(resp_body) FROM history ORDER BY seq ASC LIMIT 1"
            ).fetchone()
            if oldest is None:
                break
            self._conn.execute("DELETE FROM history WHERE seq = ?", (oldest[0],))
            evicted.append(oldest[0])
            self._cached_count -= 1
            self._cached_total_bytes -= oldest[1]
        if evicted:
            self._conn.commit()
        return evicted

    def load_recent(self, limit: int | None = None) -> list[FlowRecord]:
        limit = self.max_records if limit is None else limit
        has_new_cols = not _needs_migration(self._conn)
        extra_cols = ", source, scheme, has_query, file_extension, started_at, duration_ms, has_findings" if has_new_cols else ""
        rows = self._conn.execute(
            "SELECT seq, ts, method, host, port, path, url, status, req_headers, req_body, "
            "resp_headers, resp_body, mime, content_length, error, findings_json"
            f"{extra_cols} FROM history ORDER BY seq ASC LIMIT ?",
            (limit,),
        ).fetchall()
        records = []
        for r in rows:
            findings = [Finding(**f) for f in json.loads(r[15] or "[]")]
            extra_kwargs = {}
            if has_new_cols:
                extra_kwargs = dict(
                    source=r[16], scheme=r[17], has_query=bool(r[18]), file_extension=r[19],
                    started_at=r[20], duration_ms=r[21], has_findings=bool(r[22]),
                )
            records.append(FlowRecord(
                seq=r[0], ts=r[1], method=r[2], host=r[3], port=r[4], path=r[5], url=r[6], status=r[7],
                req_headers=r[8], req_body=r[9], resp_headers=r[10], resp_body=r[11],
                mime=r[12], content_length=r[13], error=r[14], findings=findings,
                **extra_kwargs,
            ))
        return records

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]

    def clear(self) -> None:
        self._conn.execute("DELETE FROM history")
        self._conn.commit()
        self._conn.execute("VACUUM")
        self._cached_count = 0
        self._cached_total_bytes = 0

    def close(self) -> None:
        self._conn.close()
