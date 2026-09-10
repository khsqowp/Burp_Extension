"""Local diagnostic logging (spec: 개선작업 로그 기능 명세 §5). JSON Lines,
one line per event, written under %LOCALAPPDATA%\\ProxyScanner\\logs\\ --
never the EXE's own folder or E:\\temp\\tools (spec 5.2). Every record goes
through log_redaction.py first; this module never writes HTTP bodies,
credentials, or session tokens by itself, and callers are expected to
pre-redact anything they pass in (see the helpers on FlowRecord-adjacent
call sites for examples).

Usage:
    import app_logging
    SESSION_ID = app_logging.new_session_id()
    app_logging.setup_logging(SESSION_ID)
    logger = app_logging.get_logger("gui")
    app_logging.log_event(logger, "INFO", "app_started", version="1.0.0.0")
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import queue
import subprocess
import sys
import threading
import time
import traceback
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import app_paths
import log_redaction

APP_LOG_PATH = app_paths.LOGS_DIR / "proxy-scanner.log"
MAX_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 5  # + the current file = 6 total, matching spec 5.3
CRASH_RETENTION_DAYS = 30
WORKER_RETENTION_DAYS = 14
MAX_WORKER_LINE_LENGTH = 4000  # spec 5.9: "한 줄 최대 길이를 제한"

_queue: "queue.Queue[logging.LogRecord]" = queue.Queue(-1)
_listener: logging.handlers.QueueListener | None = None
_debug_enabled = False


def new_session_id() -> str:
    return uuid.uuid4().hex[:16]


def new_run_id() -> str:
    return uuid.uuid4().hex[:12]


class _JsonFormatter(logging.Formatter):
    def __init__(self, session_id: str) -> None:
        super().__init__()
        self.session_id = session_id

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "time": datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "session_id": self.session_id,
            "component": record.name,
            "event": getattr(record, "event", record.getMessage()),
            "message": getattr(record, "user_message", ""),
        }
        run_id = getattr(record, "run_id", None)
        if run_id:
            payload["run_id"] = run_id
        thread_name = getattr(record, "log_thread", None)
        if thread_name:
            payload["thread"] = thread_name
        extra_fields = getattr(record, "fields", None)
        if extra_fields:
            payload.update(extra_fields)
        # QueueHandler.prepare() pre-formats exc_info into exc_text and
        # clears exc_info to None before the record crosses the queue (it
        # isn't safely picklable) -- check both, queue path hits exc_text.
        if record.exc_info:
            payload["exception"] = "".join(traceback.format_exception(*record.exc_info))
        elif getattr(record, "exc_text", None):
            payload["exception"] = record.exc_text
        try:
            return json.dumps(payload, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return json.dumps({**payload, "fields": "<unserializable>"}, ensure_ascii=False)


def setup_logging(session_id: str, verbose: bool = False) -> None:
    """Call once at startup. Safe to call more than once (idempotent) --
    later calls just no-op, matching spec 5.11's 'must never break the
    actual diagnostic run' requirement (a logging setup bug should degrade,
    not crash the app)."""
    global _listener, _debug_enabled
    if _listener is not None:
        return
    try:
        app_paths.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            APP_LOG_PATH, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
        )
        file_handler.setFormatter(_JsonFormatter(session_id))
        _listener = logging.handlers.QueueListener(_queue, file_handler, respect_handler_level=True)
        _listener.start()

        root = logging.getLogger("proxy_scanner")
        root.setLevel(logging.DEBUG if verbose else logging.INFO)
        root.handlers.clear()
        queue_handler = logging.handlers.QueueHandler(_queue)
        root.addHandler(queue_handler)
        root.propagate = False
        _debug_enabled = verbose
    except OSError:
        # Logging itself failing must never take the diagnostic run down
        # with it (spec 5.11) -- fall back to a no-op logger silently.
        pass


def set_debug_enabled(enabled: bool) -> None:
    global _debug_enabled
    _debug_enabled = enabled
    logging.getLogger("proxy_scanner").setLevel(logging.DEBUG if enabled else logging.INFO)


def is_debug_enabled() -> bool:
    return _debug_enabled


def shutdown_logging() -> None:
    global _listener
    if _listener is not None:
        try:
            _listener.stop()
        except Exception:  # noqa: BLE001
            pass
        _listener = None


def get_logger(component: str) -> logging.Logger:
    return logging.getLogger(f"proxy_scanner.{component}")


def log_event(
    logger: logging.Logger, level: str, event: str, message: str = "", run_id: str | None = None,
    thread: bool = False, **fields: object,
) -> None:
    """The one function almost everything else in this codebase should call
    instead of logger.info()/error() directly -- keeps the JSON shape
    (event/message/run_id/fields) consistent everywhere."""
    try:
        extra = {"event": event, "user_message": message}
        if run_id:
            extra["run_id"] = run_id
        if thread:
            extra["log_thread"] = threading.current_thread().name
        if fields:
            extra["fields"] = fields
        logger.log(getattr(logging, level.upper(), logging.INFO), event, extra=extra)
    except Exception:  # noqa: BLE001 -- a logging call must never be the thing that crashes a diagnostic run
        try:
            print(f"[logging failed] {level} {event} {message}", file=sys.stderr)
        except Exception:  # noqa: BLE001
            pass


def log_exception(logger: logging.Logger, event: str, message: str, exc_info, **fields: object) -> str:
    """Formats the traceback into a plain string up front instead of
    passing exc_info=... through to the handler -- QueueHandler.prepare()
    (used here for thread-safe file writes) clears exc_info/exc_text before
    the record crosses the queue, so relying on it silently drops every
    traceback. Pre-formatting sidesteps that entirely.

    Every call gets its own error_id (spec 5.8/6#11: an error the user sees
    must show the same error_id that's in the log) -- returned so a caller
    that surfaces this to the user (messagebox, status bar) can display it,
    even for a non-crash-hook failure like a History DB write error."""
    error_id = uuid.uuid4().hex[:8]
    try:
        formatted = "".join(traceback.format_exception(*exc_info)) if exc_info and exc_info[0] else None
        all_fields = dict(fields)
        all_fields["error_id"] = error_id
        if formatted:
            all_fields["exception"] = formatted
        extra = {"event": event, "user_message": message, "fields": all_fields}
        logger.error(event, extra=extra)
    except Exception:  # noqa: BLE001
        pass
    return error_id


# ---------------------------------------------------------------------------
# Crash / uncaught-exception hooks (spec 5.8)
# ---------------------------------------------------------------------------
def _write_crash_log(session_id: str, component: str, exc_type, exc_value, exc_tb) -> str:
    """Writes a standalone crash-YYYYMMDD-HHmmss.log (not rotated -- each
    crash gets its own file so one doesn't overwrite another) and returns a
    short error_id the GUI can show the user (spec: '오류 ID: 5f62b1a8')."""
    error_id = uuid.uuid4().hex[:8]
    try:
        app_paths.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = app_paths.LOGS_DIR / f"crash-{ts}.log"
        text = (
            f"error_id: {error_id}\nsession_id: {session_id}\ncomponent: {component}\n"
            f"time: {datetime.now(timezone.utc).astimezone().isoformat()}\n\n"
            + "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        )
        path.write_text(text, encoding="utf-8")
    except OSError:
        pass
    return error_id


def install_crash_hooks(session_id: str, on_crash=None) -> None:
    """Installs sys.excepthook + threading.excepthook. `on_crash(error_id,
    exc_value)` is called after logging, meant for the GUI to show the
    '오류 ID: ...' dialog -- optional, and any failure inside it is
    swallowed so a broken callback can't turn a crash-reporting path into a
    second crash."""
    logger = get_logger("crash")

    def _handle(component: str, exc_type, exc_value, exc_tb) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        error_id = _write_crash_log(session_id, component, exc_type, exc_value, exc_tb)
        log_exception(
            logger, "uncaught_exception", f"{component}에서 처리되지 않은 예외 발생",
            (exc_type, exc_value, exc_tb), error_id=error_id, component=component,
        )
        if on_crash is not None:
            try:
                on_crash(error_id, exc_value)
            except Exception:  # noqa: BLE001
                pass

    def _sys_hook(exc_type, exc_value, exc_tb):
        _handle("main-thread", exc_type, exc_value, exc_tb)

    def _thread_hook(args: threading.ExceptHookArgs) -> None:
        _handle(f"thread:{args.thread.name if args.thread else '?'}", args.exc_type, args.exc_value, args.exc_traceback)

    sys.excepthook = _sys_hook
    threading.excepthook = _thread_hook


def tk_report_callback_exception(session_id: str, on_crash=None):
    """Returns a function assignable to `tk.Tk().report_callback_exception`
    -- Tkinter swallows exceptions raised inside widget callbacks by
    default and only prints them to stderr, which is otherwise invisible
    in a --windowed build with no console."""
    logger = get_logger("gui")

    def _handler(exc_type, exc_value, exc_tb) -> None:
        error_id = _write_crash_log(session_id, "tkinter-callback", exc_type, exc_value, exc_tb)
        log_exception(
            logger, "uncaught_exception", "Tkinter 콜백에서 처리되지 않은 예외 발생",
            (exc_type, exc_value, exc_tb), error_id=error_id, component="tkinter-callback",
        )
        if on_crash is not None:
            try:
                on_crash(error_id, exc_value)
            except Exception:  # noqa: BLE001
                pass

    return _handler


# ---------------------------------------------------------------------------
# Per-run worker (subprocess) output log (spec 5.9)
# ---------------------------------------------------------------------------
def new_worker_log_path(run_id: str) -> Path:
    """One file per tool run, named by its run_id -- the GUI process (which
    already reads every line of a tool subprocess's stdout to show in its
    console) writes here as it goes, so the worker process itself never
    needs its own logging setup or IPC to report a run_id back."""
    app_paths.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    return app_paths.LOGS_DIR / f"worker-{run_id}.log"


def redact_worker_line(line: str) -> str:
    """Applies the same secret-redaction rules as everything else this app
    logs, caps the line length, and replaces non-printable/control
    characters (spec 5.9: 'binary 또는 제어문자를 출력해도 로그 형식을 깨지
    않도록 escape') so a misbehaving external tool can't corrupt the log
    file's line-oriented structure."""
    text = log_redaction.redact_text(line.rstrip("\r\n"))
    text = "".join(ch if ch == "\t" or (ch.isprintable() and ch not in "\r\n") else "�" for ch in text)
    if len(text) > MAX_WORKER_LINE_LENGTH:
        text = text[:MAX_WORKER_LINE_LENGTH] + " ...(줄 길이 상한 초과로 잘림)"
    return text


# ---------------------------------------------------------------------------
# Retention cleanup (spec 5.3)
# ---------------------------------------------------------------------------
def cleanup_expired_logs() -> None:
    if not app_paths.LOGS_DIR.is_dir():
        return
    now = time.time()
    try:
        for f in app_paths.LOGS_DIR.glob("crash-*.log"):
            if now - f.stat().st_mtime > CRASH_RETENTION_DAYS * 86400:
                f.unlink(missing_ok=True)
        for f in app_paths.LOGS_DIR.glob("worker-*.log"):
            if now - f.stat().st_mtime > WORKER_RETENTION_DAYS * 86400:
                f.unlink(missing_ok=True)
    except OSError:
        pass  # spec 5.3: "로그 정리 실패는 프로그램 실행을 막지 않는다"


# ---------------------------------------------------------------------------
# Log management UI support (spec 5.9: 로그 폴더 열기/내보내기/지우기)
# ---------------------------------------------------------------------------
def open_logs_folder() -> None:
    """Opens %LOCALAPPDATA%\\ProxyScanner\\logs\\ in Explorer. Best-effort --
    a failure here (e.g. no shell available) must never crash the app, so
    the caller just gets an OSError to show a messagebox for."""
    app_paths.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        os.startfile(str(app_paths.LOGS_DIR))  # noqa: S606 -- fixed local path, not user input
    else:
        subprocess.Popen(["xdg-open", str(app_paths.LOGS_DIR)])  # pragma: no cover -- Windows-only app


def export_logs(dest_zip: Path, manifest_text: str = "") -> int:
    """Zips every file currently under logs\\ into dest_zip, plus a
    manifest.txt (spec 5.10: version/자원 목록/설정값의 민감정보 제거 사본)
    if the caller supplies one. Returns the number of files written. Never
    touches History DB or certificates\\ (spec 6 scenario 14) -- those live
    under separate app_paths dirs this function doesn't look at. Doesn't
    stop the listener first -- proxy-scanner.log is opened in append mode
    by RotatingFileHandler, so reading it concurrently for the zip is safe
    on Windows (no exclusive lock held)."""
    app_paths.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(dest_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        if manifest_text:
            zf.writestr("manifest.txt", manifest_text)
            count += 1
        for f in app_paths.LOGS_DIR.glob("*"):
            if f.is_file():
                zf.write(f, arcname=f.name)
                count += 1
    return count


def clear_all_logs(session_id: str) -> None:
    """Deletes every file under logs\\ and immediately reopens a fresh
    proxy-scanner.log under the same session -- stops the listener first
    (RotatingFileHandler holds an exclusive-enough handle on Windows that a
    concurrent unlink would otherwise fail)."""
    was_debug = _debug_enabled
    shutdown_logging()
    try:
        for f in app_paths.LOGS_DIR.glob("*"):
            if f.is_file():
                f.unlink(missing_ok=True)
    except OSError:
        pass
    setup_logging(session_id, verbose=was_debug)
