"""Event Log (spec §57) -- every Scan/Task lifecycle event and Safety Policy
decision gets one JSON-line appended to scanner-data/logs/scanner.log, so an
operator can reconstruct what ran, when, and why something was blocked or
cancelled, without cross-referencing the SQLite tables and raw result files
by hand (spec review finding 2026-09-06: scanner-data/logs/ existed but
nothing ever wrote to it).

Never logs secrets, tokens, or full request/response bodies (spec §57's
"고객사 정보를 로그 외부로 전달하는 기능" concern) -- only the same small set
of ids/module names/policy reasons already surfaced through the API.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import datetime, timezone
from pathlib import Path

_logger = logging.getLogger("security_toolkit.events")


def setup_event_log(logs_dir: str | Path) -> None:
    """Idempotent -- safe to call once per process (api/main.py's lifespan)
    even though multiple Orchestrator instances may exist across tests."""
    logs_dir = Path(logs_dir)
    logs_dir.mkdir(parents=True, exist_ok=True)
    if _logger.handlers:
        return
    handler = logging.handlers.RotatingFileHandler(
        logs_dir / "scanner.log", maxBytes=10_000_000, backupCount=5, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False  # don't also spam the root logger/console


def log_event(event: str, **fields) -> None:
    """No-op (well, silently dropped by the logging module) until
    setup_event_log() has been called -- fine for tests/CLI use that never
    configure a data dir at all."""
    record = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
    _logger.info(json.dumps(record, ensure_ascii=False))
