"""Local receiver for the Burp Suite History Bridge extension (spec: Burp
Browser 연동 §3.2-3.4). Listens on 127.0.0.1 only (never any other
interface), validates a per-session token so no other local process can
inject fake History rows, and turns each accepted exchange into a
FlowRecord the GUI can feed through its existing History pipeline exactly
like a mitmproxy-captured one.

Known limitation carried over from the extension side (see
burp_extension's BurpScannerExtension docstring): Montoya's HttpHandler
only fires once a response actually arrives, so a request that times out
or gets connection-refused in Burp is invisible here -- there is no
Burp-sourced equivalent of the independent proxy mode's "응답 없음" rows.
"""
from __future__ import annotations

import http.server
import json
import queue
import secrets
import sys
import threading
import time
from collections import OrderedDict
from pathlib import Path

import app_logging
from models import FlowRecord, SOURCE_BURP_PROXY

_logger = app_logging.get_logger("burp_bridge")

STATUS_DISCONNECTED = "Burp 연결 안 됨"
STATUS_WAITING = "Burp 연결 대기 중"  # 실제 표시 시 -- 127.0.0.1:<port> 붙임
STATUS_CONNECTED = "Burp 연결됨 -- History 수신 중"
STATUS_LOST = "Burp 연결 끊김 -- 재연결 대기 중"
STATUS_ERROR = "연동 오류"  # 실제 표시 시 -- <원인> 붙임

IDLE_TIMEOUT_SECONDS = 30.0  # no accepted exchange for this long while "연결됨" -> "연결 끊김"
MAX_DEDUP_KEYS = 5000
MAX_INGEST_BYTES = 5 * 1024 * 1024  # design review finding: cap a single /ingest body instead of reading unbounded


def _extension_jar_path() -> Path:
    """Dual-path resource resolution (personal env vs. frozen-bundled),
    matching tool_registry.py's own _tools_root() pattern."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "burp_extension" / "burp-history-bridge.jar"  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent / "burp_extension" / "target" / "burp-history-bridge.jar"


class BurpBridgeServer:
    def __init__(self, out_queue: "queue.Queue[FlowRecord]") -> None:
        self.out_queue = out_queue
        self.port = 8899
        self.token = secrets.token_hex(24)
        self._httpd: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._last_accept_time: float | None = None
        self._error: str | None = None
        self._dedup: "OrderedDict[str, None]" = OrderedDict()
        self.received_count = 0

    # -- lifecycle -----------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._httpd is not None

    def start(self, port: int) -> None:
        if self.running:
            return
        self.port = port
        self._error = None
        server = self
        bridge_ref = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a: object) -> None:  # silence default stderr access log
                pass

            def _token_ok(self) -> bool:
                token = self.headers.get("X-Session-Token", "")
                return secrets.compare_digest(token, bridge_ref.token)

            def do_GET(self) -> None:  # noqa: N802
                # Authenticated health check (design review finding: "연결
                # 성공은 실제 인증된 ping/health 응답으로 확인해야 한다") --
                # lets the Burp extension's own '연결 테스트' button give an
                # immediate yes/no on whether the token actually matches,
                # instead of only finding out on the first real Burp Browser
                # request.
                if self.path != "/ping":
                    self.send_response(404)
                    self.end_headers()
                    return
                if not self._token_ok():
                    app_logging.log_event(_logger, "WARNING", "burp_auth_failed", "Burp /ping 토큰 불일치", path="/ping")
                    self.send_response(403)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self) -> None:  # noqa: N802 -- BaseHTTPRequestHandler's own naming convention
                if self.path != "/ingest":
                    self.send_response(404)
                    self.end_headers()
                    return
                if not self._token_ok():
                    app_logging.log_event(_logger, "WARNING", "burp_auth_failed", "Burp /ingest 토큰 불일치", path="/ingest")
                    self.send_response(403)
                    self.end_headers()
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length <= 0 or length > MAX_INGEST_BYTES:
                        bridge_ref._error = f"요청 본문 크기 초과 또는 잘못됨 ({length} bytes, 상한 {MAX_INGEST_BYTES})"
                        self.send_response(413)
                        self.end_headers()
                        return
                    raw = self.rfile.read(length)
                    payload = json.loads(raw.decode("utf-8"))
                    bridge_ref._accept(payload)
                    self.send_response(200)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                except Exception as exc:  # noqa: BLE001 -- one malformed request must never take the server down
                    bridge_ref._error = f"잘못된 요청 처리 실패: {exc}"
                    app_logging.log_exception(_logger, "tool_failed", "Burp /ingest 요청 처리 실패", sys.exc_info())
                    self.send_response(400)
                    self.end_headers()

        try:
            # Explicit 127.0.0.1, never "" / "0.0.0.0" -- spec 3.2: "외부 인터페이스에 바인딩하지 않는다".
            httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Handler)
        except OSError as exc:
            self._error = f"{port}번 포트를 열 수 없음: {exc}"
            app_logging.log_event(_logger, "ERROR", "burp_bridge_start_failed", str(exc), port=port)
            raise
        httpd.daemon_threads = True
        self._httpd = httpd
        self._thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        self._thread = None

    # -- ingestion -------------------------------------------------------------
    def _accept(self, payload: dict) -> None:
        dedup_key = payload.get("dedup_key") or ""
        with self._lock:
            if dedup_key and dedup_key in self._dedup:
                return  # spec 3.5: 중복 전달 방지
            if dedup_key:
                self._dedup[dedup_key] = None
                if len(self._dedup) > MAX_DEDUP_KEYS:
                    self._dedup.popitem(last=False)
            self._last_accept_time = time.monotonic()
            self.received_count += 1

        record = FlowRecord(
            seq=0,  # overwritten by HistoryStore.add() / the in-memory fallback counter, same as every other source
            ts=float(payload.get("timestamp") or time.time()),
            method=str(payload.get("method") or "?"),
            host=str(payload.get("host") or "?"),
            port=int(payload.get("port") or 0),
            path=_path_from_url(str(payload.get("url") or "")),
            url=str(payload.get("url") or ""),
            status=payload.get("status"),
            req_headers=str(payload.get("req_headers") or ""),
            req_body=str(payload.get("req_body") or ""),
            resp_headers=str(payload.get("resp_headers") or ""),
            resp_body=str(payload.get("resp_body") or ""),
            mime=str(payload.get("mime") or ""),
            content_length=int(payload.get("content_length") or 0),
            error=payload.get("error"),
            source=SOURCE_BURP_PROXY,
        )
        self.out_queue.put(record)

    # -- status ------------------------------------------------------------
    def status_text(self) -> str:
        if not self.running:
            return STATUS_DISCONNECTED
        if self._error:
            return f"{STATUS_ERROR} -- {self._error}"
        with self._lock:
            last = self._last_accept_time
        if last is None:
            return f"{STATUS_WAITING} -- 127.0.0.1:{self.port}"
        if time.monotonic() - last > IDLE_TIMEOUT_SECONDS:
            return STATUS_LOST
        return STATUS_CONNECTED


def _path_from_url(url: str) -> str:
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.path + (f"?{parsed.query}" if parsed.query else "") or "/"
    except Exception:  # noqa: BLE001
        return "/"
