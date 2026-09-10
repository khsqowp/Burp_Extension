from __future__ import annotations

import queue
import time

from models import Finding, FlowRecord, SOURCE_INDEPENDENT_PROXY
from rules import detect_reflected_values, detect_sqli_error, detect_waf_block

MAX_STORED_BODY = 200_000  # truncate stored body text so the GUI stays responsive


def _safe_text(getter) -> str:
    try:
        text = getter()
        return text if text is not None else ""
    except Exception:
        return "(디코딩 불가 -- 바이너리/알 수 없는 인코딩)"


def _truncate(s: str) -> str:
    if len(s) > MAX_STORED_BODY:
        return s[:MAX_STORED_BODY] + f"\n... (truncated, {len(s)} bytes total)"
    return s


def _mime_of(resp) -> str:
    if resp is None:
        return ""
    content_type = resp.headers.get("content-type", "")
    return content_type.split(";", 1)[0].strip()


class HistoryAddon:
    """mitmproxy addon: on every completed response, builds a FlowRecord,
    runs the passive rules against it, and pushes the record into a
    thread-safe queue for the GUI thread to pick up."""

    def __init__(self, out_queue: "queue.Queue[FlowRecord]") -> None:
        self.out_queue = out_queue
        self._seq = 0

    def response(self, flow) -> None:  # mitmproxy calls this with an http.HTTPFlow
        self._seq += 1
        req = flow.request
        resp = flow.response

        req_headers = "\n".join(f"{k}: {v}" for k, v in req.headers.items())
        resp_headers = "\n".join(f"{k}: {v}" for k, v in (resp.headers.items() if resp else []))
        req_body = _truncate(_safe_text(lambda: req.get_text()))
        resp_body = _truncate(_safe_text(lambda: resp.get_text() if resp else ""))
        content_type = resp.headers.get("content-type", "") if resp else ""
        status = resp.status_code if resp else None

        findings: list[Finding] = []

        waf = detect_waf_block(req.method, req.pretty_url, req_body, status, resp_body)
        if waf:
            findings.append(waf)

        sqli = detect_sqli_error(resp_body)
        if sqli:
            findings.append(sqli)

        sources: list[tuple[str, str, str]] = []
        try:
            for k, v in req.cookies.items(multi=True):
                sources.append(("cookie", k, v))
        except Exception:
            pass
        try:
            for k, v in req.query.items(multi=True):
                sources.append(("query", k, v))
        except Exception:
            pass
        try:
            if "application/x-www-form-urlencoded" in req.headers.get("content-type", ""):
                for k, v in req.urlencoded_form.items(multi=True):
                    sources.append(("form", k, v))
        except Exception:
            pass
        findings.extend(detect_reflected_values(sources, resp_body, content_type))

        try:
            content_length = len(resp.content) if resp is not None and resp.content is not None else 0
        except Exception:
            content_length = 0

        started_at = getattr(req, "timestamp_start", None)
        duration_ms = None
        response_end = getattr(resp, "timestamp_end", None) if resp is not None else None
        if started_at and response_end:
            duration_ms = max(0.0, (response_end - started_at) * 1000)

        record = FlowRecord(
            seq=self._seq,
            ts=time.time(),
            method=req.method,
            host=req.pretty_host,
            port=req.port,
            path=req.path,
            url=req.pretty_url,
            status=status,
            req_headers=req_headers,
            req_body=req_body,
            resp_headers=resp_headers,
            resp_body=resp_body,
            mime=_mime_of(resp),
            content_length=content_length,
            error=None,
            findings=findings,
            source=SOURCE_INDEPENDENT_PROXY,
            started_at=started_at,
            duration_ms=duration_ms,
        )
        self.out_queue.put(record)

    def error(self, flow) -> None:  # mitmproxy calls this when a flow fails before any response arrives
        """Connection refused / DNS failure / timeout / TLS handshake failure
        -- these never reach response() at all (flow.response stays None),
        so without this hook they simply vanished from History instead of
        showing up as a visible '응답 없음' entry."""
        self._seq += 1
        req = flow.request
        try:
            req_headers = "\n".join(f"{k}: {v}" for k, v in req.headers.items())
        except Exception:
            req_headers = ""
        req_body = _truncate(_safe_text(lambda: req.get_text()))
        error_msg = flow.error.msg if getattr(flow, "error", None) else "알 수 없는 오류"

        record = FlowRecord(
            seq=self._seq,
            ts=time.time(),
            method=getattr(req, "method", "?"),
            host=getattr(req, "pretty_host", "?"),
            port=getattr(req, "port", 0),
            path=getattr(req, "path", ""),
            url=getattr(req, "pretty_url", ""),
            status=None,
            req_headers=req_headers,
            req_body=req_body,
            resp_headers="",
            resp_body="",
            mime="",
            content_length=0,
            error=error_msg,
            findings=[],
            source=SOURCE_INDEPENDENT_PROXY,
            started_at=getattr(req, "timestamp_start", None),
        )
        self.out_queue.put(record)
