from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# spec: 목록 진행·Infra·ffuf·Gobuster·HTTP History 개선명세서 §10 -- a History
# row's own capture path, so the filter bar's "대상 범위" (Burp 연동 수신
# 항목만 / 독립 프록시 캡처 항목만) can distinguish them without guessing from
# other fields. A pre-migration row that predates this field is always
# "legacy_unknown", never guessed into one of the two real sources.
SOURCE_BURP_PROXY = "burp_proxy"
SOURCE_INDEPENDENT_PROXY = "independent_proxy"
SOURCE_LEGACY_UNKNOWN = "legacy_unknown"


@dataclass
class Finding:
    category: str  # WAF_BLOCK / SQLI_ERROR / REFLECTED_XSS
    severity: str  # HIGH / MEDIUM / LOW
    detail: str
    evidence: str


@dataclass
class FlowRecord:
    seq: int
    ts: float
    method: str
    host: str
    port: int
    path: str
    url: str
    status: int | None
    req_headers: str
    req_body: str
    resp_headers: str
    resp_body: str
    mime: str = ""
    content_length: int = 0
    error: str | None = None  # set (non-empty) only when no response was ever received
    findings: list[Finding] = field(default_factory=list)
    # -- filter/sort metadata (spec §10) -- scheme/has_query/file_extension/
    # has_findings are all derivable from other fields already on this
    # record, so __post_init__ fills them in automatically when a caller
    # doesn't pass one explicitly; source/started_at/duration_ms carry
    # information this record has no other way to reconstruct, so callers
    # that know better (addon.py, burp_bridge.py) should always pass them.
    source: str = SOURCE_LEGACY_UNKNOWN
    scheme: str = ""
    has_query: bool = False
    file_extension: str = ""
    started_at: float | None = None
    duration_ms: float | None = None
    has_findings: bool = False

    def __post_init__(self) -> None:
        parsed = urlsplit(self.url)
        if not self.scheme:
            self.scheme = parsed.scheme
        if not self.has_query:
            self.has_query = bool(parsed.query)
        if not self.file_extension:
            last_segment = parsed.path.rsplit("/", 1)[-1]
            if "." in last_segment:
                self.file_extension = last_segment.rsplit(".", 1)[-1].lower()
        if self.started_at is None:
            self.started_at = self.ts
        if not self.has_findings:
            self.has_findings = bool(self.findings)

    @property
    def time_str(self) -> str:
        local = time.localtime(self.ts)
        ms = int((self.ts - int(self.ts)) * 1000)
        return time.strftime("%H:%M:%S", local) + f".{ms:03d}"

    @property
    def host_display(self) -> str:
        default_port = 443 if self.url.startswith("https://") else 80
        return self.host if self.port == default_port else f"{self.host}:{self.port}"

    @property
    def status_display(self) -> str:
        return str(self.status) if self.status is not None else "응답 없음"

    @property
    def max_severity(self) -> str | None:
        order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: order.get(s, 0))
