"""Pure History filter matching logic (spec: 목록 진행·Infra·ffuf·Gobuster·
HTTP History 개선명세서 §8) -- kept separate from gui.py so the actual
matching rules can be unit-tested without building a Tk window. The GUI
layer (gui.py) owns the Tk widgets and translates their state into a
`HistoryFilterState`, then calls `matches()` for each record.

Rule (spec §14.7.3 "AND/OR 규칙이 UI 설명과 일치하는지"): every category
below is ANDed together; a multi-select category (methods/statuses/mimes)
is ORed within itself -- i.e. "메소드 GET 또는 POST" AND "상태 2xx" AND ...
"""
from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field

from models import FlowRecord

_STATIC_EXTENSIONS = {
    "css", "js", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "woff", "woff2",
    "ttf", "eot", "otf", "map", "mp4", "webm", "mp3", "wav",
}

_MIME_CATEGORIES = {
    "HTML": ("text/html",),
    "Script": ("javascript", "ecmascript"),
    "JSON/API": ("json",),
    "XML": ("xml",),
    "CSS": ("text/css",),
    "Image": ("image/",),
    "Font": ("font/", "font-woff", "vnd.ms-fontobject"),
    "Media": ("video/", "audio/"),
}


def classify_mime(mime: str) -> str:
    m = (mime or "").lower()
    for category, needles in _MIME_CATEGORIES.items():
        if any(n in m for n in needles):
            return category
    if not m:
        return "기타"
    if m.startswith("text/"):
        return "기타"
    return "Binary" if "/" in m else "기타"


def status_bucket(status: int | None) -> str:
    if status is None:
        return "응답 없음"
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if 500 <= status < 600:
        return "5xx"
    return "기타"


@dataclass
class HistoryFilterState:
    methods: set[str] = field(default_factory=set)  # empty = all
    statuses: set[str] = field(default_factory=set)  # "응답 없음"/"2xx"/... ; empty = all
    status_custom: str = ""  # explicit code/range, e.g. "429" or "500-599" -- ANDed as an extra OR-option
    mimes: set[str] = field(default_factory=set)  # empty = all

    scope: str = "all"  # all|current_target|host|port|burp|independent
    scope_host: str = ""
    scope_port: str = ""
    current_target_host: str | None = None
    current_target_port: int | None = None

    url_contains: str = ""
    ext_include: str = ""  # comma list
    ext_exclude: str = ""
    has_query: str = "any"  # any|yes|no
    hide_static: bool = False

    content_query: str = ""
    content_where: str = "both"  # request|response|both
    content_case_sensitive: bool = False
    content_regex: bool = False

    findings: str = "any"  # any|yes|no
    min_length: str = ""
    max_length: str = ""

    quick_search: str = ""
    quick_search_current_target_only: bool = False

    def is_default(self) -> bool:
        """`current_target_host`/`current_target_port` are re-derived from
        the live target bar on every _reapply_history_filter() call, not an
        actual user filter choice -- comparing them would make "Filter is
        active" flicker on/off just because a target happens to be applied,
        even when scope/quick_search never reference it at all."""
        mine = dataclasses.replace(self, current_target_host=None, current_target_port=None)
        blank = dataclasses.replace(
            HistoryFilterState(), current_target_host=None, current_target_port=None
        )
        return mine == blank


def _status_in_custom_spec(status: int | None, spec: str) -> bool:
    if status is None or not spec.strip():
        return False
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                if int(lo) <= status <= int(hi):
                    return True
            except ValueError:
                continue
        else:
            try:
                if status == int(part):
                    return True
            except ValueError:
                continue
    return False


def _text_matches(haystack: str, needle: str, case_sensitive: bool, use_regex: bool) -> bool:
    if not needle:
        return True
    if use_regex:
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            return re.search(needle, haystack, flags) is not None
        except re.error:
            return False
    if case_sensitive:
        return needle in haystack
    return needle.lower() in haystack.lower()


def matches(record: FlowRecord, f: HistoryFilterState) -> bool:
    if f.quick_search:
        if f.quick_search_current_target_only and f.current_target_host:
            if record.host != f.current_target_host:
                return False
        haystack = f"{record.method} {record.url} {record.status_display} {record.mime}"
        if not _text_matches(haystack, f.quick_search, case_sensitive=False, use_regex=False):
            return False

    if f.methods:
        known = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
        rec_method = record.method if record.method in known else "기타"
        if rec_method not in f.methods:
            return False

    if f.statuses or f.status_custom:
        bucket = status_bucket(record.status)
        in_bucket_set = bool(f.statuses) and bucket in f.statuses
        in_custom = _status_in_custom_spec(record.status, f.status_custom)
        if not (in_bucket_set or in_custom):
            return False

    if f.mimes:
        if classify_mime(record.mime) not in f.mimes:
            return False

    if f.scope == "current_target":
        if f.current_target_host is None or record.host != f.current_target_host:
            return False
        if f.current_target_port is not None and record.port != f.current_target_port:
            return False
    elif f.scope == "host":
        if f.scope_host and record.host != f.scope_host:
            return False
    elif f.scope == "port":
        if f.scope_port:
            try:
                if record.port != int(f.scope_port):
                    return False
            except ValueError:
                pass
    elif f.scope == "burp":
        if record.source != "burp_proxy":
            return False
    elif f.scope == "independent":
        if record.source != "independent_proxy":
            return False

    if f.url_contains and f.url_contains.lower() not in record.url.lower():
        return False
    if f.ext_include:
        wanted = {e.strip().lower().lstrip(".") for e in f.ext_include.split(",") if e.strip()}
        if wanted and record.file_extension not in wanted:
            return False
    if f.ext_exclude:
        excluded = {e.strip().lower().lstrip(".") for e in f.ext_exclude.split(",") if e.strip()}
        if record.file_extension in excluded:
            return False
    if f.has_query == "yes" and not record.has_query:
        return False
    if f.has_query == "no" and record.has_query:
        return False
    if f.hide_static and record.file_extension in _STATIC_EXTENSIONS:
        return False

    if f.content_query:
        req_text = f"{record.req_headers}\n{record.req_body}"
        resp_text = f"{record.resp_headers}\n{record.resp_body}"
        target_text = {"request": req_text, "response": resp_text, "both": req_text + "\n" + resp_text}[f.content_where]
        if not _text_matches(target_text, f.content_query, f.content_case_sensitive, f.content_regex):
            return False

    if f.findings == "yes" and not record.has_findings:
        return False
    if f.findings == "no" and record.has_findings:
        return False
    if f.min_length.strip():
        try:
            if record.content_length < int(f.min_length):
                return False
        except ValueError:
            pass
    if f.max_length.strip():
        try:
            if record.content_length > int(f.max_length):
                return False
        except ValueError:
            pass

    return True
