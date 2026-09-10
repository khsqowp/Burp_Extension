"""Central redaction rules for everything this program logs (spec: 개선작업
로그 기능 명세 §5.7 "민감정보 제거 규칙"). Every log write goes through
here first -- logs are diagnostic, never a second copy of a credential
store. Kept as its own module (not folded into app_logging.py) so every
caller that builds a log message -- including outside the logging module
itself, e.g. a place that wants to show a redacted argv in the GUI -- can
reuse the exact same rules instead of re-implementing them slightly
differently.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_REDACTED = "<redacted>"

# Header names whose *value* is always replaced outright, regardless of format.
_SENSITIVE_HEADER_NAMES = frozenset(
    n.lower()
    for n in (
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-session-token",
        "x-api-key",
    )
)

# URL/form query parameter names whose value gets redacted (spec 5.7).
_SENSITIVE_QUERY_PARAMS = frozenset(
    ("password", "passwd", "token", "key", "secret", "session", "auth", "code")
)

# A JWT looks like three base64url segments separated by dots, header segment
# itself typically starts with "eyJ" (base64 of '{"') -- conservative enough
# to not accidentally eat a normal 3-dot-separated non-JWT string that also
# happens to start that way, since real prose essentially never does.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")

_HEADER_LINE_RE = re.compile(r"^([^:\r\n]+):\s?(.*)$")


def redact_header_block(headers_text: str) -> str:
    """Redacts one HTTP-style "Name: value" block (one header per line) --
    used for request/response headers wherever they'd otherwise be logged."""
    if not headers_text:
        return headers_text
    out_lines = []
    for line in headers_text.splitlines():
        m = _HEADER_LINE_RE.match(line)
        if m and m.group(1).strip().lower() in _SENSITIVE_HEADER_NAMES:
            out_lines.append(f"{m.group(1)}: {_REDACTED}")
        else:
            out_lines.append(_JWT_RE.sub(_REDACTED, line))
    return "\n".join(out_lines)


def redact_url(url: str) -> str:
    """Redacts sensitive query-string parameter values, keeps everything
    else (scheme/host/port/path/param names) intact -- spec 5.7 example:
    'https://target/login?user=test&password=<redacted>'."""
    if not url or "?" not in url:
        return _JWT_RE.sub(_REDACTED, url or "")
    try:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        redacted_pairs = [
            (k, _REDACTED if k.lower() in _SENSITIVE_QUERY_PARAMS else v) for k, v in pairs
        ]
        new_query = urlencode(redacted_pairs)
        return urlunparse(parsed._replace(query=new_query))
    except ValueError:
        return _JWT_RE.sub(_REDACTED, url)


def redact_text(text: str) -> str:
    """General-purpose fallback for free-form text (console output lines,
    exception messages) that might contain a JWT or an obviously-sensitive
    query string -- does not attempt header-block parsing."""
    if not text:
        return text
    return _JWT_RE.sub(_REDACTED, text)


def redact_argv(argv: list[str]) -> list[str]:
    """Redacts the value following any CLI flag whose own name suggests a
    secret (password/token/secret/key/cookie/authorization), plus JWTs and
    sensitive query params appearing anywhere in the argv (spec 5.1:
    '실제 하위 프로세스 인자는 무엇이었는가' -- logged, but never the
    secret payload itself)."""
    sensitive_flag_re = re.compile(r"--?.*(password|passwd|token|secret|cookie|auth)", re.IGNORECASE)
    out: list[str] = []
    redact_next = False
    for arg in argv:
        if redact_next:
            out.append(_REDACTED)
            redact_next = False
            continue
        if sensitive_flag_re.match(arg):
            out.append(arg)
            redact_next = True
            continue
        if arg.startswith(("http://", "https://")):
            out.append(redact_url(arg))
        else:
            out.append(redact_text(arg))
    return out
