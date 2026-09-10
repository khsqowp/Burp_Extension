"""Passive traffic-analysis rules.

These never send anything -- they only look at request/response pairs that
already happened (the user drove real traffic through the proxy, e.g. via a
browser). Each rule flags a *candidate* worth manually checking, not a
confirmed vulnerability.
"""
from __future__ import annotations

import re

from models import Finding

MAX_BODY_SCAN = 300_000  # cap regex scans on huge bodies for responsiveness

# ---------------------------------------------------------------------------
# 1) WAF / payload-block detection
# ---------------------------------------------------------------------------
BLOCK_STATUSES = {403, 406, 419, 429, 501}

WAF_BODY_SIGNATURES = [
    r"mod_?security",
    r"access denied",
    r"request rejected",
    r"the requested url was rejected",
    r"blocked by (website|web) (protection|firewall)",
    r"incapsula incident id",
    r"sucuri website firewall",
    r"aws waf",
    r"barracuda",
    r"you don't have permission to access",
    r"web application firewall",
    r"cloudflare ray id",
]
_WAF_BODY_RE = re.compile("|".join(WAF_BODY_SIGNATURES), re.IGNORECASE)

# Rough signal that the *request* looks like it was deliberately probing --
# used to raise confidence that a block response is payload-triggered rather
# than an unrelated 403 (e.g. auth-required page).
SUSPICIOUS_REQUEST_MARKERS = [
    "<script", "onerror=", "onload=", "javascript:", "alert(",
    "' or ", "\" or ", "union select", "union all select", "--", ";--",
    "../", "..\\", "%27", "%3cscript", "1=1", "sleep(", "benchmark(",
]


def detect_waf_block(method: str, url: str, req_body: str, status: int | None, resp_body: str) -> Finding | None:
    if status is None:
        return None
    body_hit = _WAF_BODY_RE.search(resp_body[:MAX_BODY_SCAN])
    looks_probed = any(m in (url + req_body).lower() for m in SUSPICIOUS_REQUEST_MARKERS)

    if body_hit:
        sig = body_hit.group(0)
        sev = "HIGH" if looks_probed else "MEDIUM"
        return Finding(
            category="WAF_BLOCK",
            severity=sev,
            detail=f"WAF/차단 페이지 시그니처 감지 ('{sig}')" + (" -- 의심스러운 페이로드 포함 요청" if looks_probed else ""),
            evidence=sig,
        )
    if status in BLOCK_STATUSES and looks_probed:
        return Finding(
            category="WAF_BLOCK",
            severity="MEDIUM",
            detail=f"의심스러운 페이로드가 포함된 요청이 {status}로 차단됨 -- WAF/필터 가능성",
            evidence=f"status={status}",
        )
    return None


# ---------------------------------------------------------------------------
# 2) SQL error-signature detection
# ---------------------------------------------------------------------------
SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"valid mysql result",
    r"mysqlclient\.",
    r"pg_query\(\)",
    r"postgresql query failed",
    r"org\.postgresql\.util\.psqlexception",
    r"microsoft ole db provider for sql server",
    r"system\.data\.sqlclient\.",
    r"ora-\d{5}",
    r"oracle error",
    r"sqlite3\.operationalerror",
    r"sqlite_error",
    r'near ".+": syntax error',
    r"odbc (sql server driver|drivers? error)",
    r"jdbc\.driver",
    r"syntax error at or near",
    r"unterminated quoted string",
]
_SQLI_RE = re.compile("|".join(SQLI_ERROR_PATTERNS), re.IGNORECASE)


def detect_sqli_error(resp_body: str) -> Finding | None:
    m = _SQLI_RE.search(resp_body[:MAX_BODY_SCAN])
    if not m:
        return None
    return Finding(
        category="SQLI_ERROR",
        severity="HIGH",
        detail=f"응답에 DB 에러 시그니처 발견 ('{m.group(0)}') -- SQLi 가능성",
        evidence=m.group(0),
    )


# ---------------------------------------------------------------------------
# 3) Reflected value detection (cookie/query/form value echoed back unescaped)
# ---------------------------------------------------------------------------
DANGEROUS_CHARS = set("<>\"'")


def classify_context(text: str, idx: int, content_type: str) -> str:
    if "json" in content_type.lower():
        return "json"
    before = text[max(0, idx - 200) : idx]
    last_script_open = before.rfind("<script")
    last_script_close = before.rfind("</script")
    if last_script_open > last_script_close:
        if re.search(r"""['"]\s*$""", before):
            return "javascript-string"
        return "javascript-raw"
    if re.search(r"""(href|src|action)\s*=\s*["']$""", before, re.IGNORECASE):
        return "url-attribute"
    if re.search(r"""=\s*["']$""", before):
        return "attribute-quoted"
    if re.search(r"""[a-zA-Z][a-zA-Z0-9_-]*=\s*$""", before):
        return "attribute-unquoted"
    return "html-text"


def detect_reflected_values(sources: list[tuple[str, str, str]], resp_body: str, content_type: str) -> list[Finding]:
    """sources: list of (source_label, name, value) e.g. ("cookie", "session", "abc")."""
    findings: list[Finding] = []
    body = resp_body[:MAX_BODY_SCAN]
    seen: set[str] = set()
    for source, name, value in sources:
        if len(value) < 4 or not (set(value) & DANGEROUS_CHARS):
            continue
        key = f"{source}:{name}:{value}"
        if key in seen:
            continue
        idx = body.find(value)
        if idx == -1:
            continue
        seen.add(key)
        context = classify_context(body, idx, content_type)
        dangerous_context = context != "json"
        severity = "HIGH" if dangerous_context else "LOW"
        findings.append(
            Finding(
                category="REFLECTED_XSS",
                severity=severity,
                detail=f"{source} '{name}' 값이 응답에 그대로(unescaped) 반사됨 -- context={context}",
                evidence=value[:80],
            )
        )
    return findings
