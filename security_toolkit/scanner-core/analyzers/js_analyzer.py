"""JavaScript / Web Resource Analyzer (spec §17/§34).

Reuses site_depth_crawler.crawler's own already-tested
extract_js_path_candidates() for API-endpoint/internal-path extraction
instead of re-deriving the same regex. On top of that this adds two new,
narrowly-scoped signals that tool doesn't produce:
  - a handful of well-known JS library name+version fingerprints, emitted
    as Technology records so the existing CVE/EOL Matchers (spec §19/§21)
    can be run against client-side libraries too, not just nmap services.
  - obvious hardcoded-secret patterns (AWS access key, generic api_key/
    token/secret assignments) -- these DO become Findings directly, since
    a real secret is a real Finding, not just discovery data (unlike a
    plain extracted route candidate, which stays in raw_ref only).

Registered under the same ToolWrapper contract as the subprocess-based
wrappers (build_command/execute are stubbed out -- this analyzer fetches
and parses in-process instead of spawning an external tool), so the
Orchestrator can dispatch it identically via wrapper.run().
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

from storage.models import Finding, ScanTarget, Severity, Technology
from wrappers.base import ToolWrapper, WrapperResult

EXTERNAL_TOOLS_ROOT = Path(__file__).resolve().parents[3]
CRAWLER_DIR = EXTERNAL_TOOLS_ROOT / "site_depth_crawler"
if str(CRAWLER_DIR) not in sys.path:
    sys.path.insert(0, str(CRAWLER_DIR))

MAX_JS_BYTES = 2_000_000

# Best-effort, conservative fingerprints -- false negatives (missing a
# library) are fine, false positives on a Finding are not, so the secret
# patterns require a reasonably long value before matching.
_LIBRARY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("jquery", re.compile(r"jQuery\s+v?([0-9]+\.[0-9]+\.[0-9]+)")),
    ("jquery", re.compile(r"jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js")),
    ("react", re.compile(r'"react"\s*:\s*"[\^~]?([0-9]+\.[0-9]+\.[0-9]+)"')),
    ("vue", re.compile(r'Vue\.version\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']')),
    ("lodash", re.compile(r"lodash\s+v([0-9]+\.[0-9]+\.[0-9]+)")),
    ("angular", re.compile(r"angular[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js")),
]

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "hardcoded API key/secret/token",
        re.compile(r"(?:api[_-]?key|secret|token)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]", re.IGNORECASE),
    ),
]


def _validate_js_url_in_scope(js_url: str, target: ScanTarget) -> None:
    """spec review finding (2026-09-05): js_analyzer is classified SAFE
    (safety/policy.py) on the assumption it only ever does a single GET
    against the page's own JS bundle -- but js_url used to be passed
    straight into urlopen() with no validation at all, so a caller could
    point it at file:///etc/passwd, an internal-network address, or a cloud
    metadata endpoint (SSRF) and get the response reflected back via the
    secret-pattern Findings. Also spec §56 Scope Control: "Crawler,
    Redirect, JavaScript 분석 등에서 발견된 외부 도메인은 자동 Scan 대상으로
    포함하지 않는다" -- a JS file on a third-party CDN domain is out of
    scope even if it's plain http(s)."""
    parsed = urllib.parse.urlparse(js_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"js_analyzer: js_url must be http(s), got scheme {parsed.scheme!r}")
    if not parsed.hostname:
        raise ValueError("js_analyzer: js_url has no host")

    scope_host = target.scope_host or urllib.parse.urlparse(target.value).hostname or target.value
    scope_host = scope_host.split(":")[0].lower()
    if parsed.hostname.lower() != scope_host:
        raise ValueError(
            f"js_analyzer: js_url host {parsed.hostname!r} is out of scope (target scope_host={scope_host!r})"
        )


class JsAnalyzer(ToolWrapper):
    module = "js_analyzer"

    def build_command(self, target: ScanTarget, **kwargs) -> list[str]:
        raise NotImplementedError("JsAnalyzer fetches/parses in-process; it never spawns a subprocess")

    def run(
        self, target: ScanTarget, *, js_url: str = "", timeout: float | None = None,
        on_start: object = None,  # unused: no subprocess to hand to a ProcessRegistry (spec §60)
    ) -> tuple[WrapperResult, list[Finding]]:
        if not js_url:
            raise ValueError("js_analyzer requires js_url")
        _validate_js_url_in_scope(js_url, target)
        effective_timeout = timeout if timeout is not None else self.policy.timeout_seconds
        start = time.monotonic()
        try:
            req = urllib.request.Request(js_url, headers={"User-Agent": "security-toolkit-js-analyzer/1.0"})
            with urllib.request.urlopen(req, timeout=effective_timeout) as resp:  # noqa: S310 - internal, caller-controlled URL
                raw = resp.read(MAX_JS_BYTES + 1)
            text = raw[:MAX_JS_BYTES].decode("utf-8", errors="replace")
            exit_code, stderr = 0, ""
        except Exception as exc:  # noqa: BLE001 -- one unreachable bundle must not crash the Orchestrator
            duration = time.monotonic() - start
            result = WrapperResult(exit_code=1, stdout="", stderr=str(exc), timed_out=False, duration_seconds=duration)
            return result, []

        from crawler import extract_js_path_candidates  # local import: sys.path patched above

        path_candidates = extract_js_path_candidates(text, target.value)

        technologies: list[Technology] = []
        for name, pattern in _LIBRARY_PATTERNS:
            m = pattern.search(text)
            if m:
                technologies.append(
                    Technology(
                        product=name, version=m.group(1), category="js_library",
                        host=target.scope_host, evidence=js_url, source_scanner=self.module,
                        scan_id="",
                    )
                )

        findings: list[Finding] = []
        for secret_name, pattern in _SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(
                    Finding(
                        target=target.value, scanner=self.module, finding=f"클라이언트 JS에 노출된 {secret_name}",
                        severity=Severity.HIGH, host=target.scope_host, evidence=js_url,
                    )
                )

        payload = {
            "js_url": js_url, "path_candidates": path_candidates,
            "technologies": [t.to_dict() for t in technologies],
        }
        duration = time.monotonic() - start
        result = WrapperResult(
            exit_code=exit_code, stdout=json.dumps(payload, ensure_ascii=False), stderr=stderr,
            timed_out=False, duration_seconds=duration,
        )
        return result, findings

    def parse_result(self, result: WrapperResult, target: ScanTarget) -> list[Finding]:
        # run() above already produces Findings directly (no subprocess to
        # parse output from); this exists only to satisfy the ABC.
        return []
