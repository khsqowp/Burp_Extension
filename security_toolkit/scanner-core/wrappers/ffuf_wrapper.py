"""Wraps E:\\temp\\tools\\ffuf_scanner\\ffuf_scanner.py (real ffuf.exe +
automatic baseline/wildcard-response detection, spec §27).

Note: ffuf_scanner.py used to print its live-progress commentary
([기준 응답 감지]/[진행]/[발견]/[완료]) to stdout even in --output json
mode, corrupting the JSON stream on stdout -- fixed at the source (moved to
stderr) while building this wrapper, matching the JSON-only-on-stdout
contract every other tool in this toolkit already follows.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from storage.models import Finding, ScanTarget, Severity
from wrappers.base import ToolWrapper, WrapperResult

EXTERNAL_TOOLS_ROOT = Path(__file__).resolve().parents[3]
FFUF_SCRIPT = EXTERNAL_TOOLS_ROOT / "ffuf_scanner" / "ffuf_scanner.py"

# spec §55: Raw Command 제한 -- 사용자는 미리 정의된 옵션만 고르고, 실제
# ffuf 인자는 이 Wrapper가 조립한다. 여기서는 허용된 확장자 형식만 그대로
# 전달(문자/숫자/콤마만), 임의 문자열을 셸/ffuf에 주입하지 않는다.
_ALLOWED_EXT_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.")


class FfufWrapper(ToolWrapper):
    module = "ffuf"

    def build_command(
        self, target: ScanTarget, *, wordlist: str = "", wordlist_limit: int | None = None,
        extensions: str = "", match_codes: str = "",
    ) -> list[str]:
        if not FFUF_SCRIPT.exists():
            raise FileNotFoundError(f"ffuf_scanner.py not found at {FFUF_SCRIPT}")
        if extensions and not all(c in _ALLOWED_EXT_CHARS for c in extensions):
            raise ValueError(f"invalid characters in extensions: {extensions!r}")
        url = target.value if "FUZZ" in target.value else target.value.rstrip("/") + "/FUZZ"
        # spec review finding (2026-09-06): a caller-supplied wordlist_limit
        # only clamped against a hardcoded 20000 ceiling, not against the
        # actual configured policy.max_request_count -- e.g. policy default
        # 500 was bypassable up to 20000 just by passing wordlist_limit=15000.
        effective_limit = min(wordlist_limit or self.policy.max_request_count, self.policy.max_request_count, 20000)
        argv = [
            sys.executable, str(FFUF_SCRIPT), url,
            "--workers", str(min(self.policy.max_concurrent_requests, 20)),
            "--timeout", str(int(self.policy.timeout_seconds)),
            "--wordlist-limit", str(effective_limit),
            "--output", "json",
        ]
        if wordlist:
            argv += ["--wordlist", wordlist]
        if extensions:
            argv += ["--extensions", extensions]
        if match_codes:
            argv += ["--match-codes", match_codes]
        return argv

    def parse_result(self, result: WrapperResult, target: ScanTarget) -> list[Finding]:
        if result.exit_code != 0 or not result.stdout.strip():
            return []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []
        for hit in data.get("actionable_results", []):
            status = hit.get("status", 0)
            # Redirects remain available in the raw ffuf artifact. They are
            # observations, not vulnerabilities, until the destination is
            # fetched and independently shown to expose something sensitive.
            if 300 <= status < 400:
                continue
            # spec §12/§61: 200대는 정상 발견(정보성), 401/403은 접근통제
            # 관련이라 좀 더 눈에 띄게, 3xx는 낮게 -- 과도한 심각도 확대는
            # 하지 않는다 (실제 취약점 판정은 별도 CVE/취약점 스캐너 몫).
            if status in (401, 403):
                severity = Severity.MEDIUM
            elif 200 <= status < 300:
                severity = Severity.LOW
            else:
                severity = Severity.INFO
            findings.append(
                Finding(
                    target=target.value, scanner=self.module, finding=f"[{status}] {hit.get('url', '')}",
                    severity=severity, host=target.scope_host, service="http",
                    evidence=f"length={hit.get('length')} content_type={hit.get('content_type', '')}",
                )
            )
        return findings
