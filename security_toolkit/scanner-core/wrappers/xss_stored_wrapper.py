"""Wraps E:\\temp\\tools\\xss_stored_scanner\\xss_stored_scanner.py (spec
§36): marker-based Stored XSS -- inject on one page, check exactly one
other page for the stored marker. Same result schema as
XssReflectedWrapper (its "phase 2" check is the same find_reflections
logic against the check page), so parse_result mirrors it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from storage.models import Finding, ScanTarget, Severity
from wrappers.base import ToolWrapper, WrapperResult

EXTERNAL_TOOLS_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = EXTERNAL_TOOLS_ROOT / "xss_stored_scanner" / "xss_stored_scanner.py"

_SEVERITY_MAP = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


class XssStoredWrapper(ToolWrapper):
    module = "xss_stored"

    def build_command(
        self, target: ScanTarget, *, check_url: str = "", params: str = "", cookie_params: str = "",
        header_params: str = "", method: str = "post-form", bypass_variants: str = "",
    ) -> list[str]:
        if not SCRIPT.exists():
            raise FileNotFoundError(f"xss_stored_scanner.py not found at {SCRIPT}")
        if not check_url:
            raise ValueError("xss_stored requires check_url")
        if not params and not cookie_params and not header_params:
            raise ValueError("xss_stored requires at least one of params/cookie_params/header_params")
        argv = [
            sys.executable, str(SCRIPT), target.value,
            "--check-url", check_url,
            "--method", method,
            "--timeout", str(int(self.policy.timeout_seconds)),
            "--min-interval", str(1.0 / self.policy.max_requests_per_second),
            "--output", "json",
        ]
        if params:
            argv += ["--params", params]
        if cookie_params:
            argv += ["--cookie-params", cookie_params]
        if header_params:
            argv += ["--header-params", header_params]
        if bypass_variants:
            argv += ["--bypass-variants", bypass_variants]
        return argv

    def parse_result(self, result: WrapperResult, target: ScanTarget) -> list[Finding]:
        if result.exit_code != 0 or not result.stdout.strip():
            return []
        try:
            hits = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []
        for hit in hits:
            findings.append(
                Finding(
                    target=target.value, scanner=self.module,
                    finding=f"Stored XSS via '{hit.get('param', '')}' ({hit.get('context', '')})",
                    severity=_SEVERITY_MAP.get(hit.get("risk", "LOW"), Severity.LOW),
                    host=target.scope_host, service="http",
                    evidence=hit.get("snippet", ""),
                )
            )
        return findings
