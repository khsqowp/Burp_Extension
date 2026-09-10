"""Wraps E:\\temp\\tools\\gobuster_scanner\\gobuster_scanner.py (real
gobuster.exe dir mode + automatic wildcard-response detection, spec §28).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from storage.models import Finding, ScanTarget, Severity
from wrappers.base import ToolWrapper, WrapperResult

EXTERNAL_TOOLS_ROOT = Path(__file__).resolve().parents[3]
GOBUSTER_SCRIPT = EXTERNAL_TOOLS_ROOT / "gobuster_scanner" / "gobuster_scanner.py"

# spec §55: Raw Command 제한 -- 허용된 확장자 형식만 그대로 전달.
_ALLOWED_EXT_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.")


class GobusterWrapper(ToolWrapper):
    module = "gobuster"

    def build_command(
        self, target: ScanTarget, *, wordlist: str = "", wordlist_limit: int | None = None, extensions: str = ""
    ) -> list[str]:
        if not GOBUSTER_SCRIPT.exists():
            raise FileNotFoundError(f"gobuster_scanner.py not found at {GOBUSTER_SCRIPT}")
        if extensions and not all(c in _ALLOWED_EXT_CHARS for c in extensions):
            raise ValueError(f"invalid characters in extensions: {extensions!r}")
        # spec review finding (2026-09-06): same bypass as FfufWrapper -- only
        # clamped against a hardcoded 20000, not the real policy.max_request_count.
        effective_limit = min(wordlist_limit or self.policy.max_request_count, self.policy.max_request_count, 20000)
        argv = [
            sys.executable, str(GOBUSTER_SCRIPT), target.value,
            "--workers", str(min(self.policy.max_concurrent_requests, 20)),
            "--timeout", str(int(self.policy.timeout_seconds)),
            "--wordlist-limit", str(effective_limit),
            "--output", "json",
        ]
        if wordlist:
            argv += ["--wordlist", wordlist]
        if extensions:
            argv += ["--extensions", extensions]
        return argv

    def parse_result(self, result: WrapperResult, target: ScanTarget) -> list[Finding]:
        if result.exit_code != 0 or not result.stdout.strip():
            return []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []
        for hit in data.get("hits", []):
            status = hit.get("status", 0)
            # A redirect only proves routing behavior, not that the guessed
            # resource exists. Keep it in the raw gobuster JSON, but do not
            # promote it into the vulnerability/issues collection.
            if 300 <= status < 400:
                continue
            severity = Severity.MEDIUM if status in (401, 403) else Severity.LOW
            findings.append(
                Finding(
                    target=target.value, scanner=self.module, finding=f"[{status}] {hit.get('url', '')}",
                    severity=severity, host=target.scope_host, service="http",
                    evidence=f"size={hit.get('size')} redirect={hit.get('redirect')}",
                )
            )
        return findings
