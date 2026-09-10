"""Wraps E:\\temp\\tools\\default_content_scanner\\default_content_scanner.py.

The underlying script handles both default/backup-file fingerprinting AND
path-traversal fuzzing behind different flags, but spec §37 explicitly
splits them into two independently-policied modules ("Recon · Default
Content Scanner" vs "Scanner · Path Traversal", "Path Traversal은 실제 입력
변조 기반 취약점 테스트이므로 독립적인 Safety Policy를 적용한다") -- so this
file registers two separate ToolWrapper subclasses, each invoking the same
script with a fixed, non-overlapping flag set, sharing only the JSON-result
parsing logic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from storage.models import Finding, ScanTarget, Severity
from wrappers.base import ToolWrapper, WrapperResult

EXTERNAL_TOOLS_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = EXTERNAL_TOOLS_ROOT / "default_content_scanner" / "default_content_scanner.py"


def _parse_hits(result: WrapperResult, target: ScanTarget, scanner_name: str) -> list[Finding]:
    if result.exit_code != 0 or not result.stdout.strip():
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    for item in data:
        if not item.get("hit"):
            continue
        category = item.get("category", "")
        # spec §37: traversal/LFI 성공은 백업/기본 파일 노출보다 심각도가 높다.
        severity = Severity.HIGH if category == "traversal" else Severity.MEDIUM
        findings.append(
            Finding(
                target=target.value, scanner=scanner_name, finding=f"{category}: {item.get('url', '')}",
                severity=severity, host=target.scope_host, evidence=str(item.get("matched_signature") or ""),
            )
        )
    return findings


class DefaultContentWrapper(ToolWrapper):
    module = "default_content"

    def build_command(
        self, target: ScanTarget, *, tech: str = "tomcat,apache,nginx", mutate: bool = False
    ) -> list[str]:
        if not SCRIPT.exists():
            raise FileNotFoundError(f"default_content_scanner.py not found at {SCRIPT}")
        argv = [
            sys.executable, str(SCRIPT), target.value,
            "--tech", tech,
            "--max-requests", str(self.policy.max_request_count),
            "--timeout", str(int(self.policy.timeout_seconds)),
            "--retries", str(self.policy.retry_count),
            "--min-interval", str(1.0 / self.policy.max_requests_per_second),
            "--output", "json",
        ]
        if mutate:
            argv.append("--mutate")
        return argv

    def parse_result(self, result: WrapperResult, target: ScanTarget) -> list[Finding]:
        return _parse_hits(result, target, self.module)


class PathTraversalWrapper(ToolWrapper):
    module = "path_traversal"

    def build_command(
        self, target: ScanTarget, *, param: str = "", url_template: bool = False, target_os: str = "both"
    ) -> list[str]:
        if not SCRIPT.exists():
            raise FileNotFoundError(f"default_content_scanner.py not found at {SCRIPT}")
        if not param and not url_template:
            raise ValueError("path_traversal requires either 'param' or 'url_template=True'")
        argv = [
            sys.executable, str(SCRIPT), target.value,
            "--no-fingerprint", "--traversal",
            "--target-os", target_os,
            "--traversal-limit", str(min(self.policy.max_request_count, 300)),
            "--timeout", str(int(self.policy.timeout_seconds)),
            "--retries", str(self.policy.retry_count),
            "--min-interval", str(1.0 / self.policy.max_requests_per_second),
            "--output", "json",
        ]
        if param:
            argv += ["--param", param]
        if url_template:
            argv.append("--url-template")
        return argv

    def parse_result(self, result: WrapperResult, target: ScanTarget) -> list[Finding]:
        return _parse_hits(result, target, self.module)
