"""Reference Tool Wrapper implementation, wrapping the already-validated
E:\\temp\\tools\\ssl_tls_scanner script (reused as-is per the standing
decision to not duplicate already-working scanner logic). Also serves as
the end-to-end proof that the ToolWrapper interface actually works against
a real external tool, not just a mock.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

from storage.models import Finding, ScanTarget, Severity
from wrappers.base import ToolWrapper, WrapperResult

# security_toolkit/scanner-core/wrappers/ -> parents[3] == E:\temp\tools
EXTERNAL_TOOLS_ROOT = Path(__file__).resolve().parents[3]
SSL_TLS_SCRIPT = EXTERNAL_TOOLS_ROOT / "ssl_tls_scanner" / "main.py"

# spec §12: "none" severity 응답(PASS 등)은 문제로 취급하지 않는다 -- 실제
# 발견된 이슈(low/medium/high)만 Finding으로 승격한다.
_SEVERITY_MAP = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH}


class SSLTLSWrapper(ToolWrapper):
    module = "ssl_tls"

    def build_command(self, target: ScanTarget, *, port: int | None = None) -> list[str]:
        if not SSL_TLS_SCRIPT.exists():
            raise FileNotFoundError(f"ssl_tls_scanner not found at {SSL_TLS_SCRIPT}")
        if port is None:
            parsed = urlsplit(target.value if "://" in target.value else f"//{target.value}")
            port = parsed.port or (443 if parsed.scheme == "https" else 443)
        return [
            sys.executable, str(SSL_TLS_SCRIPT), target.scope_host or target.value,
            "--port", str(port),
            "--timeout", str(int(self.policy.timeout_seconds)),
            "--output", "json",
        ]

    def parse_result(self, result: WrapperResult, target: ScanTarget) -> list[Finding]:
        if result.exit_code != 0 or not result.stdout.strip():
            return []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []
        for item in data.get("findings", []):
            severity = _SEVERITY_MAP.get(item.get("severity", "none"))
            if severity is None:
                continue  # "none"/unrecognized -- not an issue, skip
            findings.append(
                Finding(
                    target=target.value, scanner=self.module, finding=item.get("name", ""),
                    severity=severity, host=data.get("ip", "") or target.scope_host,
                    port=data.get("port"), protocol="tls", service="https",
                    evidence=item.get("evidence", ""), timestamp=data.get("finished_at", ""),
                )
            )
        return findings
