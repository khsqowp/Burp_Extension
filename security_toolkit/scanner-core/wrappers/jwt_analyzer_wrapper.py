"""Wraps E:\\temp\\tools\\jwt_analyzer\\jwt_analyzer.py (spec §38): structural
JWT analysis (alg=none, missing exp, kid/jku/x5u injection surface,
algorithm-confusion exposure) plus, optionally, the CPU-heavy piece spec §18
explicitly says belongs on the Scanner Core side rather than in the Burp
Extension itself -- local HMAC secret brute force against a wordlist.

`target.value` holds the JWT string itself, not a URL/host (spec §56's
ScanTarget.value docstring already allows for that: "host, host:port, or URL
depending on module"). This module never sends anything to a network target
-- it's SAFE-classified in safety.policy accordingly.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from storage.models import Finding, ScanTarget, Severity
from wrappers.base import ToolWrapper, WrapperResult

EXTERNAL_TOOLS_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = EXTERNAL_TOOLS_ROOT / "jwt_analyzer" / "jwt_analyzer.py"

_SEVERITY_MAP = {"VULNERABLE": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.INFO}


class JwtAnalyzerWrapper(ToolWrapper):
    module = "jwt_analyzer"

    def build_command(
        self, target: ScanTarget, *, crack_secret: bool = False, wordlist: str = "", limit: int = 0,
        gen_none: bool = False, confusion_pubkey: str = "", confusion_alg: str = "HS256",
    ) -> list[str]:
        if not SCRIPT.exists():
            raise FileNotFoundError(f"jwt_analyzer.py not found at {SCRIPT}")
        if not target.value:
            raise ValueError("jwt_analyzer requires a JWT string as the scan target")
        argv = [sys.executable, str(SCRIPT), target.value, "--output", "json"]
        if crack_secret:
            argv.append("--crack-secret")
            if wordlist:
                argv += ["--wordlist", wordlist]
            if limit:
                argv += ["--limit", str(limit)]
        if gen_none:
            argv.append("--gen-none")
        if confusion_pubkey:
            argv += ["--confusion-pubkey", confusion_pubkey, "--confusion-alg", confusion_alg]
        return argv

    def parse_result(self, result: WrapperResult, target: ScanTarget) -> list[Finding]:
        if result.exit_code != 0 or not result.stdout.strip():
            return []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        if "error" in data:
            return []

        findings: list[Finding] = []
        for f in data.get("findings", []):
            findings.append(
                Finding(
                    target=target.value, scanner=self.module, finding=f.get("message", ""),
                    severity=_SEVERITY_MAP.get(f.get("severity", "INFO"), Severity.INFO),
                    evidence=json.dumps(data.get("header", {}), ensure_ascii=False),
                )
            )

        crack = data.get("crack_secret")
        if crack and crack.get("found") is not None:
            findings.append(
                Finding(
                    target=target.value, scanner=self.module,
                    finding=f"Weak HMAC secret cracked: {crack['found']!r}",
                    severity=Severity.HIGH, evidence=f"tried {crack.get('tried')} word(s) from {crack.get('wordlist')}",
                )
            )
        return findings
