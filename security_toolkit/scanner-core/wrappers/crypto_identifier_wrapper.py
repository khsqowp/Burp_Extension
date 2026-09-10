"""Wraps E:\\temp\\tools\\crypto_identifier\\crypto_identifier.py (spec §38):
auto-decodes a suspicious value (base64/base64url/hex/base32/URL-encoding/
rot13 chains) and identifies likely hash/crypt formats, optionally running a
local dictionary crack for fast unsalted digests -- the CPU-heavy piece spec
§18 says belongs on the Scanner Core side, not the Burp Extension itself.

`target.value` holds the suspicious string itself, not a URL/host (same
convention as JwtAnalyzerWrapper). Never touches a network target -- SAFE in
safety.policy.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from storage.models import Finding, ScanTarget, Severity
from wrappers.base import ToolWrapper, WrapperResult

EXTERNAL_TOOLS_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = EXTERNAL_TOOLS_ROOT / "crypto_identifier" / "crypto_identifier.py"


class CryptoIdentifierWrapper(ToolWrapper):
    module = "crypto_identifier"

    def build_command(self, target: ScanTarget, *, crack: bool = False, wordlist: str = "", limit: int = 0) -> list[str]:
        if not SCRIPT.exists():
            raise FileNotFoundError(f"crypto_identifier.py not found at {SCRIPT}")
        if not target.value:
            raise ValueError("crypto_identifier requires a value string as the scan target")
        argv = [sys.executable, str(SCRIPT), target.value, "--output", "json"]
        if crack:
            argv.append("--crack")
            if wordlist:
                argv += ["--wordlist", wordlist]
            if limit:
                argv += ["--limit", str(limit)]
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
        for chain in data.get("decode_chains", []):
            result_text = chain.get("result", "")
            preview = result_text if len(result_text) <= 200 else result_text[:200] + "..."
            findings.append(
                Finding(
                    target=target.value, scanner=self.module,
                    finding=f"Decoded via {chain.get('path', '')}", severity=Severity.INFO, evidence=preview,
                )
            )
        for guess in data.get("hash_guesses", []):
            findings.append(
                Finding(
                    target=target.value, scanner=self.module,
                    finding=f"Possible hash format: {guess.get('name', '')} ({guess.get('confidence', '')})",
                    severity=Severity.INFO,
                )
            )
        for cr in data.get("crack_results", []):
            if cr.get("found") is not None:
                findings.append(
                    Finding(
                        target=target.value, scanner=self.module,
                        finding=f"Weak hash cracked: {cr['found']!r} ({cr.get('name', '')})",
                        severity=Severity.HIGH,
                        evidence=f"tried {cr.get('tried')} word(s) from {cr.get('wordlist')}",
                    )
                )
        return findings
