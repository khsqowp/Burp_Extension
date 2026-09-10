"""Wraps E:\\temp\\tools\\infra_vuln_scanner\\infra_vuln_scanner.py (nmap
-sV + NSE vuln scripts + a local product/version-vs-CVE heuristic table,
spec §29-§31).

A plain open port with a detected product/version is NOT itself promoted to
a Finding here -- that's raw fingerprint data for the future Local CVE
Matcher (spec §31, Phase 3) to consume via raw_ref, same philosophy as
CrawlerWrapper. Only two signals the underlying tool itself already
assessed as security-relevant become Findings: real NSE vuln-script hits,
and its own version_rule_hits table (which already carries real CVE IDs).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from storage.models import Finding, ScanTarget, Severity
from wrappers.base import ToolWrapper, WrapperResult

EXTERNAL_TOOLS_ROOT = Path(__file__).resolve().parents[3]
INFRA_VULN_SCRIPT = EXTERNAL_TOOLS_ROOT / "infra_vuln_scanner" / "infra_vuln_scanner.py"


class InfraVulnWrapper(ToolWrapper):
    module = "infra_vuln"

    def build_command(
        self, target: ScanTarget, *, ports: str = "", top_ports: int | None = None, no_vuln_scripts: bool = False
    ) -> list[str]:
        if not INFRA_VULN_SCRIPT.exists():
            raise FileNotFoundError(f"infra_vuln_scanner.py not found at {INFRA_VULN_SCRIPT}")
        argv = [
            sys.executable, str(INFRA_VULN_SCRIPT), target.scope_host or target.value,
            "--nmap-timeout", str(int(self.policy.max_scan_duration_seconds)),
            "--output", "json",
        ]
        if ports:
            argv += ["--ports", ports]
        elif top_ports is not None:
            argv += ["--top-ports", str(top_ports)]
        if no_vuln_scripts:
            argv.append("--no-vuln-scripts")
        return argv

    def parse_result(self, result: WrapperResult, target: ScanTarget) -> list[Finding]:
        if result.exit_code != 0 or not result.stdout.strip():
            return []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []
        for port_result in data:
            port = port_result.get("port")
            service = port_result.get("service_name", "")
            for sf in port_result.get("script_findings", []):
                findings.append(
                    Finding(
                        target=target.value, scanner=self.module,
                        finding=f"{sf.get('script_id', '')} ({sf.get('state', '')})",
                        severity=Severity.HIGH, host=target.scope_host, port=port,
                        protocol=port_result.get("protocol", "tcp"), service=service,
                        evidence=str(sf.get("output", "")),
                    )
                )
            for vr in port_result.get("version_rule_hits", []):
                cve_refs = ", ".join(vr.get("cve_refs", []))
                findings.append(
                    Finding(
                        target=target.value, scanner=self.module, finding=vr.get("note", ""),
                        severity=Severity.HIGH, host=target.scope_host, port=port,
                        protocol=port_result.get("protocol", "tcp"), service=service,
                        evidence=f"CVE: {cve_refs}" if cve_refs else "",
                    )
                )
        return findings
