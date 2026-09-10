"""Wrappers for the local, read-only HTTP and DNS audit modules."""

from __future__ import annotations

import json
import sys

from storage.models import Finding, ScanTarget, Severity
from wrappers.base import ToolWrapper, WrapperResult


class _SafeAuditWrapper(ToolWrapper):
    def build_command(self, target: ScanTarget, *, max_candidates: int = 20) -> list[str]:
        argv = [sys.executable, "-m", "scanners.safe_http_audit", target.value]
        if self.module in {"subdomain_discovery", "virtual_host_isolation"}:
            if not 1 <= int(max_candidates) <= 25:
                raise ValueError("max_candidates must be 1..25")
            argv += ["--max-candidates", str(max_candidates)]
        argv += ["--check", self.module]
        return argv

    def parse_result(self, result: WrapperResult, target: ScanTarget) -> list[Finding]:
        if result.exit_code != 0 or not result.stdout.strip():
            return []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []
        for item in data.get("findings", []):
            severity_text = str(item.get("severity", "info")).lower()
            try:
                severity = Severity(severity_text)
            except ValueError:
                severity = Severity.INFO
            findings.append(Finding(
                target=target.value, scanner=self.module,
                finding=str(item.get("message") or item.get("id") or item.get("classification") or "진단 결과"),
                severity=severity, host=target.scope_host,
                evidence=str(item.get("evidence") or item.get("hostname") or ""),
            ))
        return findings


class ErrorPageDisclosureWrapper(_SafeAuditWrapper):
    module = "error_page_disclosure"


class HttpMethodsWrapper(_SafeAuditWrapper):
    module = "http_methods"


class DirectoryListingWrapper(_SafeAuditWrapper):
    module = "directory_listing"


class ServerHeaderWrapper(_SafeAuditWrapper):
    module = "server_header"


class SecurityHeadersWrapper(_SafeAuditWrapper):
    module = "security_headers"


class SubdomainDiscoveryWrapper(_SafeAuditWrapper):
    module = "subdomain_discovery"


class VirtualHostIsolationWrapper(_SafeAuditWrapper):
    module = "virtual_host_isolation"


SAFE_AUDIT_WRAPPERS = (
    ErrorPageDisclosureWrapper, HttpMethodsWrapper, DirectoryListingWrapper,
    ServerHeaderWrapper, SecurityHeadersWrapper, SubdomainDiscoveryWrapper,
    VirtualHostIsolationWrapper,
)
