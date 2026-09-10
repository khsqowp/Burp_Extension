"""CVE Matcher (spec §31): Technology list -> Finding list, using the Local
CVE Database only (never a live network lookup, per spec §4.1's "진단 중
외부 통신 금지"). A match never triggers automatic exploitation (spec §31)
-- it only produces an informational/risk Finding for a human to review.
"""

from __future__ import annotations

from storage.cve_db import CveDB
from storage.models import Finding, Severity, Technology
from matchers.version_utils import version_less_than

_SEVERITY_MAP = {"medium": Severity.MEDIUM, "high": Severity.HIGH}


def match(technologies: list[Technology], cve_db: CveDB) -> list[Finding]:
    rules = cve_db.list_rules()
    findings: list[Finding] = []
    for tech in technologies:
        if not tech.version:
            continue
        product_lower = tech.product.lower()
        for rule in rules:
            if rule["product_substr"] not in product_lower:
                continue
            if not version_less_than(tech.version, rule["max_safe_version"]):
                continue
            cve_refs = ", ".join(rule["cve_ids"])
            findings.append(
                Finding(
                    target=tech.host, scanner="cve_matcher", finding=rule["note"],
                    severity=_SEVERITY_MAP.get(rule["severity"], Severity.MEDIUM),
                    host=tech.host, port=tech.port, technology=f"{tech.product} {tech.version}",
                    evidence=f"CVE: {cve_refs}" if cve_refs else "특정 CVE ID 없음 -- 버전 직접 확인 권장",
                    scan_id=tech.scan_id,
                )
            )
    return findings
