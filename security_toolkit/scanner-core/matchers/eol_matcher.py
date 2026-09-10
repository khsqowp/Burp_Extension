"""EOS/EOL Matcher (spec §32): Technology list -> Finding list, using only
the Local EOS/EOL Database (spec §4.1: no live lookup at scan time). A
Technology only becomes a Finding once its matched rule's eol_date has
actually passed as of today -- a product that will reach EOL in the future
isn't itself a current issue yet.
"""

from __future__ import annotations

from datetime import date, datetime

from matchers.version_utils import parse_version
from storage.eol_db import EolDB
from storage.models import Finding, Severity, Technology


def _version_matches_prefix(version: str, prefix: str) -> bool:
    v, p = parse_version(version), parse_version(prefix)
    return v[: len(p)] == p


def match(technologies: list[Technology], eol_db: EolDB, *, today: date | None = None) -> list[Finding]:
    today = today or datetime.now().date()
    rules = eol_db.list_rules()
    findings: list[Finding] = []
    for tech in technologies:
        if not tech.version:
            continue
        product_lower = tech.product.lower()
        for rule in rules:
            if rule["product_substr"] not in product_lower:
                continue
            if not _version_matches_prefix(tech.version, rule["version_prefix"]):
                continue
            eol_date = datetime.strptime(rule["eol_date"], "%Y-%m-%d").date()
            if eol_date > today:
                continue  # not EOL yet -- not a current issue
            findings.append(
                Finding(
                    target=tech.host, scanner="eol_matcher", finding=f"{rule['note']} ({rule['eol_date']} EOL)",
                    severity=Severity.MEDIUM, host=tech.host, port=tech.port,
                    technology=f"{tech.product} {tech.version}",
                    evidence=f"EOL 이후 {(today - eol_date).days}일 경과 -- 보안 패치 미제공 가능성",
                    scan_id=tech.scan_id,
                )
            )
    return findings
