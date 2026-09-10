"""Version Manifest (spec §63-64) -- records which data/tool versions were
active for a given Scan, so a result can be re-analyzed later knowing
exactly what produced it (spec §64's own worked example: "Scan #1004 / CVE
DB 2026-09-01 / EOL DB 2026-09-01 / Dictionary v1.3 / Scanner Core v0.1.0").

Honesty note: none of the wrapped external tools (ffuf/gobuster/nmap/the
in-house *_scanner.py scripts) currently expose a clean --version we could
capture generically here -- adding that is future work, not silently
faked. What IS genuinely available today is captured: the Scanner Core's
own version, and a content fingerprint of the CVE/EOL seed-rule tables
(these have no independent version number of their own, so a count + hash
of their current content is the honest stand-in for "which revision of
this data was used").
"""

from __future__ import annotations

import hashlib
import json

SCANNER_CORE_VERSION = "0.1.0"  # spec §63 -- kept in step with api/main.py's FastAPI(version=...)


def _hash_rules(rules: list[dict]) -> str:
    canonical = json.dumps(rules, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def build_version_manifest(cve_db=None, eol_db=None) -> dict:
    manifest: dict = {"scanner_core_version": SCANNER_CORE_VERSION}
    if cve_db is not None:
        rules = cve_db.list_rules()
        manifest["cve_db"] = {"rule_count": len(rules), "content_fingerprint": _hash_rules(rules)}
    if eol_db is not None:
        rules = eol_db.list_rules()
        manifest["eol_db"] = {"rule_count": len(rules), "content_fingerprint": _hash_rules(rules)}
    return manifest
