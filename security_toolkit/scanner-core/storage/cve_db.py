"""Local CVE Database (spec §31, §39: cve.sqlite) -- product/version rules
seeded from infra_vuln_scanner.py's own already-vetted VERSION_RULES table
(spec §5.3: external data goes through review/filtering before use; these
rules were already reviewed when that tool was built, so they're reused
as-is rather than re-deriving or fabricating new CVE entries). Only CVEs
with a real CVE ID list are treated as HIGH; the vaguer "verify manually"
notes without a specific CVE stay MEDIUM (spec §31: CVE 존재를 이유로
자동 판정을 과신하지 않는다).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cve_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_substr TEXT NOT NULL,
    max_safe_version TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    cve_ids TEXT NOT NULL DEFAULT '[]',
    severity TEXT NOT NULL DEFAULT 'medium'
);
"""

# Reused verbatim from infra_vuln_scanner.py's VERSION_RULES (spec §63 버전
# 관리 -- source noted here so a future refresh knows where this came from).
SEED_RULES: list[dict] = [
    {"product_substr": "apache httpd", "max_safe_version": "2.4.51", "note": "2.4.49/2.4.50 경로 순회+RCE", "cve_ids": ["CVE-2021-41773", "CVE-2021-42013"], "severity": "high"},
    {"product_substr": "openssh", "max_safe_version": "7.4", "note": "구버전 OpenSSH: 사용자 열거", "cve_ids": ["CVE-2018-15473"], "severity": "high"},
    {"product_substr": "apache tomcat", "max_safe_version": "9.0.31", "note": "구버전 Tomcat: AJP Ghostcat", "cve_ids": ["CVE-2020-1938"], "severity": "high"},
    {"product_substr": "exim smtpd", "max_safe_version": "4.94", "note": "구버전 Exim 다수 RCE", "cve_ids": ["CVE-2019-10149"], "severity": "high"},
    {"product_substr": "samba smbd", "max_safe_version": "4.11.0", "note": "구버전 Samba(SambaCry)", "cve_ids": ["CVE-2017-7494"], "severity": "high"},
    {"product_substr": "nginx", "max_safe_version": "1.21.0", "note": "구버전 nginx는 여러 알려진 CVE 대상 (버전별로 상이, 직접 확인 필요)", "cve_ids": [], "severity": "medium"},
    {"product_substr": "vsftpd", "max_safe_version": "3.0.3", "note": "vsftpd 2.3.4는 악명 높은 백도어 포함 버전(별도 확인 권장)", "cve_ids": [], "severity": "medium"},
    {"product_substr": "proftpd", "max_safe_version": "1.3.6", "note": "구버전 ProFTPD 다수 RCE/정보노출 취약점", "cve_ids": [], "severity": "medium"},
    {"product_substr": "mysql", "max_safe_version": "5.7.0", "note": "EOL/구버전 MySQL — 다수 CVE 존재, 직접 버전 확인 권장", "cve_ids": [], "severity": "medium"},
    {"product_substr": "mariadb", "max_safe_version": "10.3.0", "note": "구버전 MariaDB — 다수 CVE 존재, 직접 버전 확인 권장", "cve_ids": [], "severity": "medium"},
    {"product_substr": "php", "max_safe_version": "7.4.0", "note": "EOL PHP — 보안 패치 미제공", "cve_ids": [], "severity": "medium"},
    {"product_substr": "microsoft iis", "max_safe_version": "10.0", "note": "구버전 IIS — WebDAV 등 다수 취약점 이력", "cve_ids": [], "severity": "medium"},
    {"product_substr": "redis", "max_safe_version": "6.0.0", "note": "인증 없는 구버전 Redis는 원격 코드 실행으로 이어진 사례 다수", "cve_ids": [], "severity": "medium"},
    {"product_substr": "elasticsearch", "max_safe_version": "7.0.0", "note": "구버전 Elasticsearch — 인증 미설정 시 데이터 노출/RCE 이력", "cve_ids": [], "severity": "medium"},
    {"product_substr": "postgresql", "max_safe_version": "12.0", "note": "EOL 근접/구버전 PostgreSQL — 직접 버전별 CVE 확인 권장", "cve_ids": [], "severity": "medium"},
]


class CveDB:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._seed_if_empty()

    def _seed_if_empty(self) -> None:
        count = self._conn.execute("SELECT COUNT(*) FROM cve_rules").fetchone()[0]
        if count > 0:
            return
        for rule in SEED_RULES:
            self._conn.execute(
                "INSERT INTO cve_rules (product_substr, max_safe_version, note, cve_ids, severity) "
                "VALUES (?, ?, ?, ?, ?)",
                (rule["product_substr"], rule["max_safe_version"], rule["note"],
                 json.dumps(rule["cve_ids"], ensure_ascii=False), rule["severity"]),
            )
        self._conn.commit()

    def list_rules(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM cve_rules").fetchall()
        return [
            {
                "product_substr": r["product_substr"], "max_safe_version": r["max_safe_version"],
                "note": r["note"], "cve_ids": json.loads(r["cve_ids"]), "severity": r["severity"],
            }
            for r in rows
        ]

    def close(self) -> None:
        self._conn.close()
