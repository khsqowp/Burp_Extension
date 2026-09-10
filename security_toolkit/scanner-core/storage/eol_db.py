"""Local EOS/EOL Database (spec §32, §39: eol.sqlite). Seeded with a small,
hand-curated set of well-documented public EOL dates (each is common,
widely-published vendor lifecycle information, not derived from any live
lookup at scan time -- spec §4.1 진단 중 외부 통신 금지 applies to scan
time, not to how this seed table itself was written).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS eol_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_substr TEXT NOT NULL,
    version_prefix TEXT NOT NULL,
    eol_date TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT ''
);
"""

SEED_RULES: list[dict] = [
    {"product_substr": "php", "version_prefix": "5.6", "eol_date": "2018-12-31", "note": "PHP 5.6 EOL"},
    {"product_substr": "php", "version_prefix": "7.0", "eol_date": "2019-01-10", "note": "PHP 7.0 EOL"},
    {"product_substr": "php", "version_prefix": "7.1", "eol_date": "2019-12-01", "note": "PHP 7.1 EOL"},
    {"product_substr": "php", "version_prefix": "7.2", "eol_date": "2020-11-30", "note": "PHP 7.2 EOL"},
    {"product_substr": "php", "version_prefix": "7.3", "eol_date": "2021-12-06", "note": "PHP 7.3 EOL"},
    {"product_substr": "php", "version_prefix": "7.4", "eol_date": "2022-11-28", "note": "PHP 7.4 EOL"},
    {"product_substr": "openssh", "version_prefix": "7.4", "eol_date": "2020-01-01", "note": "OpenSSH 7.x 계열, 최신 배포판에서 지원 종료된 branch"},
    {"product_substr": "openssl", "version_prefix": "1.0.2", "eol_date": "2019-12-31", "note": "OpenSSL 1.0.2 EOL"},
    {"product_substr": "openssl", "version_prefix": "1.1.0", "eol_date": "2019-09-11", "note": "OpenSSL 1.1.0 EOL"},
    {"product_substr": "mysql", "version_prefix": "5.6", "eol_date": "2021-02-05", "note": "MySQL 5.6 EOL"},
    {"product_substr": "mysql", "version_prefix": "5.7", "eol_date": "2023-10-31", "note": "MySQL 5.7 EOL"},
    {"product_substr": "apache tomcat", "version_prefix": "8.5", "eol_date": "2024-03-31", "note": "Tomcat 8.5 EOL"},
    {"product_substr": "apache tomcat", "version_prefix": "7", "eol_date": "2021-03-31", "note": "Tomcat 7 EOL"},
    {"product_substr": "nginx", "version_prefix": "1.16", "eol_date": "2020-04-21", "note": "nginx 1.16(mainline 이전) 지원 종료"},
]


class EolDB:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._seed_if_empty()

    def _seed_if_empty(self) -> None:
        count = self._conn.execute("SELECT COUNT(*) FROM eol_rules").fetchone()[0]
        if count > 0:
            return
        for rule in SEED_RULES:
            self._conn.execute(
                "INSERT INTO eol_rules (product_substr, version_prefix, eol_date, note) VALUES (?, ?, ?, ?)",
                (rule["product_substr"], rule["version_prefix"], rule["eol_date"], rule["note"]),
            )
        self._conn.commit()

    def list_rules(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM eol_rules").fetchall()
        return [
            {"product_substr": r["product_substr"], "version_prefix": r["version_prefix"],
             "eol_date": r["eol_date"], "note": r["note"]}
            for r in rows
        ]

    def close(self) -> None:
        self._conn.close()
