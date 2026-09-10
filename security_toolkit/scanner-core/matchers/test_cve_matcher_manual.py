import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from matchers import cve_matcher
from matchers.version_utils import parse_version, version_less_than
from storage.cve_db import CveDB
from storage.models import Severity, Technology

# -- version comparison -------------------------------------------------------
assert parse_version("2.4.49") == (2, 4, 49)
assert parse_version("9.6p1") == (9, 6, 1)
assert version_less_than("2.4.49", "2.4.51")
assert not version_less_than("2.4.52", "2.4.51")
assert version_less_than("2.4", "2.4.1")
assert not version_less_than("2.5", "2.4.51")
print("version_utils OK")

# -- CveDB seeding + reopen persistence ---------------------------------------
tmp_db = Path(tempfile.mkdtemp()) / "cve.sqlite"
db = CveDB(tmp_db)
rules = db.list_rules()
print("seeded rule count:", len(rules))
assert len(rules) == 15
assert any(r["product_substr"] == "apache httpd" for r in rules)
db.close()

db2 = CveDB(tmp_db)  # reopen -- must not re-seed/duplicate
assert len(db2.list_rules()) == 15
print("reopen (no duplicate reseed) OK")

# -- matcher: real vulnerable version -----------------------------------------
techs = [
    Technology(product="Apache httpd", version="2.4.49", host="example.com", port=443, scan_id="scan-1"),
    Technology(product="Apache httpd", version="2.4.52", host="example.com", port=8443, scan_id="scan-1"),  # patched
    Technology(product="nginx", version="1.18.0", host="example.com", port=80, scan_id="scan-1"),  # old, no CVE id
    Technology(product="OpenSSH", version="9.6", host="example.com", port=22, scan_id="scan-1"),  # current, safe
    Technology(product="TotallyUnknownThing", version="1.0", host="example.com", scan_id="scan-1"),  # no rule at all
]
findings = cve_matcher.match(techs, db2)
print("findings:", [(f.finding, f.severity.value, f.technology, f.evidence) for f in findings])
assert len(findings) == 2, "expected exactly Apache 2.4.49 (vulnerable) and nginx 1.18.0 (old, no CVE) to match"

apache_finding = next(f for f in findings if "Apache" in f.technology)
assert apache_finding.severity == Severity.HIGH
assert "CVE-2021-41773" in apache_finding.evidence
assert apache_finding.port == 443
assert apache_finding.scan_id == "scan-1"

nginx_finding = next(f for f in findings if "nginx" in f.technology)
assert nginx_finding.severity == Severity.MEDIUM
assert "특정 CVE ID 없음" in nginx_finding.evidence

assert not any("2.4.52" in f.technology for f in findings), "patched version must not match"
assert not any("OpenSSH" in f.technology for f in findings), "current OpenSSH version must not match"
assert not any("TotallyUnknownThing" in f.technology for f in findings), "unregistered product must not match"

print("\nALL CVE MATCHER TESTS OK")
