import sys
import tempfile
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from matchers import eol_matcher
from storage.eol_db import EolDB
from storage.models import Severity, Technology

tmp_db = Path(tempfile.mkdtemp()) / "eol.sqlite"
db = EolDB(tmp_db)
rules = db.list_rules()
print("seeded rule count:", len(rules))
assert len(rules) == 14
db.close()
db2 = EolDB(tmp_db)
assert len(db2.list_rules()) == 14
print("reopen (no duplicate reseed) OK")

techs = [
    Technology(product="PHP", version="7.4.33", host="example.com", port=443, scan_id="scan-1"),  # long past EOL
    Technology(product="PHP", version="8.2.0", host="example.com", port=8443, scan_id="scan-1"),  # not EOL (no rule)
    Technology(product="OpenSSL", version="1.0.2u", host="example.com", port=443, scan_id="scan-1"),  # past EOL
    Technology(product="MySQL", version="5.7.44", host="example.com", port=3306, scan_id="scan-1"),  # past EOL as of "today"
    Technology(product="TotallyUnknownThing", version="1.0", host="example.com", scan_id="scan-1"),
]

findings = eol_matcher.match(techs, db2)
print("findings (real 'today'):", [(f.finding, f.technology) for f in findings])
assert any("PHP 7.4.33" in f.technology for f in findings)
assert any("OpenSSL 1.0.2u" in f.technology for f in findings)
assert not any("PHP 8.2.0" in f.technology for f in findings)
assert not any("TotallyUnknownThing" in f.technology for f in findings)
assert all(f.severity == Severity.MEDIUM for f in findings)

# -- future-EOL rule must NOT produce a finding (deterministic via injected `today`) --
future_findings = eol_matcher.match(
    [Technology(product="MySQL", version="5.7.44", host="h", scan_id="s")],
    db2, today=date(2020, 1, 1),  # before MySQL 5.7's 2023-10-31 EOL
)
print("findings with today=2020-01-01:", future_findings)
assert future_findings == [], "a version not yet EOL as of the given date must not be flagged"

print("\nALL EOL MATCHER TESTS OK")
