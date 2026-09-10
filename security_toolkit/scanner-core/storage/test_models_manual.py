import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from storage.models import Finding, ScanRecord, ScanTarget, Severity, TaskRecord, TaskStatus

# Finding round-trip
f = Finding(
    target="https://example.com", scanner="ffuf", finding="Exposed backup file /site.zip",
    severity=Severity.HIGH, host="example.com", port=443, protocol="https",
    service="http", technology="nginx", evidence="200 OK, 1024 bytes",
    timestamp="2026-09-05T12:00:00Z", scan_id="scan-abc", task_id="task-1",
    raw_ref="results/example.com/2026-09-05/scan-000001/ffuf.json",
)
d = f.to_dict()
print("Finding.to_dict:", json.dumps(d, ensure_ascii=False))
assert d["severity"] == "high"
f2 = Finding.from_dict(d)
assert f2.severity == Severity.HIGH
assert f2.target == f.target
assert f2.id == f.id
print("Finding round-trip OK")

# TaskRecord round-trip
t = TaskRecord(scan_id="scan-abc", module="ffuf", status=TaskStatus.RUNNING)
td = t.to_dict()
assert td["status"] == "running"
t2 = TaskRecord.from_dict(td)
assert t2.status == TaskStatus.RUNNING
assert t2.id == t.id
print("TaskRecord round-trip OK")

# ScanRecord (nested ScanTarget) round-trip
target = ScanTarget(value="https://example.com", scope_host="example.com")
scan = ScanRecord(target=target, status=TaskStatus.PENDING)
sd = scan.to_dict()
print("ScanRecord.to_dict:", json.dumps(sd, ensure_ascii=False))
assert sd["status"] == "pending"
assert sd["target"]["value"] == "https://example.com"
scan2 = ScanRecord.from_dict(sd)
assert isinstance(scan2.target, ScanTarget)
assert scan2.target.scope_host == "example.com"
assert scan2.status == TaskStatus.PENDING
assert scan2.id == scan.id
print("ScanRecord round-trip OK")

# JSON file round-trip (this is exactly how §41 result files get written/read)
import tempfile
tmp = Path(tempfile.mkdtemp()) / "finding.json"
tmp.write_text(json.dumps(f.to_dict(), ensure_ascii=False), encoding="utf-8")
loaded = Finding.from_dict(json.loads(tmp.read_text(encoding="utf-8")))
assert loaded == f
print("JSON file round-trip OK")

print("\nALL MODEL TESTS OK")
