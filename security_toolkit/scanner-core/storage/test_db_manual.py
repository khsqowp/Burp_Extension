import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from storage.db import ScannerDB
from storage.models import Finding, ScanRecord, ScanTarget, Severity, TaskRecord, TaskStatus

tmp_db = Path(tempfile.mkdtemp()) / "scanner.sqlite"
db = ScannerDB(tmp_db)

# -- target + scan --------------------------------------------------------
target = ScanTarget(value="https://example.com", scope_host="example.com")
scan = ScanRecord(target=target, status=TaskStatus.PENDING, start_time="2026-09-05T12:00:00Z")
db.save_scan(scan)

loaded_scan = db.get_scan(scan.id)
assert loaded_scan is not None
assert loaded_scan.target.value == "https://example.com"
assert loaded_scan.status == TaskStatus.PENDING
print("scan save/get OK:", loaded_scan.id)

db.update_scan_status(scan.id, TaskStatus.RUNNING)
assert db.get_scan(scan.id).status == TaskStatus.RUNNING
print("scan status update OK")

# -- tasks ------------------------------------------------------------------
task1 = TaskRecord(scan_id=scan.id, module="ssl_tls", status=TaskStatus.PENDING)
task2 = TaskRecord(scan_id=scan.id, module="crawler", status=TaskStatus.PENDING)
db.save_task(task1)
db.save_task(task2)

tasks = db.list_tasks_for_scan(scan.id)
assert len(tasks) == 2
assert {t.module for t in tasks} == {"ssl_tls", "crawler"}
print("task save/list OK:", [t.module for t in tasks])

db.update_task_status(task1.id, TaskStatus.COMPLETED, end_time="2026-09-05T12:01:00Z", result_file="ssl.json")
t1 = db.get_task(task1.id)
assert t1.status == TaskStatus.COMPLETED
assert t1.result_file == "ssl.json"
assert t1.end_time == "2026-09-05T12:01:00Z"
print("task status update OK")

db.update_task_status(task2.id, TaskStatus.FAILED, error="timeout")
t2 = db.get_task(task2.id)
assert t2.status == TaskStatus.FAILED
assert t2.error == "timeout"
print("task failure update OK")

# -- findings (Issues) --------------------------------------------------------
f1 = Finding(
    target=target.value, scanner="ssl_tls", finding="TLS 1.0 enabled", severity=Severity.MEDIUM,
    host="example.com", port=443, protocol="tls", scan_id=scan.id, task_id=task1.id,
    timestamp="2026-09-05T12:00:30Z", raw_ref="results/example.com/2026-09-05/scan-1/ssl.json",
)
f2 = Finding(
    target=target.value, scanner="crawler", finding="Directory listing enabled", severity=Severity.LOW,
    host="example.com", scan_id=scan.id, task_id=task2.id, timestamp="2026-09-05T12:00:45Z",
)
db.save_finding(f1)
db.save_finding(f2)

findings = db.list_findings(scan_id=scan.id)
assert len(findings) == 2
assert {f.finding for f in findings} == {"TLS 1.0 enabled", "Directory listing enabled"}
print("finding save/list OK:", [(f.scanner, f.severity.value) for f in findings])

db.update_scan_status(scan.id, TaskStatus.COMPLETED, end_time="2026-09-05T12:02:00Z")
assert db.get_scan(scan.id).status == TaskStatus.COMPLETED
assert db.get_scan(scan.id).end_time == "2026-09-05T12:02:00Z"
print("scan completion OK")

targets = db.list_targets()
assert len(targets) == 1
scans = db.list_scans(target_id=target.id)
assert len(scans) == 1
print("target/scan listing OK")

db.close()

# -- durability: reopen the SAME file and confirm everything survived -------
# (spec §43: docker compose down/build/up must not lose scan data)
db2 = ScannerDB(tmp_db)
reopened_scan = db2.get_scan(scan.id)
assert reopened_scan is not None
assert reopened_scan.status == TaskStatus.COMPLETED
assert len(db2.list_tasks_for_scan(scan.id)) == 2
assert len(db2.list_findings(scan_id=scan.id)) == 2
db2.close()
print("reopen/durability OK")

print("\nALL DB TESTS OK")
