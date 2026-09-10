import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzers.js_analyzer import JsAnalyzer
from orchestrator.manager import Orchestrator
from safety.policy import HttpSafetyPolicy, SafetyPolicyEngine
from storage.cve_db import CveDB
from storage.db import ScannerDB
from storage.eol_db import EolDB
from storage.models import Severity, TaskStatus

tmp = Path(tempfile.mkdtemp(prefix="phase3_test_"))
db = ScannerDB(tmp / "scanner.sqlite")
cve_db = CveDB(tmp / "cve.sqlite")
eol_db = EolDB(tmp / "eol.sqlite")
engine = SafetyPolicyEngine(HttpSafetyPolicy(max_scan_duration_seconds=60))
orch = Orchestrator(db, engine, results_root=tmp / "results", cve_db=cve_db, eol_db=eol_db)
orch.register_wrapper(JsAnalyzer(engine.policy))

# -- real end-to-end: js_analyzer run -> Technology extracted + saved -------
TESTSERVER = r"C:\Users\user\AppData\Local\Temp\claude\E--temp\cde5e06e-b8b1-45d0-aad9-a3dad83ce944\scratchpad\js_testserver.py"
PORT = 8861
server = subprocess.Popen([sys.executable, TESTSERVER, str(PORT)])
time.sleep(1)
try:
    scan = orch.create_scan(f"http://127.0.0.1:{PORT}/", scope_host="127.0.0.1")
    task = orch.run_module(scan.id, "js_analyzer", js_url=f"http://127.0.0.1:{PORT}/app.js")
    print("js_analyzer task:", task.status, task.error)
    assert task.status == TaskStatus.COMPLETED

    techs = db.list_technologies(scan_id=scan.id)
    print("technologies saved:", [(t.product, t.version, t.source_scanner) for t in techs])
    assert len(techs) == 1
    assert techs[0].product == "jquery"
    assert techs[0].version == "3.4.1"
    assert techs[0].scan_id == scan.id

    # jQuery isn't in the CVE/EOL seed tables -- no findings expected from this one
    findings = db.list_findings(scan_id=scan.id)
    matcher_findings = [f for f in findings if f.scanner in ("cve_matcher", "eol_matcher")]
    print("matcher findings (expected none for jquery):", matcher_findings)
    assert matcher_findings == []
finally:
    server.terminate()
    server.wait(timeout=5)

# -- white-box: exercise the extraction+matching glue directly with a real,
# vulnerable-version infra_vuln-shaped payload (spinning up an actually
# vulnerable Apache 2.4.49 isn't practical here, so this drives the exact
# same _extract_and_match_technologies() the real infra_vuln path calls) --
scan2 = orch.create_scan("https://vulnerable.example", scope_host="vulnerable.example")
task2 = orch.create_task(scan2.id, "infra_vuln")
task2.result_file = str(tmp / "results" / "infra_vuln.json")
fake_infra_json = json.dumps([
    {"port": 443, "protocol": "tcp", "state": "open", "service_name": "https",
     "product": "Apache httpd", "version": "2.4.49", "extrainfo": "", "cpe": [],
     "script_findings": [], "version_rule_hits": []},
    {"port": 3306, "protocol": "tcp", "state": "open", "service_name": "mysql",
     "product": "MySQL", "version": "5.7.10", "extrainfo": "", "cpe": [],
     "script_findings": [], "version_rule_hits": []},
])
orch._extract_and_match_technologies(task2, scan2, fake_infra_json)

techs2 = db.list_technologies(scan_id=scan2.id)
print("infra_vuln technologies saved:", [(t.product, t.version, t.host, t.port) for t in techs2])
assert len(techs2) == 2
assert all(t.host == "vulnerable.example" for t in techs2)

findings2 = db.list_findings(scan_id=scan2.id)
matcher_findings2 = [f for f in findings2 if f.scanner in ("cve_matcher", "eol_matcher")]
print("matcher findings:", [(f.scanner, f.finding, f.severity.value, f.technology) for f in matcher_findings2])
assert any(f.scanner == "cve_matcher" and "Apache httpd 2.4.49" in f.technology for f in matcher_findings2)
assert any(f.scanner == "eol_matcher" and "MySQL 5.7.10" in f.technology for f in matcher_findings2)
assert all(f.task_id == task2.id for f in matcher_findings2)
assert all(f.scan_id == scan2.id for f in matcher_findings2)

db.close()
cve_db.close()
eol_db.close()
print("\nALL PHASE 3 INTEGRATION TESTS OK")
