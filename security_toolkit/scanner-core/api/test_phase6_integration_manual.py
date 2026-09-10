import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

tmp_data = Path(tempfile.mkdtemp(prefix="phase6_api_test_"))
os.environ["SCANNER_DATA_DIR"] = str(tmp_data)

from fastapi.testclient import TestClient
from api.main import app

SCRATCHPAD = Path(r"C:\Users\user\AppData\Local\Temp\claude\E--temp\cde5e06e-b8b1-45d0-aad9-a3dad83ce944\scratchpad")
CURRENT_SCRATCHPAD = Path(r"C:\Users\user\AppData\Local\Temp\claude\E--temp\dcf173e9-7d9a-4773-89f0-d7a723d6ea90\scratchpad")

servers = [
    subprocess.Popen([sys.executable, str(SCRATCHPAD / "xss_reflected_testserver.py"), "8890"]),
    subprocess.Popen([sys.executable, str(SCRATCHPAD / "xss_stored_testserver.py"), "8891"]),
    subprocess.Popen([sys.executable, str(CURRENT_SCRATCHPAD / "path_traversal_testserver.py"), "8899"]),
]
time.sleep(1)

try:
    with TestClient(app) as client:
        # -- xss_reflected -----------------------------------------------------
        r = client.post("/scans", json={"target": "http://127.0.0.1:8890/", "scope_host": "127.0.0.1"})
        scan_id = r.json()["id"]
        r = client.post(f"/scans/{scan_id}/tasks", json={"module": "xss_reflected", "args": {"confirm": True, "params": "name,safe"}})
        task_id = r.json()["id"]
        deadline = time.time() + 30
        final = None
        while time.time() < deadline:
            t = client.get(f"/tasks/{task_id}").json()
            if t["status"] not in ("pending", "running"):
                final = t
                break
            time.sleep(1)
        print("xss_reflected task:", final)
        assert final is not None and final["status"] == "completed"
        issues = client.get("/issues", params={"scan_id": scan_id}).json()
        print("xss_reflected issues:", [(i["finding"], i["severity"]) for i in issues])
        assert len(issues) == 2
        assert any(i["severity"] == "high" for i in issues)

        # -- xss_stored ----------------------------------------------------------
        r = client.post("/scans", json={"target": "http://127.0.0.1:8891/", "scope_host": "127.0.0.1"})
        scan2_id = r.json()["id"]
        r = client.post(f"/scans/{scan2_id}/tasks", json={
            "module": "xss_stored",
            "args": {"confirm": True, "check_url": "http://127.0.0.1:8891/view", "params": "comment"},
        })
        task2_id = r.json()["id"]
        deadline = time.time() + 30
        final2 = None
        while time.time() < deadline:
            t = client.get(f"/tasks/{task2_id}").json()
            if t["status"] not in ("pending", "running"):
                final2 = t
                break
            time.sleep(1)
        print("xss_stored task:", final2)
        assert final2 is not None and final2["status"] == "completed"
        issues2 = client.get("/issues", params={"scan_id": scan2_id}).json()
        print("xss_stored issues:", [(i["finding"], i["severity"]) for i in issues2])
        assert len(issues2) == 1
        assert issues2[0]["severity"] == "high"

        # -- path_traversal --------------------------------------------------------
        r = client.post("/scans", json={"target": "http://127.0.0.1:8899/download", "scope_host": "127.0.0.1"})
        scan3_id = r.json()["id"]
        r = client.post(f"/scans/{scan3_id}/tasks", json={
            "module": "path_traversal",
            "args": {"confirm": True, "param": "file", "target_os": "both"},
        })
        task3_id = r.json()["id"]
        deadline = time.time() + 60
        final3 = None
        while time.time() < deadline:
            t = client.get(f"/tasks/{task3_id}").json()
            if t["status"] not in ("pending", "running"):
                final3 = t
                break
            time.sleep(1)
        print("path_traversal task:", final3)
        assert final3 is not None and final3["status"] == "completed"
        issues3 = client.get("/issues", params={"scan_id": scan3_id}).json()
        print("path_traversal issues:", len(issues3), "hits, first:", issues3[0]["finding"] if issues3 else None)
        assert len(issues3) >= 1
        assert all(i["severity"] == "high" for i in issues3)

        print("\nALL PHASE 6 API INTEGRATION TESTS OK")
finally:
    for s in servers:
        s.terminate()
    for s in servers:
        s.wait(timeout=5)
