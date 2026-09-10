import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

tmp_data = Path(tempfile.mkdtemp(prefix="api_filter_test_"))
os.environ["SCANNER_DATA_DIR"] = str(tmp_data)

from fastapi.testclient import TestClient
from api.main import app

with TestClient(app) as client:
    r1 = client.post("/scans", json={"target": "https://a.example.com", "scope_host": "a.example.com"})
    scan1 = r1.json()
    r2 = client.post("/scans", json={"target": "https://a.example.com", "scope_host": "a.example.com"})
    scan2 = r2.json()
    r3 = client.post("/scans", json={"target": "https://b.example.com", "scope_host": "b.example.com"})
    scan3 = r3.json()

    targets = client.get("/targets").json()
    print("targets:", targets)
    target_a = next(t for t in targets if t["value"] == "https://a.example.com")
    target_b = next(t for t in targets if t["value"] == "https://b.example.com")

    filtered_a = client.get("/scans", params={"target_id": target_a["id"]}).json()
    print("scans for target a:", [s["id"] for s in filtered_a])
    assert {s["id"] for s in filtered_a} == {scan1["id"], scan2["id"]}

    filtered_b = client.get("/scans", params={"target_id": target_b["id"]}).json()
    assert {s["id"] for s in filtered_b} == {scan3["id"]}

    all_scans = client.get("/scans").json()
    assert len(all_scans) == 3

    print("\nALL SCANS-FILTER TESTS OK")
