import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

tmp_data = Path(tempfile.mkdtemp(prefix="phase7_api_test_"))
os.environ["SCANNER_DATA_DIR"] = str(tmp_data)

from fastapi.testclient import TestClient
from api.main import app


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


wl = tmp_data / "wordlist.txt"
wl.write_text("password\n123456\nsecret\nadmin\n", encoding="utf-8")

header = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
payload = _b64u(json.dumps({"sub": "1234567890"}, separators=(",", ":")).encode())
sig = hmac.new(b"secret", f"{header}.{payload}".encode(), hashlib.sha256).digest()
token = f"{header}.{payload}.{_b64u(sig)}"

md5_of_admin = hashlib.md5(b"admin").hexdigest()

with TestClient(app) as client:
    # -- jwt_analyzer ----------------------------------------------------------
    r = client.post("/scans", json={"target": token, "scope_host": "decoder"})
    scan_id = r.json()["id"]
    r = client.post(f"/scans/{scan_id}/tasks", json={
        "module": "jwt_analyzer",
        "args": {"crack_secret": True, "wordlist": str(wl)},
    })
    task_id = r.json()["id"]
    deadline = time.time() + 30
    final = None
    while time.time() < deadline:
        t = client.get(f"/tasks/{task_id}").json()
        if t["status"] not in ("pending", "running"):
            final = t
            break
        time.sleep(1)
    print("jwt_analyzer task:", final)
    assert final is not None and final["status"] == "completed"
    issues = client.get("/issues", params={"scan_id": scan_id}).json()
    print("jwt_analyzer issues:", [(i["finding"], i["severity"]) for i in issues])
    cracked = [i for i in issues if "cracked" in i["finding"]]
    assert len(cracked) == 1 and cracked[0]["severity"] == "high"
    assert "'secret'" in cracked[0]["finding"]

    # -- crypto_identifier -------------------------------------------------------
    r = client.post("/scans", json={"target": md5_of_admin, "scope_host": "decoder"})
    scan2_id = r.json()["id"]
    r = client.post(f"/scans/{scan2_id}/tasks", json={
        "module": "crypto_identifier",
        "args": {"crack": True, "wordlist": str(wl)},
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
    print("crypto_identifier task:", final2)
    assert final2 is not None and final2["status"] == "completed"
    issues2 = client.get("/issues", params={"scan_id": scan2_id}).json()
    print("crypto_identifier issues:", [(i["finding"], i["severity"]) for i in issues2])
    cracked2 = [i for i in issues2 if "cracked" in i["finding"]]
    assert len(cracked2) == 1 and cracked2[0]["severity"] == "high"
    assert "'admin'" in cracked2[0]["finding"]

    print("\nALL PHASE 7 API INTEGRATION TESTS OK")
