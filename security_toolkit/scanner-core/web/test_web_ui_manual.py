import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

tmp_data = Path(tempfile.mkdtemp(prefix="web_ui_test_"))
os.environ["SCANNER_DATA_DIR"] = str(tmp_data)

from fastapi.testclient import TestClient
from api.main import app

with TestClient(app) as client:
    r = client.get("/ui/")
    print("GET /ui/ status:", r.status_code, "content-type:", r.headers.get("content-type"))
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
    assert "Security Toolkit" in r.text
    assert "loadAll()" in r.text
    assert "설명 / 예상 피해" in r.text
    assert "api(`/scans/${scanId}/summary`)" in r.text
    assert "진단 판정" in r.text
    assert "비적용" in r.text

    r2 = client.get("/ui/index.html")
    assert r2.status_code == 200
    assert r2.text == r.text

    # API routes must still work unaffected by the /ui mount
    r3 = client.get("/health")
    assert r3.status_code == 200

    print("\nALL WEB UI STATIC SERVING TESTS OK")
