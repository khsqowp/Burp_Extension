import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

tmp_data = Path(tempfile.mkdtemp(prefix="api_test_data_"))
os.environ["SCANNER_DATA_DIR"] = str(tmp_data)

from fastapi.testclient import TestClient
from api.main import app

# Localhost-only access (spec §54) is enforced at the network boundary (direct
# run binds 127.0.0.1; Docker publishes "127.0.0.1:8000:8000") rather than in
# this app -- see api/main.py's module docstring for why an in-app client.host
# check was tried and removed. That boundary is verified separately in Docker
# (docker compose ps showing "127.0.0.1:8000->8000/tcp", plus a real curl from
# the host succeeding), not here.

with TestClient(app) as client:
    # -- health -----------------------------------------------------------------
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    print("health OK")

    # -- create scan --------------------------------------------------------------
    r = client.post("/scans", json={"target": "https://example.com", "scope_host": "example.com"})
    assert r.status_code == 200, r.text
    scan = r.json()
    print("created scan:", scan)
    assert scan["status"] == "pending"
    scan_id = scan["id"]

    r = client.get(f"/scans/{scan_id}")
    assert r.status_code == 200
    assert r.json()["id"] == scan_id
    print("get scan OK")

    r = client.get("/scans")
    assert any(s["id"] == scan_id for s in r.json())
    print("list scans OK")

    r = client.get("/scans/nope")
    assert r.status_code == 404
    print("404 for unknown scan OK")

    # -- run module (background) + poll task status ------------------------------
    r = client.post(f"/scans/{scan_id}/tasks", json={"module": "ssl_tls", "args": {"port": 443}})
    assert r.status_code == 200, r.text
    task = r.json()
    print("created task:", task)
    assert task["status"] == "pending"
    task_id = task["id"]

    deadline = time.time() + 90
    final_task = None
    while time.time() < deadline:
        r = client.get(f"/tasks/{task_id}")
        assert r.status_code == 200
        t = r.json()
        if t["status"] in ("completed", "skipped", "failed", "cancelled"):
            final_task = t
            break
        time.sleep(1)
    print("final task state:", final_task)
    assert final_task is not None, "task never reached a terminal state within 90s"
    assert final_task["status"] == "completed", final_task

    # -- scan auto-completes once its only task reaches a terminal state ----------
    # (spec review finding 2026-09-06: nothing used to call complete_scan() outside
    # tests -- every real scan sat at status=running with no end_time forever)
    r = client.get(f"/scans/{scan_id}")
    scan_after = r.json()
    print("scan status after task completion:", scan_after["status"], "end_time:", scan_after["end_time"])
    assert scan_after["status"] == "completed"
    assert scan_after["end_time"] != ""

    # -- results / issues -----------------------------------------------------------
    r = client.get(f"/scans/{scan_id}/results")
    assert r.status_code == 200
    results = r.json()
    print("scan results tasks:", [t["module"] for t in results["tasks"]])
    print("scan results findings:", [(f["finding"], f["severity"]) for f in results["findings"]])
    assert len(results["tasks"]) == 1
    assert len(results["findings"]) > 0

    r = client.get("/issues", params={"scan_id": scan_id})
    assert r.status_code == 200
    assert len(r.json()) == len(results["findings"])

    # -- GET /scans/{id}/summary: real findings present -> issues_found ------
    r = client.get(f"/scans/{scan_id}/summary")
    assert r.status_code == 200
    summary1 = r.json()
    print("scan1 summary:", summary1["overall"], summary1["findings_by_severity"])
    assert summary1["overall"] == "issues_found"
    assert summary1["findings_count"] == len(results["findings"])
    print("/summary correctly reports issues_found OK")
    print("issues endpoint OK")

    r = client.get("/targets")
    assert any(t["value"] == "https://example.com" for t in r.json())
    print("targets endpoint OK")

    # -- unknown module: run_module should still return 200 with a FAILED task later
    r = client.post(f"/scans/{scan_id}/tasks", json={"module": "no_such_module", "args": {}})
    assert r.status_code == 200
    bad_task_id = r.json()["id"]
    deadline = time.time() + 15
    bad_final = None
    while time.time() < deadline:
        t = client.get(f"/tasks/{bad_task_id}").json()
        if t["status"] in ("completed", "skipped", "failed", "cancelled"):
            bad_final = t
            break
        time.sleep(0.5)
    print("unknown-module task final state:", bad_final)
    assert bad_final["status"] == "failed"

    # -- scan re-evaluates to failed once a second task lands FAILED ----------------
    r = client.get(f"/scans/{scan_id}")
    scan_after2 = r.json()
    print("scan status after second (failed) task:", scan_after2["status"])
    assert scan_after2["status"] == "failed"

    # -- explicit /complete finalizes a scan with zero tasks ------------------------
    r = client.post("/scans", json={"target": "https://empty.example", "scope_host": "empty.example"})
    scan3_id = r.json()["id"]
    r = client.post(f"/scans/{scan3_id}/complete")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "failed"
    assert r.json()["end_time"] != ""
    print("explicit /complete on a zero-task scan OK")

    r = client.post("/scans/nope/complete")
    assert r.status_code == 404
    print("404 for /complete on unknown scan OK")

    # -- CAUTION module without confirm is rejected by Safety Policy ---------------
    # (spec review finding 2026-09-06: CAUTION used to auto-allow exactly like SAFE)
    r = client.post("/scans", json={"target": "https://caution.example", "scope_host": "caution.example"})
    scan4_id = r.json()["id"]
    r = client.post(f"/scans/{scan4_id}/tasks", json={"module": "default_content", "args": {}})
    task4_id = r.json()["id"]
    deadline = time.time() + 15
    final4 = None
    while time.time() < deadline:
        t = client.get(f"/tasks/{task4_id}").json()
        if t["status"] not in ("pending", "running"):
            final4 = t
            break
        time.sleep(0.5)
    print("CAUTION-without-confirm task:", final4)
    assert final4 is not None and final4["status"] == "failed"
    assert "confirm" in final4["error"]
    print("CAUTION module blocked without confirm OK")

    # -- GET /scans/{id}/summary: a scan whose only task failed must report
    # "incomplete", never "clean" (spec review finding 2026-09-06) -----------
    r = client.get(f"/scans/{scan4_id}/summary")
    assert r.status_code == 200, r.text
    summary4 = r.json()
    print("scan4 summary:", summary4["overall"], summary4["module_counts"])
    assert summary4["overall"] == "incomplete"
    assert summary4["module_counts"] == {"completed": 0, "skipped": 0, "failed": 1, "cancelled": 0, "active": 0, "total": 1}
    scan_result_dir4 = Path(client.get(f"/scans/{scan4_id}").json()["result_dir"])
    assert (scan_result_dir4 / "scan-summary.json").is_file()
    assert (scan_result_dir4 / "scan-summary.txt").is_file()
    assert "전체 양호 -- 발견된 이슈 없음" not in (scan_result_dir4 / "scan-summary.txt").read_text(encoding="utf-8")
    print("/summary correctly reports incomplete (not clean) for an all-failed scan OK")

    r = client.get("/scans/nope/summary")
    assert r.status_code == 404
    print("404 for /summary on unknown scan OK")

    # -- crawler over-budget max_pages is rejected before the subprocess ever runs -
    r = client.post("/scans", json={"target": "https://budget.example", "scope_host": "budget.example"})
    scan5_id = r.json()["id"]
    r = client.post(f"/scans/{scan5_id}/tasks", json={
        "module": "crawler", "args": {"max_pages": 999999},
    })
    task5_id = r.json()["id"]
    deadline = time.time() + 15
    final5 = None
    while time.time() < deadline:
        t = client.get(f"/tasks/{task5_id}").json()
        if t["status"] not in ("pending", "running"):
            final5 = t
            break
        time.sleep(0.5)
    print("over-budget crawler task:", final5)
    assert final5 is not None and final5["status"] == "failed"
    assert "초과" in final5["error"]
    print("over-budget request rejected before dispatch OK")

    # -- stop_scan cancels pending tasks (and the tasks themselves, spec §60) ------
    # orch.create_task() (not the /tasks POST endpoint) leaves the Task PENDING
    # with no BackgroundTasks execution scheduled, so this is deterministic --
    # no race with a real subprocess that might finish before /stop is called.
    r = client.post("/scans", json={"target": "https://example.org", "scope_host": "example.org"})
    scan2_id = r.json()["id"]
    pending_task = app.state.orchestrator.create_task(scan2_id, "ssl_tls")
    r = client.post(f"/scans/{scan2_id}/stop")
    assert r.status_code == 200
    assert r.json()["status"] == "cancelled"
    pending_task_after = client.get(f"/tasks/{pending_task.id}").json()
    print("pending task after stop_scan:", pending_task_after["status"])
    assert pending_task_after["status"] == "cancelled"
    print("stop_scan on a still-pending scan OK")

    # -- xss_reflected with a disallowed method is rejected before dispatch --------
    # (spec review finding 2026-09-06: method was never checked in the real path)
    r = client.post("/scans", json={"target": "https://method.example", "scope_host": "method.example"})
    scan7_id = r.json()["id"]
    r = client.post(f"/scans/{scan7_id}/tasks", json={
        "module": "xss_reflected", "args": {"confirm": True, "params": "q", "method": "delete"},
    })
    task7_id = r.json()["id"]
    deadline = time.time() + 15
    final7 = None
    while time.time() < deadline:
        t = client.get(f"/tasks/{task7_id}").json()
        if t["status"] not in ("pending", "running"):
            final7 = t
            break
        time.sleep(0.5)
    print("xss_reflected with method=delete:", final7)
    assert final7 is not None and final7["status"] == "failed"
    assert "delete" in final7["error"]
    print("disallowed method rejected before dispatch OK")

    # -- sequential registration (Burp's create->wait->create-next pattern) must
    # not leave the scan showing "completed" while a 2nd Task is about to run --
    # (spec review finding 2026-09-06, api/main.py _execute_in_background) -------
    r = client.post("/scans", json={"target": "https://example.com", "scope_host": "example.com"})
    scan6_id = r.json()["id"]
    r = client.post(f"/scans/{scan6_id}/tasks", json={"module": "ssl_tls", "args": {"port": 443}})
    taskA_id = r.json()["id"]
    deadline = time.time() + 90
    while time.time() < deadline:
        if client.get(f"/tasks/{taskA_id}").json()["status"] not in ("pending", "running"):
            break
        time.sleep(1)
    scan_after_a = client.get(f"/scans/{scan6_id}").json()
    print("scan after task A alone:", scan_after_a["status"])
    assert scan_after_a["status"] == "completed"

    # NOTE on why this doesn't assert the transient "running" state inline:
    # Starlette's TestClient runs a request's BackgroundTasks close enough to
    # synchronously that client.post() below can return only once Task B's
    # background execution has *already finished* -- confirmed by directly
    # timing it (the POST took ~as long as a full ssl_tls run) and by a
    # separate manual run against a real uvicorn server on a real socket,
    # where the transient state genuinely is observable: scan status flips to
    # "running" with end_time cleared immediately once Task B is created,
    # well before Task B finishes. TestClient's collapsed timing is a test
    # harness quirk, not a reason to skip verifying the real invariant here.
    r = client.post(f"/scans/{scan6_id}/tasks", json={"module": "ssl_tls", "args": {"port": 443}})
    taskB_id = r.json()["id"]

    deadline = time.time() + 90
    while time.time() < deadline:
        if client.get(f"/tasks/{taskB_id}").json()["status"] not in ("pending", "running"):
            break
        time.sleep(1)
    taskB_final = client.get(f"/tasks/{taskB_id}").json()
    scan_final6 = client.get(f"/scans/{scan6_id}").json()
    print("taskB final:", taskB_final["status"], taskB_final["end_time"])
    print("scan after both tasks:", scan_final6["status"], scan_final6["end_time"])
    assert scan_final6["status"] == "completed"
    # the real invariant this whole scenario protects: the scan's completion
    # must reflect Task B actually having run, not just be Task A's stale
    # completion frozen in time (which is exactly what create_task()'s
    # end_time="" reset + complete_scan()'s non-terminal guard prevent).
    assert scan_final6["end_time"] >= taskB_final["end_time"], (
        "scan end_time is older than Task B's -- scan was completed based on stale "
        "data from before Task B ran"
    )
    print("sequential registration reopens scan correctly OK")

    # -- version manifest (spec §63) ------------------------------------------------
    r = client.get("/version")
    assert r.status_code == 200
    v = r.json()
    print("version manifest:", v)
    assert v["scanner_core_version"]
    assert v["cve_db"]["rule_count"] > 0
    assert v["eol_db"]["rule_count"] > 0
    print("/version OK")

    # -- versions.json written into the scan's own result dir (spec §64) -----------
    scan_result_dir = Path(client.get(f"/scans/{scan_id}").json()["result_dir"])
    assert (scan_result_dir / "versions.json").is_file()
    print("versions.json snapshot in result_dir OK")

    # -- event log actually has entries (spec §57 -- scanner-data/logs/ used to be
    # an empty placeholder forever) --------------------------------------------------
    log_path = tmp_data / "logs" / "scanner.log"
    assert log_path.is_file(), f"expected event log at {log_path}"
    log_lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    events = [json.loads(line)["event"] for line in log_lines]
    print("event log events seen:", set(events))
    for expected in ("scan_started", "task_started", "task_completed", "task_failed", "scan_completed", "policy_blocked", "task_cancelled"):
        assert expected in events, f"expected at least one {expected!r} event in the log"
    print("event log OK")

    print("\nALL API TESTS OK")
