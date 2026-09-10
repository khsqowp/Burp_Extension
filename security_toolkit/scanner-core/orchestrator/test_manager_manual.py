import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator.manager import Orchestrator
from safety.policy import SafetyPolicyEngine, HttpSafetyPolicy
from storage.db import ScannerDB
from storage.models import TaskStatus
from wrappers.base import ToolWrapper, WrapperResult
from wrappers.default_content_wrapper import DefaultContentWrapper
from wrappers.ssl_tls_wrapper import SSLTLSWrapper

tmp = Path(tempfile.mkdtemp(prefix="orch_test_"))
db = ScannerDB(tmp / "scanner.sqlite")
engine = SafetyPolicyEngine(HttpSafetyPolicy(max_scan_duration_seconds=90))
orch = Orchestrator(db, engine, results_root=tmp / "results")
orch.register_wrapper(SSLTLSWrapper(engine.policy))
orch.register_wrapper(DefaultContentWrapper(engine.policy))

# -- create_scan: result_dir created, sequential scan-NNNNNN naming ----------
scan1 = orch.create_scan("https://example.com", scope_host="example.com")
scan2 = orch.create_scan("https://example.com", scope_host="example.com")
print("scan1 result_dir:", scan1.result_dir)
print("scan2 result_dir:", scan2.result_dir)
assert Path(scan1.result_dir).exists()
assert scan1.result_dir.endswith("scan-000001")
assert scan2.result_dir.endswith("scan-000002")
assert scan1.status == TaskStatus.PENDING
print("create_scan / sequential dirs OK")

# -- unregistered module: policy allows (SAFE) but no wrapper --------------
task_no_wrapper = orch.run_module(scan1.id, "crawler")
print("no-wrapper task:", task_no_wrapper.status, task_no_wrapper.error)
assert task_no_wrapper.status == TaskStatus.FAILED
assert "no wrapper registered" in task_no_wrapper.error
assert orch.db.get_scan(scan1.id).status == TaskStatus.PENDING, "scan must not flip to RUNNING for a task that never actually ran"
print("no-wrapper-registered failure OK (scan untouched)")

# -- totally unknown module: safety policy fails closed before wrapper lookup
task_unknown = orch.run_module(scan1.id, "totally_unknown_module")
print("unknown-module task:", task_unknown.status, task_unknown.error)
assert task_unknown.status == TaskStatus.FAILED
assert "알 수 없는" in task_unknown.error
print("policy fail-closed OK")

# -- real end-to-end module run (ssl_tls, real target) -----------------------
task_ok = orch.run_module(scan1.id, "ssl_tls", port=443)
print("ssl_tls task:", task_ok.status, "result_file:", task_ok.result_file, "error:", task_ok.error)
assert task_ok.status == TaskStatus.COMPLETED
assert task_ok.result_file and Path(task_ok.result_file).exists()
assert orch.db.get_scan(scan1.id).status == TaskStatus.RUNNING, "scan should have flipped to RUNNING once a real task executed"

findings = orch.db.list_findings(scan_id=scan1.id)
print("findings stored:", [(f.finding, f.severity.value, f.raw_ref) for f in findings])
assert len(findings) > 0
assert all(f.task_id == task_ok.id for f in findings)
assert all(f.raw_ref == task_ok.result_file for f in findings)
print("real module run + finding persistence OK")

# -- complete_scan: mixed pass/fail -> FAILED overall ------------------------
scan1_final = orch.complete_scan(scan1.id)
print("scan1 final status:", scan1_final.status, "end_time:", scan1_final.end_time)
assert scan1_final.status == TaskStatus.FAILED  # has 2 FAILED tasks alongside the 1 COMPLETED
assert scan1_final.end_time
print("complete_scan (mixed) OK")

# -- complete_scan: all-pass -> COMPLETED overall ----------------------------
task_ok2 = orch.run_module(scan2.id, "ssl_tls", port=443)
assert task_ok2.status == TaskStatus.COMPLETED
scan2_final = orch.complete_scan(scan2.id)
assert scan2_final.status == TaskStatus.COMPLETED
print("complete_scan (all-pass) OK")

# -- cancel_task: PENDING task can be cancelled before execute_task runs -----
scan3 = orch.create_scan("https://example.org", scope_host="example.org")
pending_task = orch.create_task(scan3.id, "ssl_tls")
assert pending_task.status == TaskStatus.PENDING
cancelled = orch.cancel_task(pending_task.id)
assert cancelled.status == TaskStatus.CANCELLED
result_after_cancel = orch.execute_task(pending_task.id, port=443)
assert result_after_cancel.status == TaskStatus.CANCELLED
assert not result_after_cancel.result_file
print("cancel_task before execute OK -- never actually ran:", result_after_cancel.status)

# -- exception safety (spec §58): a wrapper that raises must not crash Orchestrator
class ExplodingWrapper(ToolWrapper):
    module = "exploder"
    def build_command(self, target, **kwargs):
        return ["python", "-c", "print('{}')"]
    def parse_result(self, result, target):
        raise RuntimeError("boom -- simulated parser crash")

from storage.models import RiskLevel
from safety import policy as policy_module
policy_module.MODULE_RISK["exploder"] = RiskLevel.SAFE
orch.register_wrapper(ExplodingWrapper(engine.policy))
task_boom = orch.run_module(scan3.id, "exploder")
print("exploding wrapper task:", task_boom.status, task_boom.error)
assert task_boom.status == TaskStatus.FAILED
assert "boom" in task_boom.error
# Orchestrator itself must still be usable afterward
still_alive = orch.run_module(scan3.id, "ssl_tls", port=443)
assert still_alive.status == TaskStatus.COMPLETED
print("exception safety OK -- orchestrator survived a wrapper crash")

# -- cancel_task: RUNNING task's real subprocess actually gets killed -------
# (spec §60 Process Termination -- spec review finding 2026-09-06: this used
# to be impossible, "이미 디스패치된 subprocess를 여기서 즉시 죽이지 않는다")
class SleeperWrapper(ToolWrapper):
    module = "sleeper"
    def build_command(self, target, *, seconds=30, **kwargs):
        return [sys.executable, "-c", f"import time; time.sleep({seconds})"]
    def parse_result(self, result, target):
        return []

policy_module.MODULE_RISK["sleeper"] = RiskLevel.SAFE
orch.register_wrapper(SleeperWrapper(engine.policy))
scan4 = orch.create_scan("https://example.net", scope_host="example.net")
sleeper_task = orch.create_task(scan4.id, "sleeper")

result_box: list = []
t = threading.Thread(target=lambda: result_box.append(orch.execute_task(sleeper_task.id, seconds=30)))
start = time.monotonic()
t.start()
# give the subprocess a moment to actually spawn and register itself
deadline = time.monotonic() + 5
while time.monotonic() < deadline and orch.process_registry._procs.get(sleeper_task.id) is None:
    time.sleep(0.05)
assert orch.process_registry._procs.get(sleeper_task.id) is not None, "subprocess never registered in time"

cancelled_running = orch.cancel_task(sleeper_task.id)
print("cancel_task(RUNNING) returned:", cancelled_running.status)
assert cancelled_running.status == TaskStatus.CANCELLED

t.join(timeout=10)
elapsed = time.monotonic() - start
print(f"execute_task() thread finished in {elapsed:.1f}s (would be ~30s if the process wasn't actually killed)")
assert elapsed < 10, "subprocess was not actually terminated -- execute_task() waited out the full sleep"
assert len(result_box) == 1 and result_box[0].status == TaskStatus.CANCELLED, \
    "the executing thread's own FAILED write must not clobber the CANCELLED status set by cancel_task()"
print("cancel_task actually kills a RUNNING subprocess OK")

# -- sequential task registration must not let the scan look "completed"
# while a later Task is still about to run under it (spec review finding
# 2026-09-06: Burp's runScan() does create->wait->create next, exactly this
# pattern) ---------------------------------------------------------------
scan6 = orch.create_scan("https://example.com", scope_host="example.com")
task_a = orch.run_module(scan6.id, "ssl_tls", port=443)
assert task_a.status == TaskStatus.COMPLETED
after_task_a = orch.complete_scan(scan6.id)
print("scan after task A alone:", after_task_a.status, "end_time:", after_task_a.end_time)
assert after_task_a.status == TaskStatus.COMPLETED
assert after_task_a.end_time

# a second Task now gets registered against this already-"completed" scan --
# create_task() itself must reopen it immediately (not just once the Task
# starts executing), so a poller between these two calls never sees a lie.
task_b_pending = orch.create_task(scan6.id, "ssl_tls")
reopened = orch.db.get_scan(scan6.id)
print("scan right after 2nd task created (not yet run):", reopened.status, "end_time:", repr(reopened.end_time))
assert reopened.status == TaskStatus.RUNNING, "scan must be reopened the instant a new Task is added, not left completed"
assert reopened.end_time == "", "stale end_time from the first completion must be cleared, not left dangling"

task_b = orch.execute_task(task_b_pending.id, port=443)
assert task_b.status == TaskStatus.COMPLETED
final6 = orch.complete_scan(scan6.id)
print("scan after both tasks:", final6.status, "end_time:", final6.end_time)
assert final6.status == TaskStatus.COMPLETED
assert final6.end_time
tasks6 = orch.db.list_tasks_for_scan(scan6.id)
assert len(tasks6) == 2 and all(t.status == TaskStatus.COMPLETED for t in tasks6)
print("sequential task registration reopens scan correctly OK")

# -- failed Task still preserves full stderr/meta on disk (spec review finding
# 2026-09-06: only successful Tasks with non-empty stdout got a raw file at
# all; a crashed/failed Task's full stderr and applied args vanished except
# for a 500-char snippet in the DB error column) -------------------------
scan7 = orch.create_scan("192.168.0.12", scope_host="192.168.0.12")  # no scheme -- default_content_scanner.py now rejects this cleanly
task_bad = orch.run_module(scan7.id, "default_content", confirm=True, tech="")
print("bad-url task:", task_bad.status, "error:", task_bad.error[:80])
assert task_bad.status == TaskStatus.FAILED

result_dir = Path(scan7.result_dir)
stderr_file = result_dir / f"default_content.{task_bad.id}.stderr.txt"
meta_file = result_dir / f"default_content.{task_bad.id}.meta.json"
assert stderr_file.is_file(), f"expected {stderr_file} to exist"
assert meta_file.is_file(), f"expected {meta_file} to exist"

stderr_text = stderr_file.read_text(encoding="utf-8")
print("stderr.txt contents:", stderr_text.strip())
assert "http://" in stderr_text or "https://" in stderr_text

import json as _json
meta = _json.loads(meta_file.read_text(encoding="utf-8"))
print("meta.json contents:", meta)
assert meta["module"] == "default_content"
assert meta["args"] == {"tech": ""}
assert meta["exit_code"] == 2
print("failed-task raw preservation (stderr.txt + meta.json) OK")

# -- complete_scan: all Tasks CANCELLED (no FAILED at all) must report the
# scan itself as CANCELLED, not COMPLETED (spec review finding 2026-09-06:
# the old formula was "any FAILED? -> FAILED : COMPLETED" with no CANCELLED
# branch, so a scan where every Task was merely stopped -- e.g. via the Stop
# button before anything crashed on its own -- was written to the DB as
# COMPLETED, directly contradicting its own scan-summary.json "incomplete"
# verdict and Burp's own "중지됨" status label) -----------------------------
scan8 = orch.create_scan("https://example.com", scope_host="example.com")
pending_task8a = orch.create_task(scan8.id, "ssl_tls")
pending_task8b = orch.create_task(scan8.id, "ssl_tls")
assert orch.cancel_task(pending_task8a.id).status == TaskStatus.CANCELLED
assert orch.cancel_task(pending_task8b.id).status == TaskStatus.CANCELLED
scan8_final = orch.complete_scan(scan8.id)
print("scan8 (all cancelled) final status:", scan8_final.status)
assert scan8_final.status == TaskStatus.CANCELLED, \
    "a scan with zero FAILED tasks but every task CANCELLED must not be reported as COMPLETED"
print("complete_scan (all-cancelled) OK")

# -- complete_scan: FAILED still outranks CANCELLED in a mixed scan ----------
scan9 = orch.create_scan("https://example.com", scope_host="example.com")
pending_task9 = orch.create_task(scan9.id, "ssl_tls")
assert orch.cancel_task(pending_task9.id).status == TaskStatus.CANCELLED
task9_failed = orch.run_module(scan9.id, "totally_unknown_module")
assert task9_failed.status == TaskStatus.FAILED
scan9_final = orch.complete_scan(scan9.id)
print("scan9 (1 cancelled + 1 failed) final status:", scan9_final.status)
assert scan9_final.status == TaskStatus.FAILED, "FAILED must still win over CANCELLED when both are present"
print("complete_scan (mixed cancelled+failed -> FAILED) OK")

db.close()
print("\nALL ORCHESTRATOR TESTS OK")
