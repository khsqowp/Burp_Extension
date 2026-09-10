import tempfile
from pathlib import Path

from orchestrator.manager import Orchestrator
from safety.policy import SafetyPolicyEngine
from storage.db import ScannerDB
from storage.models import TaskStatus
from wrappers.base import ToolWrapper, WrapperResult


class ParseFailWrapper(ToolWrapper):
    module = "server_header"

    def build_command(self, target, **kwargs):
        return []

    def execute(self, target, **kwargs):
        return WrapperResult(0, "IMPORTANT_RAW", "IMPORTANT_ERR", False, 0.01)

    def parse_result(self, result, target):
        raise ValueError("parse boom")


root = Path(tempfile.mkdtemp(prefix="failure_integrity_"))
db = ScannerDB(root / "scanner.sqlite")
orch = Orchestrator(db, SafetyPolicyEngine(), root / "results")
orch.register_wrapper(ParseFailWrapper())

scan = orch.create_scan("http://127.0.0.1", scope_host="127.0.0.1")
task = orch.run_module(scan.id, "server_header")
assert task.status == TaskStatus.FAILED
assert "parse boom" in task.error
stem = f"server_header.{task.id}"
result_dir = Path(scan.result_dir)
assert (result_dir / f"{stem}.json").read_text(encoding="utf-8") == "IMPORTANT_RAW"
assert (result_dir / f"{stem}.stderr.txt").read_text(encoding="utf-8") == "IMPORTANT_ERR"
assert (result_dir / f"{stem}.meta.json").is_file()

cancelled = orch.create_scan("http://127.0.0.1", scope_host="127.0.0.1")
db.update_scan_status(cancelled.id, TaskStatus.CANCELLED)
try:
    orch.create_task(cancelled.id, "server_header")
    raise AssertionError("cancelled scan accepted a new task")
except ValueError as exc:
    assert "cancelled" in str(exc)

print("FAILURE INTEGRITY TESTS OK")
