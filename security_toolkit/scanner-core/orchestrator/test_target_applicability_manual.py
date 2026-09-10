"""Regression checks for target/module applicability decisions."""

import json
import tempfile
from pathlib import Path

from api.main import build_orchestrator
from orchestrator.manager import _not_applicable_reason
from storage.models import TaskStatus
from storage.models import ScanTarget


http_ip = ScanTarget(value="http://192.168.0.12:3000", scope_host="192.168.0.12")
assert _not_applicable_reason("ssl_tls", http_ip)
assert _not_applicable_reason("subdomain_discovery", http_ip)
assert _not_applicable_reason("virtual_host_isolation", http_ip)
assert not _not_applicable_reason("crawler", http_ip)

internal_single_label = ScanTarget(value="http://juice-shop:3000", scope_host="juice-shop")
assert _not_applicable_reason("subdomain_discovery", internal_single_label)
assert _not_applicable_reason("virtual_host_isolation", internal_single_label)

https_domain = ScanTarget(value="https://example.test", scope_host="example.test")
assert not _not_applicable_reason("ssl_tls", https_domain)
assert not _not_applicable_reason("subdomain_discovery", https_domain)
assert not _not_applicable_reason("virtual_host_isolation", https_domain)

# Full Core path: no target-facing process is started, RAW explains why, and
# non-applicable modules do not poison the overall scan status.
with tempfile.TemporaryDirectory() as td:
    orch = build_orchestrator(Path(td))
    scan = orch.create_scan(http_ip.value, scope_host=http_ip.scope_host)
    for module in ("ssl_tls", "subdomain_discovery", "virtual_host_isolation"):
        task = orch.run_module(scan.id, module)
        assert task.status == TaskStatus.SKIPPED
        assert "건너뜁니다" in task.error
        raw = json.loads(Path(task.result_file).read_text(encoding="utf-8"))
        assert raw["status"] == "skipped"
        assert raw["observations"][0]["type"] == "not_applicable"
    final_scan = orch.complete_scan(scan.id)
    assert final_scan.status == TaskStatus.COMPLETED
    summary = orch.get_scan_summary(scan.id)
    assert summary["module_counts"]["skipped"] == 3
    assert summary["overall"] == "incomplete"
    orch.db.close()
    orch.cve_db.close()
    orch.eol_db.close()

print("TARGET APPLICABILITY TESTS OK")
