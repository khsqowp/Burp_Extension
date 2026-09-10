import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator.scan_summary import build_scan_summary, describe_finding, render_scan_summary_text
from storage.models import Finding, ScanRecord, ScanTarget, Severity, TaskRecord, TaskStatus

target = ScanTarget(value="https://example.com", scope_host="example.com")

# -- clean: every task completed, zero findings ------------------------------
scan_clean = ScanRecord(target=target, status=TaskStatus.COMPLETED, start_time="t0", end_time="t1")
tasks_clean = [TaskRecord(scan_id=scan_clean.id, module="ssl_tls", status=TaskStatus.COMPLETED)]
summary_clean = build_scan_summary(scan_clean, tasks_clean, [])
print("clean overall:", summary_clean["overall"])
assert summary_clean["overall"] == "clean"
assert "전체 양호" in render_scan_summary_text(summary_clean)

scan_running = ScanRecord(target=target, status=TaskStatus.RUNNING, start_time="t0")
tasks_running = [TaskRecord(scan_id=scan_running.id, module="crawler", status=TaskStatus.RUNNING)]
summary_running = build_scan_summary(scan_running, tasks_running, [])
assert summary_running["overall"] == "incomplete"
assert summary_running["module_counts"]["active"] == 1

# -- incomplete: zero findings, but every task FAILED (spec review finding
# 2026-09-06: this used to be indistinguishable from "clean") ---------------
scan_incomplete = ScanRecord(target=target, status=TaskStatus.FAILED, start_time="t0", end_time="t1")
tasks_incomplete = [
    TaskRecord(scan_id=scan_incomplete.id, module="crawler", status=TaskStatus.FAILED, error="URL must start with http"),
    TaskRecord(scan_id=scan_incomplete.id, module="ffuf", status=TaskStatus.FAILED, error="baseline detection failed"),
]
summary_incomplete = build_scan_summary(scan_incomplete, tasks_incomplete, [])
print("incomplete overall:", summary_incomplete["overall"])
assert summary_incomplete["overall"] == "incomplete"
text = render_scan_summary_text(summary_incomplete)
assert "전체 양호 -- 발견된 이슈 없음" not in text, "a scan where every module failed must never render as the bare 전체 양호 line"
assert "볼 수 없음" in text
print("clean vs incomplete are correctly distinguished OK")

# -- issues_found: real findings present -------------------------------------
scan_issues = ScanRecord(target=target, status=TaskStatus.COMPLETED, start_time="t0", end_time="t1")
tasks_issues = [TaskRecord(scan_id=scan_issues.id, module="ssl_tls", status=TaskStatus.COMPLETED)]
findings_issues = [
    Finding(target=target.value, scanner="ssl_tls", finding="TLSv1.0 Supported", severity=Severity.HIGH),
    Finding(target=target.value, scanner="ssl_tls", finding="HSTS Header missing", severity=Severity.MEDIUM),
]
summary_issues = build_scan_summary(scan_issues, tasks_issues, findings_issues)
print("issues_found overall:", summary_issues["overall"], summary_issues["findings_by_severity"])
assert summary_issues["overall"] == "issues_found"
assert summary_issues["findings_by_severity"] == {"high": 1, "medium": 1}
assert summary_issues["module_counts"] == {"completed": 1, "skipped": 0, "failed": 0, "cancelled": 0, "active": 0, "total": 1}
assert summary_issues["findings"][0]["description"]

safe_header_finding = Finding(
    target="http://example.test", scanner="security_headers",
    finding="CSP가 unsafe-inline을 허용합니다.", severity=Severity.INFO,
)
assert "스크립트" in describe_finding(safe_header_finding)

server_disclosure_finding = Finding(
    target="http://example.test", scanner="server_header",
    finding="응답 헤더가 제품 정보를 노출합니다.", severity=Severity.INFO,
)
assert "공격 표면" in describe_finding(server_disclosure_finding)
assert "설명:" in render_scan_summary_text(summary_issues)
print("issues_found branch OK")

# A non-applicable module is not a failure, but an all-skipped scan has not
# actually tested anything and must never be labelled clean.
scan_skipped = ScanRecord(target=target, status=TaskStatus.COMPLETED, start_time="t0", end_time="t1")
tasks_skipped = [TaskRecord(scan_id=scan_skipped.id, module="ssl_tls", status=TaskStatus.SKIPPED, error="HTTP target")]
summary_skipped = build_scan_summary(scan_skipped, tasks_skipped, [])
assert summary_skipped["overall"] == "incomplete"
assert summary_skipped["module_counts"]["skipped"] == 1
print("all-skipped scan summary is incomplete OK")

print("\nALL SCAN SUMMARY TESTS OK")
