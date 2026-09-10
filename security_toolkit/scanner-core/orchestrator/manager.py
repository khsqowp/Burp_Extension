"""Orchestrator / Task Manager (spec §23-§24) -- central flow every scan
goes through:

    Scan Request -> Task 생성 -> Safety Policy 검증 -> Scanner 실행
                 -> Result Parsing -> Local Storage 저장

Task creation and execution are deliberately two separate calls
(`create_task` / `execute_task`) rather than one -- that's what gives a
caller (the future Scanner API, using FastAPI BackgroundTasks) a real
window to `cancel_task()` a still-PENDING task before it actually starts
(spec §24: Cancelled is one of the 5 required states). `run_module()` is a
synchronous convenience that does both in one call, for direct/CLI/test use
where cancellation isn't relevant.

A failing Task never takes down the Orchestrator itself (spec §58): any
exception from a wrapper is caught and recorded as a Failed Task, and other
Tasks/Scans are unaffected.
"""

from __future__ import annotations

import json
import ipaddress
import re
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from analyzers.technology import extract_from_infra_vuln, extract_from_js_analyzer
from matchers import cve_matcher, eol_matcher
from orchestrator.event_log import log_event
from orchestrator.scan_summary import build_scan_summary, render_scan_summary_text
from orchestrator.version_manifest import build_version_manifest
from safety.policy import SafetyPolicyEngine
from storage.cve_db import CveDB
from storage.db import ScannerDB
from storage.eol_db import EolDB
from storage.models import ScanRecord, ScanTarget, TaskRecord, TaskStatus, Technology
from wrappers.base import ToolWrapper, WrapperParseError


class ProcessRegistry:
    """spec §60 Process Termination -- the one place that knows which
    task_id is backed by which live subprocess right now, so cancel_task()
    (called from a different thread/request than the one running the scan)
    can actually kill it instead of only being able to touch Tasks that
    haven't started yet (spec review finding 2026-09-06: previously "stop"
    only ever cancelled still-PENDING Tasks)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._procs: dict[str, subprocess.Popen] = {}

    def register(self, task_id: str, proc: subprocess.Popen) -> None:
        with self._lock:
            self._procs[task_id] = proc

    def unregister(self, task_id: str) -> None:
        with self._lock:
            self._procs.pop(task_id, None)

    def kill(self, task_id: str) -> bool:
        """Terminate the process backing task_id, if one is currently
        registered. Blocks until it has actually exited (falling back to
        kill() if terminate() doesn't finish it quickly), so a caller that
        gets True back can rely on the process really being gone."""
        with self._lock:
            proc = self._procs.get(task_id)
        if proc is None or proc.poll() is not None:
            return False
        try:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
            return True
        except Exception:  # noqa: BLE001 -- best-effort; a kill failing must not crash the request handling it
            return False

# spec §16/§19/§21: which modules' raw JSON carries Technology signals worth
# running the CVE/EOS-EOL Matchers against, and how to extract them.
_TECHNOLOGY_EXTRACTORS = {
    "infra_vuln": lambda data, scan: extract_from_infra_vuln(data, host=scan.target.scope_host or scan.target.value, scan_id=scan.id),
    "js_analyzer": lambda data, scan: extract_from_js_analyzer(data, scan_id=scan.id),
}

# spec §10: which of each module's build_command() kwargs represents a
# caller-controllable "how many requests will this make" value, checked
# against SafetyPolicyEngine.check_request_budget() before the wrapper ever
# runs (spec review finding 2026-09-06).
_BUDGET_KWARG_BY_MODULE = {
    "crawler": "max_pages",
    "ffuf": "wordlist_limit",
    "gobuster": "wordlist_limit",
    "subdomain_discovery": "max_candidates",
    "virtual_host_isolation": "max_candidates",
}

# spec §11 (spec review finding 2026-09-06: check_method()/check_module_method()
# was only ever called from tests -- a caller could pass method="post-form"
# etc. to xss_reflected/xss_stored with zero central policy check).
_METHOD_KWARG_BY_MODULE = {
    "xss_reflected": "method",
    "xss_stored": "method",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _not_applicable_reason(module: str, target: ScanTarget) -> str:
    """Return a reason when a valid module does not apply to this target.

    Applicability is not an execution failure.  Keeping this decision in the
    Core prevents Burp, Web UI, and direct API clients from producing different
    scan verdicts for the same target.
    """
    value = target.value if "://" in target.value else f"http://{target.value}"
    parsed = urlsplit(value)
    hostname = parsed.hostname or target.scope_host
    if module == "ssl_tls" and parsed.scheme.lower() == "http":
        return "TLS 진단은 HTTPS 대상에만 적용됩니다. HTTP 대상이므로 건너뜁니다."
    if module in {"subdomain_discovery", "virtual_host_isolation"}:
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            if "." in hostname:
                return ""
            return "서브도메인 진단은 FQDN 대상에만 적용됩니다. 단일 이름 내부 호스트이므로 건너뜁니다."
        return "서브도메인 진단은 FQDN 대상에만 적용됩니다. IP 대상이므로 건너뜁니다."
    return ""


class Orchestrator:
    def __init__(
        self, db: ScannerDB, policy_engine: SafetyPolicyEngine, results_root: str | Path,
        cve_db: CveDB | None = None, eol_db: EolDB | None = None,
    ) -> None:
        self.db = db
        self.policy_engine = policy_engine
        self.results_root = Path(results_root)
        self.cve_db = cve_db
        self.eol_db = eol_db
        self.wrappers: dict[str, ToolWrapper] = {}
        self.process_registry = ProcessRegistry()
        self._target_locks_guard = threading.Lock()
        self._target_locks: dict[str, threading.Lock] = {}

    def _target_lock(self, target: ScanTarget) -> threading.Lock:
        """One execution gate per scope host so per-module limits aggregate safely."""
        key = (target.scope_host or target.value).lower()
        with self._target_locks_guard:
            return self._target_locks.setdefault(key, threading.Lock())

    def register_wrapper(self, wrapper: ToolWrapper) -> None:
        self.wrappers[wrapper.module] = wrapper

    # -- scan lifecycle -------------------------------------------------------
    def create_scan(self, target_value: str, scope_host: str = "") -> ScanRecord:
        # spec §46 Domain 기반 조회: 같은 target_value로 여러 번 스캔해도 같은
        # Target 행을 재사용해야 도메인별로 스캔들이 묶인다 -- 매번 새 id를
        # 발급하면 target_id로 필터링한 조회가 항상 스캔 1개짜리로만 나뉜다.
        target = self.db.get_target_by_value(target_value)
        if target is None:
            target = ScanTarget(value=target_value, scope_host=scope_host or target_value)
        elif scope_host and target.scope_host != scope_host:
            # Repair stale/incorrect scope metadata instead of silently
            # reusing it forever for subsequent scans of the same target.
            target.scope_host = scope_host
        result_dir = self._make_result_dir(target.scope_host)
        scan = ScanRecord(target=target, status=TaskStatus.PENDING, start_time=_now_iso(), result_dir=str(result_dir))
        self.db.save_scan(scan)
        log_event("scan_started", scan_id=scan.id, target=target_value, scope_host=target.scope_host)
        # spec §63-64 버전 관리: 이 Scan이 어떤 CVE/EOL 데이터로 실행됐는지
        # 나중에 재분석할 때 알 수 있도록 스냅샷을 결과 폴더에 남긴다.
        try:
            manifest = build_version_manifest(self.cve_db, self.eol_db)
            (result_dir / "versions.json").write_text(
                json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except OSError:
            pass  # best-effort -- must never block scan creation
        return scan

    def _make_result_dir(self, host: str) -> Path:
        # spec §41: results/{domain}/{date}/scan-NNNNNN/
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        safe_host = re.sub(r"[^A-Za-z0-9._-]", "_", host or "unknown").strip(".") or "unknown"
        base = self.results_root / safe_host / date_str
        base.mkdir(parents=True, exist_ok=True)
        existing = [p.name for p in base.glob("scan-*") if p.is_dir()]
        next_n = max((int(n.split("-")[1]) for n in existing), default=0) + 1
        scan_dir = base / f"scan-{next_n:06d}"
        scan_dir.mkdir(parents=True, exist_ok=True)
        return scan_dir

    def complete_scan(self, scan_id: str) -> ScanRecord | None:
        tasks = self.db.list_tasks_for_scan(scan_id)
        # spec review finding (2026-09-06): this used to compute status from
        # "any Task FAILED?" alone, with no check for Tasks still PENDING/
        # RUNNING -- harmless when called once after everything's done, but
        # a real race exists: _execute_in_background's own "are all Tasks
        # terminal" snapshot and this method's internal re-fetch of the Task
        # list aren't atomic with a concurrent create_task() for a new Task
        # on the same scan, so this could still fire and mark the scan
        # COMPLETED while a just-added Task is sitting PENDING. Refusing to
        # finalize while any Task is non-terminal makes this method safe to
        # call from anywhere, any number of times, in any order.
        if any(t.status in (TaskStatus.PENDING, TaskStatus.RUNNING) for t in tasks):
            return self.db.get_scan(scan_id)
        # spec review finding (2026-09-06): this used to be a plain
        # "any FAILED? -> FAILED : COMPLETED" formula with no CANCELLED
        # branch at all, so a scan where every single Task was cancelled
        # (e.g. Stop 버튼을 눌렀는데 그 시점에 실패한 Task가 하나도 없던 경우)
        # was written to the DB as COMPLETED -- directly contradicting its
        # own scan-summary.json ("incomplete") and Burp's own "중지됨" status.
        # FAILED still wins over CANCELLED: a Task that crashed on its own is
        # a stronger signal than one that was merely told to stop.
        if not tasks:
            # A lifecycle may be closed without work, but it was not a
            # successful diagnostic run. Keep Scan status consistent with
            # the summary's `incomplete` verdict.
            status = TaskStatus.FAILED
        elif any(t.status == TaskStatus.FAILED for t in tasks):
            status = TaskStatus.FAILED
        elif any(t.status == TaskStatus.CANCELLED for t in tasks):
            status = TaskStatus.CANCELLED
        else:
            status = TaskStatus.COMPLETED
        self.db.update_scan_status(scan_id, status, end_time=_now_iso())
        log_event("scan_completed", scan_id=scan_id, status=status.value)
        scan = self.db.get_scan(scan_id)
        self._write_scan_summary(scan, tasks)
        return scan

    def _write_scan_summary(self, scan: ScanRecord, tasks: list[TaskRecord]) -> None:
        """spec review finding (2026-09-06): persist the same roll-up any
        client can already fetch via get_scan_summary() so it also survives
        on disk (scan-summary.json/.txt in the scan's own result_dir), same
        philosophy as versions.json -- best-effort, must never block scan
        completion if the disk write fails."""
        findings = self.db.list_findings(scan_id=scan.id)
        summary = build_scan_summary(scan, tasks, findings)
        try:
            result_dir = Path(scan.result_dir)
            (result_dir / "scan-summary.json").write_text(
                json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            (result_dir / "scan-summary.txt").write_text(render_scan_summary_text(summary), encoding="utf-8")
        except OSError:
            pass

    def get_scan_summary(self, scan_id: str) -> dict | None:
        scan = self.db.get_scan(scan_id)
        if scan is None:
            return None
        tasks = self.db.list_tasks_for_scan(scan_id)
        findings = self.db.list_findings(scan_id=scan_id)
        return build_scan_summary(scan, tasks, findings)

    # -- task lifecycle -------------------------------------------------------
    def create_task(self, scan_id: str, module: str) -> TaskRecord:
        scan = self.db.get_scan(scan_id)
        if scan is None:
            raise ValueError(f"unknown scan_id: {scan_id}")
        # spec review finding (2026-09-06): a caller that registers modules
        # sequentially (create Task 1 -> wait for it -> create Task 2, which
        # is exactly how the Burp Extension's runScan() works) could see the
        # scan auto-complete after Task 1 alone (api/main.py's
        # _execute_in_background checks "are all *currently existing* Tasks
        # terminal", which Task 1 alone satisfies) before Task 2 is even
        # created -- and nothing then flipped it back to RUNNING while Task 2
        # was actually running, since execute_task() only does that from
        # PENDING. Reopening here closes that window at the moment a new
        # Task is added, not just once it starts executing.
        if scan.status == TaskStatus.CANCELLED:
            raise ValueError(f"scan {scan_id} is cancelled; create a new scan instead")
        if scan.status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
            self.db.update_scan_status(scan_id, TaskStatus.RUNNING)
        task = TaskRecord(scan_id=scan_id, module=module, status=TaskStatus.PENDING)
        self.db.save_task(task)
        return task

    def cancel_task(self, task_id: str) -> TaskRecord | None:
        task = self.db.get_task(task_id)
        if task is None:
            return None
        if task.status == TaskStatus.PENDING:
            self.db.update_task_status(task_id, TaskStatus.CANCELLED, end_time=_now_iso())
            log_event("task_cancelled", task_id=task_id, scan_id=task.scan_id, module=task.module, was="pending")
            return self.db.get_task(task_id)
        if task.status == TaskStatus.RUNNING:
            # spec §60 Process Termination (spec review finding 2026-09-06:
            # this used to be a no-op for RUNNING tasks -- "새 PENDING Task만
            # 취소한다"). _finish() below is the guard that stops the
            # executing thread's own FAILED/COMPLETED write from clobbering
            # this CANCELLED status once its now-killed subprocess exits.
            killed = self.process_registry.kill(task_id)
            # A RUNNING task may still be waiting on the per-target execution
            # gate and therefore have no subprocess yet. Mark it cancelled in
            # either case; execute_task re-checks this state after acquiring
            # the gate and will not start a process.
            self.db.update_task_status(task_id, TaskStatus.CANCELLED, end_time=_now_iso())
            log_event(
                "task_cancelled", task_id=task_id, scan_id=task.scan_id,
                module=task.module, was="running", process_killed=killed,
            )
            return self.db.get_task(task_id)
        return task  # already finished -- nothing to cancel

    def execute_task(self, task_id: str, *, confirm: bool = False, **kwargs) -> TaskRecord:
        task = self.db.get_task(task_id)
        if task is None:
            raise ValueError(f"unknown task_id: {task_id}")
        if task.status == TaskStatus.CANCELLED:
            return task  # cancelled before it got a chance to run
        if task.status != TaskStatus.PENDING:
            raise ValueError(f"task {task_id} is not pending (status={task.status.value})")

        scan = self.db.get_scan(task.scan_id)
        if scan is None:
            raise ValueError(f"task {task_id} references unknown scan {task.scan_id}")

        decision = self.policy_engine.evaluate(task.module, confirm=confirm)
        if not decision.allowed:
            log_event("policy_blocked", task_id=task_id, scan_id=task.scan_id, module=task.module, reason=decision.reason)
            return self._finish(task, TaskStatus.FAILED, error=decision.reason)

        wrapper = self.wrappers.get(task.module)
        if wrapper is None:
            return self._finish(task, TaskStatus.FAILED, error=f"no wrapper registered for module '{task.module}'")

        # spec §10 (spec review finding 2026-09-06: check_request_budget() was
        # only ever called from tests -- crawler's depth/max_pages had NO clamp
        # at all against policy when a caller supplied them explicitly, and
        # ffuf/gobuster's wordlist_limit clamped against a hardcoded 20000
        # ceiling instead of the actual configured policy.max_request_count,
        # so a caller could still blow past the real budget). This is a second,
        # earlier line of defense in front of each wrapper's own now-corrected
        # clamp (wrappers/crawler_wrapper.py etc.) -- rejects loudly instead of
        # silently substituting a smaller number the caller never asked for.
        budget_key = _BUDGET_KWARG_BY_MODULE.get(task.module)
        if budget_key is not None and kwargs.get(budget_key) is not None:
            budget_decision = self.policy_engine.check_request_budget(kwargs[budget_key])
            if not budget_decision.allowed:
                log_event(
                    "policy_blocked", task_id=task_id, scan_id=task.scan_id, module=task.module,
                    reason=budget_decision.reason,
                )
                return self._finish(task, TaskStatus.FAILED, error=budget_decision.reason)

        method_key = _METHOD_KWARG_BY_MODULE.get(task.module)
        if method_key is not None and kwargs.get(method_key) is not None:
            method_decision = self.policy_engine.check_module_method(task.module, kwargs[method_key])
            if not method_decision.allowed:
                log_event(
                    "policy_blocked", task_id=task_id, scan_id=task.scan_id, module=task.module,
                    reason=method_decision.reason,
                )
                return self._finish(task, TaskStatus.FAILED, error=method_decision.reason)

        # A scan may legitimately retry the same module.  Task-id-qualified
        # names preserve one-to-one provenance instead of letting the later
        # run overwrite the earlier task's RAW/stderr/meta artifacts.
        artifact_stem = f"{task.module}.{task.id}"
        raw_path = Path(scan.result_dir) / f"{artifact_stem}.json"
        stderr_path = Path(scan.result_dir) / f"{artifact_stem}.stderr.txt"
        meta_path = Path(scan.result_dir) / f"{artifact_stem}.meta.json"

        # spec review finding (2026-09-06): 성공한 Task의 stdout만 저장했고,
        # 실패한 Task는 DB error 컬럼에 500자로 잘린 stderr 스니펫만 남았다
        # (spec §62 Raw Data 보존 취지 위반) -- 이제 실패/예외 여부와 무관하게
        # 적용된 옵션과 결과를 항상 파일로 남긴다.
        def _write_meta(**fields) -> None:
            meta = {"module": task.module, "args": kwargs, "start_time": task.start_time, **fields}
            try:
                meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
            except OSError:
                pass

        not_applicable = _not_applicable_reason(task.module, scan.target)
        if not_applicable:
            task.start_time = _now_iso()
            payload = {
                "module": task.module,
                "target": scan.target.value,
                "status": "skipped",
                "reason": not_applicable,
                "findings": [],
                "observations": [{"type": "not_applicable", "message": not_applicable}],
            }
            try:
                raw_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
                task.result_file = str(raw_path)
                _write_meta(status="skipped", reason=not_applicable)
            except OSError as exc:
                return self._finish(task, TaskStatus.FAILED, error=f"skip result persistence failed: {exc}")
            return self._finish(task, TaskStatus.SKIPPED, error=not_applicable)

        try:
            timeout = self.policy_engine.policy.max_scan_duration_seconds
            target_lock = self._target_lock(scan.target)
            if target_lock.locked():
                log_event("task_waiting_target_gate", task_id=task.id, scan_id=task.scan_id, module=task.module)
            with target_lock:
                current = self.db.get_task(task.id)
                if current is not None and current.status == TaskStatus.CANCELLED:
                    return current
                current_scan = self.db.get_scan(scan.id)
                if current_scan is not None and current_scan.status == TaskStatus.PENDING:
                    self.db.update_scan_status(scan.id, TaskStatus.RUNNING)
                task.status = TaskStatus.RUNNING
                task.start_time = _now_iso()
                self.db.save_task(task)
                log_event("task_started", task_id=task_id, scan_id=task.scan_id, module=task.module)
                result, findings = wrapper.run(
                    scan.target, timeout=timeout,
                    on_start=lambda proc: self.process_registry.register(task.id, proc),
                    **kwargs,
                )
                # Capture the actual end of target-facing work before the
                # gate is released. Result persistence may continue afterward,
                # but the next target task must not appear to overlap this one.
                task.end_time = _now_iso()
        except WrapperParseError as exc:
            result = exc.result
            try:
                if result.stdout:
                    raw_path.write_text(result.stdout, encoding="utf-8")
                    task.result_file = str(raw_path)
                    self.db.save_task(task)
                if result.stderr:
                    stderr_path.write_text(result.stderr, encoding="utf-8")
            except Exception as persistence_error:
                _write_meta(exception=str(exc), persistence_error=str(persistence_error))
                return self._finish(task, TaskStatus.FAILED, error=f"{exc}; raw persistence failed: {persistence_error}")
            _write_meta(
                exception=str(exc), exit_code=result.exit_code,
                timed_out=result.timed_out, duration_seconds=result.duration_seconds,
            )
            return self._finish(task, TaskStatus.FAILED, error=str(exc))
        except Exception as exc:  # noqa: BLE001 -- spec §58: 한 모듈 실패가 Core 전체를 죽이면 안 됨
            _write_meta(exception=str(exc))
            return self._finish(task, TaskStatus.FAILED, error=str(exc))
        finally:
            self.process_registry.unregister(task.id)

        _write_meta(exit_code=result.exit_code, timed_out=result.timed_out, duration_seconds=result.duration_seconds)

        try:
            if result.stdout:
                raw_path.write_text(result.stdout, encoding="utf-8")
                task.result_file = str(raw_path)
                log_event("result_saved", task_id=task_id, scan_id=task.scan_id, module=task.module, path=str(raw_path))
            if result.stderr:
                stderr_path.write_text(result.stderr, encoding="utf-8")
                log_event("stderr_saved", task_id=task_id, scan_id=task.scan_id, module=task.module, path=str(stderr_path))

            for finding in findings:
                finding.scan_id = task.scan_id
                finding.task_id = task.id
                finding.raw_ref = task.result_file
                self.db.save_finding(finding)

            if not result.timed_out and result.exit_code == 0:
                self._extract_and_match_technologies(task, scan, result.stdout)
        except Exception as exc:  # storage/parser enrichment must never strand RUNNING state
            _write_meta(persistence_error=str(exc))
            return self._finish(task, TaskStatus.FAILED, error=f"result persistence failed: {exc}")

        if result.timed_out:
            log_event("task_timeout", task_id=task_id, scan_id=task.scan_id, module=task.module)
            return self._finish(task, TaskStatus.FAILED, error="timeout")
        if result.exit_code != 0:
            return self._finish(task, TaskStatus.FAILED, error=f"exit code {result.exit_code}: {result.stderr[:500]}")
        return self._finish(task, TaskStatus.COMPLETED)

    def _extract_and_match_technologies(self, task: TaskRecord, scan: ScanRecord, stdout: str) -> None:
        """spec §16/§19/§21: normalize a completed Task's raw output into
        Technology records, persist them, then run the CVE/EOS-EOL Matchers
        against just those (not the whole scan's history) so results stay
        attributable to this Task. Silently a no-op for modules with no
        registered extractor, or when the CVE/EOL DBs weren't configured."""
        extractor = _TECHNOLOGY_EXTRACTORS.get(task.module)
        if extractor is None or not stdout.strip():
            return
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return
        technologies: list[Technology] = extractor(data, scan)
        for tech in technologies:
            self.db.save_technology(tech)
        if not technologies:
            return
        matched = []
        if self.cve_db is not None:
            matched += cve_matcher.match(technologies, self.cve_db)
        if self.eol_db is not None:
            matched += eol_matcher.match(technologies, self.eol_db)
        for finding in matched:
            finding.scan_id = task.scan_id
            finding.task_id = task.id
            finding.raw_ref = task.result_file
            self.db.save_finding(finding)

    def _finish(self, task: TaskRecord, status: TaskStatus, *, error: str = "") -> TaskRecord:
        # spec §60: cancel_task() may have already killed this Task's
        # subprocess and marked it CANCELLED from another thread while
        # wrapper.run() above was unblocking from that kill -- don't let the
        # natural FAILED/COMPLETED write that follows clobber it back.
        current = self.db.get_task(task.id)
        if current is not None and current.status == TaskStatus.CANCELLED:
            return current
        task.status = status
        task.end_time = task.end_time or _now_iso()
        if error:
            task.error = error
        self.db.save_task(task)
        event_name = {
            TaskStatus.COMPLETED: "task_completed",
            TaskStatus.SKIPPED: "task_skipped",
        }.get(status, "task_failed")
        log_event(
            event_name,
            task_id=task.id, scan_id=task.scan_id, module=task.module, error=error,
        )
        return task

    def run_module(self, scan_id: str, module: str, **kwargs) -> TaskRecord:
        """create_task() + execute_task() in one call -- direct/CLI/test use
        where there's no window (or need) for cancellation."""
        task = self.create_task(scan_id, module)
        return self.execute_task(task.id, **kwargs)
