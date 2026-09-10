"""Scanner API (spec §50-§51, §54) -- the only interface Burp Extension /
Web UI / future CLI ever talk to (spec §50: none of them are allowed to
depend on Orchestrator internals directly).

Localhost-only access (spec §54) is enforced at the network boundary, NOT
inside this app -- an in-app "reject if request.client.host isn't
127.0.0.1" check was tried and removed: verified against the real running
Docker container, a host-machine curl to the published port arrives at
this process as Docker's bridge gateway address (e.g. 172.20.0.1), not
127.0.0.1, because Docker's port-publishing NATs the source address. That
check ended up blocking legitimate local traffic instead of blocking
anything real. The actual boundary is:
  - direct run (see __main__ below): uvicorn binds host="127.0.0.1", so the
    OS itself refuses any non-loopback connection before this code ever runs.
  - Docker (see Dockerfile CMD): binds 0.0.0.0 *inside* the container (required
    for Docker's NAT to reach it at all), and docker-compose.yml's port
    mapping is "127.0.0.1:8000:8000" -- Docker only publishes the port on the
    host's loopback interface, so no other machine on the network can reach
    it either way.
"""

from __future__ import annotations

import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from analyzers.js_analyzer import JsAnalyzer
from orchestrator.event_log import setup_event_log
from orchestrator.manager import Orchestrator
from orchestrator.scan_summary import describe_finding
from orchestrator.version_manifest import build_version_manifest
from safety.policy import HttpSafetyPolicy, SafetyPolicyEngine
from storage.cve_db import CveDB
from storage.db import ScannerDB
from storage.eol_db import EolDB
from storage.models import Finding, ScanRecord, ScanTarget, TaskRecord, TaskStatus
from wrappers.crawler_wrapper import CrawlerWrapper
from wrappers.crypto_identifier_wrapper import CryptoIdentifierWrapper
from wrappers.default_content_wrapper import DefaultContentWrapper, PathTraversalWrapper
from wrappers.ffuf_wrapper import FfufWrapper
from wrappers.gobuster_wrapper import GobusterWrapper
from wrappers.infra_vuln_wrapper import InfraVulnWrapper
from wrappers.jwt_analyzer_wrapper import JwtAnalyzerWrapper
from wrappers.safe_http_audit_wrapper import SAFE_AUDIT_WRAPPERS
from wrappers.ssl_tls_wrapper import SSLTLSWrapper
from wrappers.xss_reflected_wrapper import XssReflectedWrapper
from wrappers.xss_stored_wrapper import XssStoredWrapper

SCANNER_CORE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = SCANNER_CORE_ROOT.parent / "scanner-data"


def normalize_http_target(value: str) -> tuple[str, str]:
    """Normalize the common URL input and return (URL, canonical scope host)."""
    target = (value or "").strip()
    if not target:
        raise ValueError("target URL is required")
    if "," in target or any(ch.isspace() for ch in target):
        raise ValueError("target URL contains invalid characters")
    if "://" not in target:
        target = "http://" + target
    try:
        parsed = urlsplit(target)
        port = parsed.port  # forces malformed-port validation
    except ValueError as exc:
        raise ValueError(f"invalid target URL: {exc}") from exc
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("target URL scheme must be http or https")
    if not parsed.hostname:
        raise ValueError("target URL must include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentials are not allowed in the target URL")
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("target URL port must be between 1 and 65535")
    return target, parsed.hostname


def build_orchestrator(data_dir: Path) -> Orchestrator:
    setup_event_log(data_dir / "logs")  # spec §57 -- scanner-data/logs/scanner.log
    db = ScannerDB(data_dir / "db" / "scanner.sqlite")
    engine = SafetyPolicyEngine(HttpSafetyPolicy())
    cve_db = CveDB(data_dir / "db" / "cve.sqlite")
    eol_db = EolDB(data_dir / "db" / "eol.sqlite")
    orch = Orchestrator(db, engine, results_root=data_dir / "results", cve_db=cve_db, eol_db=eol_db)
    for wrapper_cls in (
        SSLTLSWrapper, CrawlerWrapper, DefaultContentWrapper, PathTraversalWrapper,
        InfraVulnWrapper, FfufWrapper, GobusterWrapper, JsAnalyzer,
        XssReflectedWrapper, XssStoredWrapper,
        JwtAnalyzerWrapper, CryptoIdentifierWrapper,
        *SAFE_AUDIT_WRAPPERS,
    ):
        orch.register_wrapper(wrapper_cls(engine.policy))
    return orch


@asynccontextmanager
async def lifespan(app: FastAPI):
    data_dir = Path(os.environ.get("SCANNER_DATA_DIR", str(DEFAULT_DATA_DIR)))
    data_dir.mkdir(parents=True, exist_ok=True)
    app.state.orchestrator = build_orchestrator(data_dir)
    yield
    orch = app.state.orchestrator
    orch.db.close()
    if orch.cve_db is not None:
        orch.cve_db.close()
    if orch.eol_db is not None:
        orch.eol_db.close()


app = FastAPI(title="Security Toolkit Scanner API", version="0.1.0", lifespan=lifespan)

# spec §44-§49 Web UI -- Result Viewer 정적 SPA, /ui에서 서빙 (html=True라
# /ui/ 요청 시 index.html을 자동으로 내려줌). API 라우트와 경로가 겹치지
# 않도록 /ui 하위에만 마운트한다.
WEB_STATIC_DIR = SCANNER_CORE_ROOT / "web" / "static"
if WEB_STATIC_DIR.is_dir():
    app.mount("/ui", StaticFiles(directory=str(WEB_STATIC_DIR), html=True), name="web-ui")


# spec review finding (2026-09-06): the API root ("/") had no route at all,
# so the address a user naturally tries first (http://host:8000/, with no
# /ui suffix) returned a bare 404 -- indistinguishable from "the Web UI was
# never actually shipped" even though /ui/ itself works fine. Redirecting
# the root to /ui/ makes the obvious address the working one.
@app.get("/", include_in_schema=False)
def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/ui/")


def get_orchestrator(request: Request) -> Orchestrator:
    return request.app.state.orchestrator


# -- request/response schemas ------------------------------------------------
class CreateScanRequest(BaseModel):
    target: str
    scope_host: str = ""


class RunModuleRequest(BaseModel):
    module: str
    args: dict = {}


class TaskOut(BaseModel):
    id: str
    scan_id: str
    module: str
    status: str
    start_time: str
    end_time: str
    error: str
    result_file: str

    @classmethod
    def from_record(cls, t: TaskRecord) -> "TaskOut":
        return cls(
            id=t.id, scan_id=t.scan_id, module=t.module, status=t.status.value,
            start_time=t.start_time, end_time=t.end_time, error=t.error, result_file=t.result_file,
        )


class ScanOut(BaseModel):
    id: str
    target: str
    scope_host: str
    status: str
    start_time: str
    end_time: str
    result_dir: str

    @classmethod
    def from_record(cls, s: ScanRecord) -> "ScanOut":
        return cls(
            id=s.id, target=s.target.value, scope_host=s.target.scope_host, status=s.status.value,
            start_time=s.start_time, end_time=s.end_time, result_dir=s.result_dir,
        )


class FindingOut(BaseModel):
    id: str
    scan_id: str
    task_id: str
    target: str
    scanner: str
    finding: str
    description: str
    severity: str
    host: str
    port: int | None
    protocol: str
    service: str
    technology: str
    evidence: str
    timestamp: str
    raw_ref: str

    @classmethod
    def from_record(cls, f: Finding) -> "FindingOut":
        return cls(**{**f.to_dict(), "description": describe_finding(f)})


# -- health -------------------------------------------------------------------
@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/version")
def version(orch: Orchestrator = Depends(get_orchestrator)) -> dict:
    """spec §63 -- what's actually running right now: Scanner Core version
    plus the CVE/EOL local data's rule count + content fingerprint (spec
    review finding 2026-09-06: nothing exposed this before)."""
    return build_version_manifest(orch.cve_db, orch.eol_db)


# -- targets (spec §51 Target 조회) --------------------------------------------
@app.get("/targets")
def list_targets(orch: Orchestrator = Depends(get_orchestrator)) -> list[dict]:
    return [t.to_dict() for t in orch.db.list_targets()]


# -- scans (spec §51 Scan 생성/중지/상태조회/결과조회) --------------------------
@app.post("/scans", response_model=ScanOut)
def create_scan(req: CreateScanRequest, orch: Orchestrator = Depends(get_orchestrator)) -> ScanOut:
    if req.scope_host == "decoder":
        # Decoder-only modules intentionally use a JWT/hash as ScanTarget;
        # preserve that established API contract while keeping the storage
        # scope a fixed server-controlled name.
        target, scope_host = req.target, "decoder"
    else:
        try:
            target, scope_host = normalize_http_target(req.target)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        # Do not trust caller-provided scope_host for filesystem paths or
        # scope enforcement. It must always match the parsed target host.
    scan = orch.create_scan(target, scope_host=scope_host)
    return ScanOut.from_record(scan)


@app.get("/scans", response_model=list[ScanOut])
def list_scans(target_id: str | None = None, orch: Orchestrator = Depends(get_orchestrator)) -> list[ScanOut]:
    return [ScanOut.from_record(s) for s in orch.db.list_scans(target_id=target_id)]


@app.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, orch: Orchestrator = Depends(get_orchestrator)) -> ScanOut:
    scan = orch.db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return ScanOut.from_record(scan)


@app.post("/scans/{scan_id}/stop", response_model=ScanOut)
def stop_scan(scan_id: str, orch: Orchestrator = Depends(get_orchestrator)) -> ScanOut:
    scan = orch.db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    # spec §60 Process Termination (spec review finding 2026-09-06: this used
    # to only cancel still-PENDING Tasks and explicitly left RUNNING ones
    # alone) -- cancel_task() now actually kills a RUNNING Task's subprocess
    # via Orchestrator.process_registry, so both states are stoppable here.
    for task in orch.db.list_tasks_for_scan(scan_id):
        if task.status in (TaskStatus.PENDING, TaskStatus.RUNNING):
            orch.cancel_task(task.id)
    if scan.status in (TaskStatus.PENDING, TaskStatus.RUNNING):
        orch.db.update_scan_status(scan_id, TaskStatus.CANCELLED, end_time=datetime.now(timezone.utc).isoformat())
    return ScanOut.from_record(orch.db.get_scan(scan_id))


@app.post("/scans/{scan_id}/complete", response_model=ScanOut)
def complete_scan(scan_id: str, orch: Orchestrator = Depends(get_orchestrator)) -> ScanOut:
    """Explicit finalize call for a client (Burp Extension/Web UI) that
    knows it's done adding Tasks to this scan -- the auto-complete in
    _execute_in_background only fires after a Task finishes, so a scan with
    zero Tasks (or one whose caller wants to stop waiting) would otherwise
    never leave PENDING/RUNNING without this."""
    if orch.db.get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail="scan not found")
    scan = orch.complete_scan(scan_id)
    return ScanOut.from_record(scan)


@app.get("/scans/{scan_id}/results")
def get_scan_results(scan_id: str, orch: Orchestrator = Depends(get_orchestrator)) -> dict:
    scan = orch.db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    tasks = orch.db.list_tasks_for_scan(scan_id)
    findings = orch.db.list_findings(scan_id=scan_id)
    return {
        "scan": ScanOut.from_record(scan).model_dump(),
        "tasks": [TaskOut.from_record(t).model_dump() for t in tasks],
        "findings": [FindingOut.from_record(f).model_dump() for f in findings],
    }


@app.get("/scans/{scan_id}/summary")
def get_scan_summary(scan_id: str, orch: Orchestrator = Depends(get_orchestrator)) -> dict:
    """spec review finding (2026-09-06) -- the same 성공/실패/취소 +
    심각도별 이슈 roll-up every client (Burp/Web UI/scripts) can rely on,
    computed fresh from the DB rather than only ever existing as text
    printed once into Burp's own log (also mirrored to
    scan-summary.json/.txt in the scan's result_dir once it finishes)."""
    summary = orch.get_scan_summary(scan_id)
    if summary is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return summary


# -- tasks / modules (spec §51 Module 실행/Task 상태조회) -----------------------
_TERMINAL_TASK_STATUSES = (TaskStatus.COMPLETED, TaskStatus.SKIPPED, TaskStatus.FAILED, TaskStatus.CANCELLED)


def _execute_in_background(orch: Orchestrator, task_id: str, kwargs: dict) -> None:
    # spec review finding (2026-09-06): nothing used to call complete_scan()
    # outside of tests -- every real scan sat at status=running forever with
    # no end_time, confirmed against the live scanner.sqlite (10/10 scans
    # stuck). A scan is "done" once every Task under it has reached a
    # terminal state; re-checking after each Task finishes (rather than only
    # once at the very end) means this converges correctly however many
    # Tasks get added to a scan, in whatever order they finish.
    task = orch.execute_task(task_id, **kwargs)
    remaining = orch.db.list_tasks_for_scan(task.scan_id)
    if remaining and all(t.status in _TERMINAL_TASK_STATUSES for t in remaining):
        orch.complete_scan(task.scan_id)


@app.post("/scans/{scan_id}/tasks", response_model=TaskOut)
def run_module(
    scan_id: str, req: RunModuleRequest, background_tasks: BackgroundTasks,
    orch: Orchestrator = Depends(get_orchestrator),
) -> TaskOut:
    if orch.db.get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail="scan not found")
    try:
        task = orch.create_task(scan_id, req.module)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    background_tasks.add_task(_execute_in_background, orch, task.id, req.args)
    return TaskOut.from_record(task)


@app.get("/tasks/{task_id}", response_model=TaskOut)
def get_task(task_id: str, orch: Orchestrator = Depends(get_orchestrator)) -> TaskOut:
    task = orch.db.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    return TaskOut.from_record(task)


# spec §61-62: execute_task()가 항상 남기는 {module}.json(성공시)/
# {module}.stderr.txt/{module}.meta.json을 Web UI에서 직접 읽을 수 있는
# 유일한 경로 -- 지금까지 Web UI의 "Raw Results"는 이 파일들의 *경로 문자열*
# 만 보여줬고 내용을 열람/다운로드할 방법이 없었다 (spec review finding
# 2026-09-06).
#
# task.module은 POST /scans/{id}/tasks의 req.module로 사용자가 직접 지정하는
# 값이라 DB에 임의 문자열이 그대로 저장될 수 있다 (execute_task()가 실행
# 단계에서 SafetyPolicyEngine으로 막긴 하지만, 그건 "실행"을 막을 뿐 DB에
# 남는 문자열 자체를 검증하지 않는다) -- 그 값을 그대로 파일 경로에 이어붙이면
# Path Traversal이 된다. 실제 모듈 이름은 전부 영문 소문자+밑줄뿐이므로
# 화이트리스트로 그 형태가 아닌 값은 조용히 404로 처리한다.
_SAFE_MODULE_NAME = re.compile(r"^[A-Za-z0-9_]+$")


@app.get("/tasks/{task_id}/raw")
def get_task_raw(task_id: str, orch: Orchestrator = Depends(get_orchestrator)) -> dict:
    task = orch.db.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    if not _SAFE_MODULE_NAME.match(task.module):
        raise HTTPException(status_code=404, detail="no raw artifacts found for this task")
    scan = orch.db.get_scan(task.scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    result_dir = Path(scan.result_dir)
    artifacts: dict[str, str] = {}
    stem = f"{task.module}.{task.id}"
    qualified_paths = [result_dir / f"{stem}{suffix}" for suffix in (".json", ".stderr.txt", ".meta.json")]
    use_legacy = not any(path.is_file() for path in qualified_paths)
    for suffix, key in ((".json", "result"), (".stderr.txt", "stderr"), (".meta.json", "meta")):
        path = result_dir / f"{task.module if use_legacy else stem}{suffix}"
        if path.is_file():
            artifacts[key] = path.read_text(encoding="utf-8", errors="replace")
    if not artifacts:
        raise HTTPException(status_code=404, detail="no raw artifacts found for this task")
    return artifacts


@app.post("/tasks/{task_id}/cancel", response_model=TaskOut)
def cancel_task(task_id: str, orch: Orchestrator = Depends(get_orchestrator)) -> TaskOut:
    task = orch.cancel_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    return TaskOut.from_record(task)


# -- issues (spec §51 Issue 조회) -----------------------------------------------
@app.get("/issues", response_model=list[FindingOut])
def list_issues(scan_id: str | None = None, orch: Orchestrator = Depends(get_orchestrator)) -> list[FindingOut]:
    return [FindingOut.from_record(f) for f in orch.db.list_findings(scan_id=scan_id)]


# -- technologies (spec §16 Technology Detection) ------------------------------
@app.get("/technologies")
def list_technologies(scan_id: str | None = None, orch: Orchestrator = Depends(get_orchestrator)) -> list[dict]:
    return [t.to_dict() for t in orch.db.list_technologies(scan_id=scan_id)]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
