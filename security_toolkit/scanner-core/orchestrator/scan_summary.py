"""Scan Summary (spec review finding 2026-09-06) -- a structured, persisted
roll-up of a Scan's outcome (per-module status + severity-grouped findings).

Previously this only ever existed as text printed once into the Burp
Extension's Swing log: it vanished when Burp closed, was never saved
anywhere in Scanner Core's own result directory, and couldn't be retrieved
via the Web UI or API. Generating it here means any client (Burp, Web UI,
a script) gets the exact same authoritative answer to "how did this scan
go", and it survives independently of whichever client happened to be
watching when the scan finished.

`overall` is deliberately three states, not two -- spec review finding: "이슈
없음" was previously conflated with "everything actually succeeded". A scan
where every module failed also has zero findings; that must never be
reported the same way as a scan that genuinely ran clean.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from storage.models import Finding, ScanRecord, TaskRecord, TaskStatus

_KST = timezone(timedelta(hours=9))
_WEEKDAYS_KO = ("월", "화", "수", "목", "금", "토", "일")


def describe_finding(finding: Finding) -> str:
    """Return a concise impact statement without upgrading observations to vulnerabilities."""
    text = finding.finding.lower()
    evidence = finding.evidence.lower()
    if finding.scanner == "ssl_tls":
        if "certificate" in text:
            return "인증서 검증 문제가 있으면 통신 상대의 신원을 신뢰하기 어려워 중간자 공격 위험이 커질 수 있습니다."
        if "tlsv1.0" in text or "tlsv1.1" in text or "sslv" in text:
            return "노후 TLS/SSL 프로토콜 사용은 알려진 암호학적 공격과 통신 내용 노출 위험을 높일 수 있습니다."
        return "TLS 설정 약점은 암호화 통신의 기밀성이나 서버 신뢰성을 떨어뜨릴 수 있습니다."
    if finding.scanner == "infra_vuln":
        return "공개 취약점이 실제로 악용되면 해당 서비스의 정보 노출, 권한 상승 또는 원격 코드 실행으로 이어질 수 있습니다."
    if finding.scanner in ("ffuf", "gobuster", "default_content"):
        if ".git" in text or "backup" in text or "config" in text:
            return "민감 파일이 실제로 열리면 소스 코드, 설정값 또는 인증정보가 외부에 노출될 수 있습니다."
        if "redirect=" in evidence or text.startswith("[3"):
            return "리다이렉트 응답은 경로 존재의 증거가 아니므로 최종 응답을 확인한 뒤 취약점 여부를 판단해야 합니다."
        return "노출된 경로에 민감한 기능이나 파일이 있으면 정보 노출 또는 비인가 접근으로 이어질 수 있습니다."
    if finding.scanner == "error_page_disclosure":
        return "기본 오류 페이지에 제품명·버전·내부 경로가 노출되면 공격자가 환경에 맞는 취약점과 공격 경로를 더 쉽게 선별할 수 있습니다."
    if finding.scanner == "http_methods":
        return "불필요한 HTTP 메서드가 실제 처리되면 서버 자원 변경이나 우회 요청의 공격 표면이 넓어질 수 있습니다."
    if finding.scanner == "directory_listing":
        return "디렉터리 목록이 노출되면 공개 의도가 없던 파일명과 백업·설정 파일을 공격자가 탐색할 수 있습니다."
    if finding.scanner == "server_header":
        return "서버·프레임워크 제품 정보가 노출되면 공격자가 공격 표면을 식별하고 해당 버전에 맞는 공개 취약점을 선별하기 쉬워집니다."
    if finding.scanner == "security_headers":
        return "브라우저 보안 헤더가 없거나 약하면 악성 스크립트 실행·클릭재킹·콘텐츠 변조 시 브라우저의 피해 완화 효과가 줄어들 수 있습니다."
    if finding.scanner == "virtual_host_isolation":
        return "임의 Host 값이 보호 대상 가상 호스트와 같은 응답으로 연결되면 접근통제 우회나 캐시 오염의 공격 표면이 생길 수 있습니다."
    if "xss" in text:
        return "공격 스크립트가 실행되면 사용자 세션 탈취나 화면 변조, 피싱 동작이 발생할 수 있습니다."
    return "이 보안 약점이 악용되면 대상 서비스의 기밀성, 무결성 또는 가용성에 영향을 줄 수 있습니다."


def _format_display_time(iso_str: str) -> str:
    """DB/API에 저장되는 UTC ISO 문자열(예: '2026-09-06T03:44:54.530348+00:00')을
    scan-summary.txt에서만 사람이 읽는 KST 표기(예: '2026-09-06 12:44:54(일)')로
    바꾼다 -- JSON(build_scan_summary/API 응답)은 기계가 소비하는 값이라 ISO
    그대로 둔다. 아직 끝나지 않은 Task/Scan의 end_time처럼 빈 문자열이거나
    형식이 다른 값은 원본을 그대로 반환한다."""
    if not iso_str:
        return iso_str
    try:
        dt = datetime.fromisoformat(iso_str).astimezone(_KST)
    except ValueError:
        return iso_str
    return f"{dt.strftime('%Y-%m-%d %H:%M:%S')}({_WEEKDAYS_KO[dt.weekday()]})"


def build_scan_summary(scan: ScanRecord, tasks: list[TaskRecord], findings: list[Finding]) -> dict:
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

    ok_count = sum(1 for t in tasks if t.status == TaskStatus.COMPLETED)
    skipped_count = sum(1 for t in tasks if t.status == TaskStatus.SKIPPED)
    failed_count = sum(1 for t in tasks if t.status == TaskStatus.FAILED)
    cancelled_count = sum(1 for t in tasks if t.status == TaskStatus.CANCELLED)
    active_count = sum(1 for t in tasks if t.status in (TaskStatus.PENDING, TaskStatus.RUNNING))

    if not findings and ok_count > 0 and failed_count == 0 and cancelled_count == 0 and active_count == 0:
        overall = "clean"  # 전체 양호: 전 모듈 성공 + 이슈 없음
    elif not findings:
        overall = "incomplete"  # 이슈는 없지만 일부/전부 실패·취소 -- "양호" 아님
    else:
        overall = "issues_found"

    return {
        "scan_id": scan.id,
        "target": scan.target.value,
        "scope_host": scan.target.scope_host,
        "status": scan.status.value,
        "start_time": scan.start_time,
        "end_time": scan.end_time,
        "modules": [{"module": t.module, "status": t.status.value, "error": t.error} for t in tasks],
        "module_counts": {
            "completed": ok_count, "skipped": skipped_count, "failed": failed_count, "cancelled": cancelled_count,
            "active": active_count, "total": len(tasks),
        },
        "findings_count": len(findings),
        "findings_by_severity": by_severity,
        "overall": overall,
        "findings": [{**f.to_dict(), "description": describe_finding(f)} for f in findings],
    }


def render_scan_summary_text(summary: dict) -> str:
    counts = summary["module_counts"]
    lines = [
        f"=== Scan Summary: {summary['scan_id']} ===",
        f"Target: {summary['target']} ({summary['scope_host']})",
        f"Status: {summary['status']}  Start: {_format_display_time(summary['start_time'])}  "
        f"End: {_format_display_time(summary['end_time'])}",
        f"Modules: {counts['completed']} completed / {counts.get('skipped', 0)} skipped / {counts['failed']} failed / "
        f"{counts['cancelled']} cancelled (of {counts['total']})",
        "",
    ]
    for m in summary["modules"]:
        line = f"  [{m['module']}] {m['status']}"
        if m["error"]:
            line += f" -- {m['error']}"
        lines.append(line)
    lines.append("")
    if summary["overall"] == "clean":
        lines.append("전체 양호 -- 발견된 이슈 없음")
    elif summary["overall"] == "incomplete":
        lines.append('발견된 이슈는 없지만 모듈이 실패·취소되었거나 전부 비적용임 -- "전체 양호"로 볼 수 없음, 위 모듈별 상태를 확인하세요.')
    else:
        lines.append(f"총 이슈 {summary['findings_count']}건 {summary['findings_by_severity']}")
        for f in summary["findings"]:
            lines.append(f"  · [{f['severity'].upper()}] {f['scanner']}: {f['finding']}")
            lines.append(f"    설명: {f.get('description', '')}")
    return "\n".join(lines)
