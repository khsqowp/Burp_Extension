"""Safety Policy Engine (spec §9-§12) -- every Scanner/Tool Wrapper must go
through this before touching a customer target. Nothing here talks to a
network; it only decides whether a task is allowed to run and what HTTP
pacing limits apply, exactly like spec §9's diagram:

    Safety Policy
         |
    ffuf / nmap / XSS -> Wrapper / Scanner
"""

from __future__ import annotations

from dataclasses import dataclass, field

from storage.models import RiskLevel

# spec §11: 자동 탐색은 기본적으로 GET/HEAD 중심, POST/PUT/DELETE/PATCH는
# 기본 실행 대상에서 제외 (필요한 개별 진단 기능에서 별도로 통제).
DEFAULT_ALLOWED_METHODS: tuple[str, ...] = ("GET", "HEAD")

# spec §12: 모든 Scanner/Payload는 SAFE/CAUTION/BLOCKED 중 하나로 분류된다.
# v1 범위(§65)에 있는 모듈만 등록 -- 등록되지 않은 module은 알수없음으로 취급해
# 안전하게 CAUTION으로 fail-closed 시킨다 (조용히 SAFE로 취급해 그냥 통과시키지
# 않는다).
MODULE_RISK: dict[str, RiskLevel] = {
    "ssl_tls": RiskLevel.SAFE,
    "crawler": RiskLevel.SAFE,
    "jwt_analyzer": RiskLevel.SAFE,
    "crypto_identifier": RiskLevel.SAFE,
    "js_analyzer": RiskLevel.SAFE,  # single GET + static regex parsing, spec §12 SAFE example
    "default_content": RiskLevel.CAUTION,
    "infra_vuln": RiskLevel.CAUTION,  # nmap
    "ffuf": RiskLevel.CAUTION,
    "gobuster": RiskLevel.CAUTION,
    "xss_reflected": RiskLevel.CAUTION,
    "xss_stored": RiskLevel.CAUTION,  # spec §36: 데이터 변경 가능성 -- 더 보수적으로
    "path_traversal": RiskLevel.CAUTION,  # spec §37: default_content과 분리된 독립 모듈
    "error_page_disclosure": RiskLevel.SAFE,
    "http_methods": RiskLevel.SAFE,
    "directory_listing": RiskLevel.SAFE,
    "server_header": RiskLevel.SAFE,
    "security_headers": RiskLevel.SAFE,
    "subdomain_discovery": RiskLevel.SAFE,
    "virtual_host_isolation": RiskLevel.SAFE,
}

# spec §11 "필요한 진단 기능에서 별도로 통제": xss_reflected/xss_stored는
# GET/HEAD 외의 값도 명시적으로 허용받는 개별 모듈이다 -- 값은 일반 HTTP verb가
# 아니라 각 wrapper가 감싼 스크립트의 --method 인코딩 이름(xss_reflected_
# scanner.py/xss_stored_scanner.py의 --method choices)과 일치해야 한다.
# 여기 없는 모듈은 SafetyPolicyEngine.check_module_method()에서 기본
# policy.allowed_methods(GET/HEAD)로 fallback한다 (spec review finding
# 2026-09-06: method 파라미터가 있는 모듈인데도 실행 경로에서 전혀 검사되지
# 않았음).
MODULE_ALLOWED_METHODS: dict[str, tuple[str, ...]] = {
    "xss_reflected": ("get", "post-form", "post-json"),
    "xss_stored": ("get", "post-form", "post-json"),
}


@dataclass
class HttpSafetyPolicy:
    """spec §10 -- 중앙에서 관리되는 HTTP 진단 정책. 초기 기본값은 보수적으로."""

    max_requests_per_second: float = 5.0
    max_concurrent_requests: int = 3
    timeout_seconds: float = 10.0
    retry_count: int = 1
    redirect_count: int = 3
    max_crawl_depth: int = 3
    max_request_count: int = 500
    max_scan_duration_seconds: int = 900
    allowed_methods: tuple[str, ...] = DEFAULT_ALLOWED_METHODS

    def __post_init__(self) -> None:
        if self.max_requests_per_second <= 0:
            raise ValueError("max_requests_per_second must be positive")
        if self.max_concurrent_requests <= 0:
            raise ValueError("max_concurrent_requests must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_request_count <= 0:
            raise ValueError("max_request_count must be positive")
        if self.max_scan_duration_seconds <= 0:
            raise ValueError("max_scan_duration_seconds must be positive")
        if not self.allowed_methods:
            raise ValueError("allowed_methods must not be empty")


DEFAULT_POLICY = HttpSafetyPolicy()


@dataclass
class PolicyDecision:
    allowed: bool
    risk: RiskLevel
    reason: str = ""


class SafetyPolicyEngine:
    """Single choke point every Orchestrator task must pass through (spec
    §9: "Scanner가 직접 Safety Policy를 우회해서는 안 된다"). Tool Wrapper
    implementations receive the resolved HttpSafetyPolicy, never raw user
    input, and enforce max_request_count/timeout/methods themselves."""

    def __init__(self, policy: HttpSafetyPolicy | None = None) -> None:
        self.policy = policy or DEFAULT_POLICY

    def classify(self, module: str) -> RiskLevel:
        return MODULE_RISK.get(module, RiskLevel.CAUTION)

    def evaluate(self, module: str, *, confirm: bool = False) -> PolicyDecision:
        risk = self.classify(module)
        if risk == RiskLevel.BLOCKED:
            return PolicyDecision(
                allowed=False, risk=risk,
                reason=f"'{module}'은(는) BLOCKED로 분류되어 기본 자동화 환경에서 실행하지 않습니다.",
            )
        if module not in MODULE_RISK:
            return PolicyDecision(
                allowed=False, risk=risk,
                reason=f"'{module}'은(는) 등록되지 않은 module입니다 (알 수 없는 위험도는 기본적으로 차단).",
            )
        # spec review finding (2026-09-06): CAUTION 모듈이 별도 확인 없이 SAFE와
        # 동일하게 자동 허용됐음 -- 특히 xss_stored처럼 대상 데이터를 변경할 수
        # 있는 작업(spec §36)은 명시적 확인이 필요하다. 호출자(Burp Extension/
        # Web UI)가 사용자 액션(체크박스 선택 + 실행 클릭)을 confirm=True로
        # 넘기지 않으면 여기서 막는다 -- SAFE 모듈은 원래도 확인이 필요 없다.
        if risk == RiskLevel.CAUTION and not confirm:
            return PolicyDecision(
                allowed=False, risk=risk,
                reason=f"'{module}'은(는) CAUTION으로 분류되어 명시적 확인(confirm=true) 없이는 실행하지 않습니다.",
            )
        return PolicyDecision(allowed=True, risk=risk)

    def check_method(self, method: str) -> bool:
        return method.upper() in self.policy.allowed_methods

    def check_module_method(self, module: str, method: str) -> PolicyDecision:
        """Like check_method(), but honors a module's own explicit
        exception list (spec §11) instead of only ever checking against the
        blanket GET/HEAD default -- see MODULE_ALLOWED_METHODS."""
        allowed = MODULE_ALLOWED_METHODS.get(module, self.policy.allowed_methods)
        if method.lower() in (m.lower() for m in allowed):
            return PolicyDecision(allowed=True, risk=RiskLevel.SAFE)
        return PolicyDecision(
            allowed=False, risk=RiskLevel.CAUTION,
            reason=f"'{module}'에서 method={method!r}는 허용되지 않습니다 (허용: {', '.join(allowed)}).",
        )

    def check_request_budget(self, planned_requests: int) -> PolicyDecision:
        if planned_requests > self.policy.max_request_count:
            return PolicyDecision(
                allowed=False, risk=RiskLevel.CAUTION,
                reason=(
                    f"요청 {planned_requests}건이 정책 상한 "
                    f"{self.policy.max_request_count}건을 초과합니다."
                ),
            )
        return PolicyDecision(allowed=True, risk=RiskLevel.SAFE)
