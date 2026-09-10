"""Static registry of the other CLI tools in the suite, so proxy_scanner can
give each one its own tab and (where it makes sense) auto-fill its target
from a selected history entry."""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path


_PERSONAL_TOOLS_ROOT = Path(r"E:\temp\tools")

# Kept as its own list (not derived from TOOLS below) because TOOLS_ROOT --
# which TOOLS' own script= fields are built from -- has to be resolved
# before TOOLS can be constructed at all. Mirrors TOOLS' script paths 1:1;
# add a line here whenever a new tool is added to TOOLS.
_REQUIRED_TOOL_SCRIPTS = [
    "site_depth_crawler/crawler.py",
    "default_content_scanner/default_content_scanner.py",
    "infra_vuln_scanner/infra_vuln_scanner.py",
    "ssl_tls_scanner/main.py",
    "xss_reflected_scanner/xss_reflected_scanner.py",
    "xss_stored_scanner/xss_stored_scanner.py",
    "jwt_analyzer/jwt_analyzer.py",
    "crypto_identifier/crypto_identifier.py",
    "ffuf_scanner/ffuf_scanner.py",
    "gobuster_scanner/gobuster_scanner.py",
]


def _has_complete_tools(root: Path) -> bool:
    """Completeness probe (spec: 단일 EXE 휴대용 배포 §4.3 "기능별 자원
    검증 후... 일관되게 선택") -- checks every tool's own script, not just
    crawler.py (design review finding: a single-file check let a partially
    damaged personal path still get selected wholesale, silently breaking
    every *other* tool instead of falling back to the EXE's bundled
    resources where they'd actually be complete)."""
    return all((root / rel).is_file() for rel in _REQUIRED_TOOL_SCRIPTS)


def _tools_root() -> Path:
    """개인 환경 경로 우선, 없거나 불완전하면 EXE 내장 자원(frozen 모드의
    sys._MEIPASS)으로 자동 전환 (spec: 단일 EXE 휴대용 배포 §4.1-4.3).
    build.py는 각 스캐너 스크립트와 최소 워드리스트를 개인 환경과 동일한
    상대 경로 구조로 EXE에 내장하므로, 여기서 루트 하나만 옳게 고르면
    tool_worker.py의 동적 import와 각 스캐너 자신의 Path(__file__) 기준
    상대 경로 계산이 별도 코드 변경 없이 그대로 맞아떨어진다."""
    if _has_complete_tools(_PERSONAL_TOOLS_ROOT):
        return _PERSONAL_TOOLS_ROOT
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", "")
        if meipass and _has_complete_tools(Path(meipass)):
            return Path(meipass)
    # Dev-mode fallback (not frozen, personal path missing/incomplete) --
    # resolve relative to this source file so a differently-located dev
    # checkout still works instead of silently pointing at a dead path.
    return Path(__file__).resolve().parent.parent


TOOLS_ROOT = _tools_root()


@dataclass(frozen=True)
class ToolSpec:
    key: str
    category: str  # tab-strip grouping prefix, Burp-style (Recon / Scanner / Decoder)
    name: str
    script: Path
    target_kind: str  # "url" | "host" | "host_port" | "none" -- what a "send from history" click / the
                       # common target bar fills in ("host_port" also fills a separate --port field)
    description: str  # shown as a header inside the tab so it's clear what the tool is for
    custom_ui: bool = False  # True if this tab has a bespoke layout instead of the auto-generated form

    @property
    def label(self) -> str:
        return f"{self.category} · {self.name}"


TOOLS: list[ToolSpec] = [
    ToolSpec(
        "crawler", "Recon", "Crawler",
        TOOLS_ROOT / "site_depth_crawler" / "crawler.py", "url",
        "링크를 따라가며 사이트 구조를 수집. 깊이(depth)와 페이지 수를 제한해서 서버에 무리 안 가게 크롤링.",
    ),
    ToolSpec(
        "default_content", "Recon", "Default Content Scanner",
        TOOLS_ROOT / "default_content_scanner" / "default_content_scanner.py", "url",
        "설치 시 남는 기본 파일/샘플/테스트 파일, 백업 파일(.bak 등), 경로탐색(Path Traversal) 취약점을 찾음.",
    ),
    ToolSpec(
        "infra_vuln", "Recon", "Infra Vuln Scanner",
        TOOLS_ROOT / "infra_vuln_scanner" / "infra_vuln_scanner.py", "host",
        "nmap으로 포트/서비스 버전을 탐지하고 알려진 취약점(NSE 스크립트 + 버전 대조표)과 매칭.",
    ),
    ToolSpec(
        "ssl_tls", "Recon", "SSL/TLS Scanner",
        TOOLS_ROOT / "ssl_tls_scanner" / "main.py", "host_port",
        "프로토콜/암호스위트/인증서/PFS/HSTS 등 SSL Labs 수준의 TLS 설정 점검, A~F 등급 산출.",
    ),
    ToolSpec(
        "ffuf", "Recon", "ffuf",
        TOOLS_ROOT / "ffuf_scanner" / "ffuf_scanner.py", "url",
        "실제 ffuf.exe를 감싼 범용 퍼저 -- FUZZ 키워드를 URL/헤더/바디 어디에든 넣어 빠르게 대입. "
        "경로 외에도 파라미터 값·헤더 값 등 자유로운 위치를 퍼징할 때 사용.",
    ),
    ToolSpec(
        "gobuster", "Recon", "gobuster",
        TOOLS_ROOT / "gobuster_scanner" / "gobuster_scanner.py", "url",
        "실제 gobuster.exe(dir 모드)를 감싼 디렉터리/파일 브루트포스 -- 와일드카드(SPA 폴백) 응답을 "
        "자동 감지해 오탐을 막아줌. 단순 경로 탐색은 ffuf보다 이쪽이 더 빠르고 직관적.",
    ),
    ToolSpec(
        "xss_reflected", "Scanner", "XSS Reflected",
        TOOLS_ROOT / "xss_reflected_scanner" / "xss_reflected_scanner.py", "url",
        "한 페이지에 마커+특수문자를 넣어 반사되는지, 어떤 컨텍스트에서 이스케이프 없이 살아남는지 확인.",
    ),
    ToolSpec(
        "xss_stored", "Scanner", "XSS Stored",
        TOOLS_ROOT / "xss_stored_scanner" / "xss_stored_scanner.py", "url",
        "입력 페이지 1개에 주입 후 확인 페이지 1개만 검사 -- 저장형 XSS를 크롤링 없이 최소 트래픽으로 확인.",
    ),
    ToolSpec(
        "jwt_analyzer", "Decoder", "JWT Analyzer",
        TOOLS_ROOT / "jwt_analyzer" / "jwt_analyzer.py", "none",
        "JWT를 디코딩하고 구조적 취약점(alg=none, 약한 HMAC 시크릿, 알고리즘 컨퓨전)을 점검. jwt.io 스타일.",
        custom_ui=True,
    ),
    ToolSpec(
        "crypto_identifier", "Decoder", "Crypto Identifier",
        TOOLS_ROOT / "crypto_identifier" / "crypto_identifier.py", "none",
        "정체불명 문자열의 인코딩 체인을 자동 해독하고, 해시 포맷을 추정 -- 무솔트 해시는 워드리스트로 직접 크래킹, "
        "느린 포맷(bcrypt 등)은 hashcat/john 명령만 생성(자동 실행 안 함). 레인보우테이블이 아니라 사전대입 방식.",
    ),
]
