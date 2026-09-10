from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk
from urllib.parse import parse_qsl, urlparse

import app_logging
import log_redaction
from target_context import TargetContext
from tool_registry import ToolSpec

_logger = app_logging.get_logger("tool_tab")

# Mirrors infra_vuln_scanner.py's own NMAP_CANDIDATES / find_nmap() -- kept
# separate (not imported from the tool) because that module isn't safe to
# import into this long-lived GUI process (see tool_worker.py's docstring on
# why every tool runs in its own subprocess). Small enough that duplicating
# it here beats adding IPC just to ask "is nmap installed".
_NMAP_CANDIDATES = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
]


def _find_nmap() -> str | None:
    which = shutil.which("nmap")
    if which:
        return which
    for candidate in _NMAP_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    return None

# Compact unit suffix shown right next to a field's value (e.g. "10 초") instead
# of translating its whole (English, from the underlying CLI tool's argparse
# help=) description into Korean prose -- keeps the CLI tools' own --help
# output untouched while still making units obvious at a glance in the GUI.
UNIT_HINTS: dict[str, str] = {
    "timeout": "초",
    "min_interval": "초",
    "nmap_timeout": "초",
    "depth": "단계",
    "workers": "개",
    "retries": "회",
    "wildcard_probes": "회",
    "baseline_probes": "회",
    "batch_size": "개",
    "limit": "개",
    "top_ports": "개",
    "max_pages": "개",
    "max_requests": "개",
    "traversal_limit": "개",
    "wordlist_limit": "개",
    "version_intensity": "(0~9)",
    "recursion_depth": "단계",
    "js_bundle_limit": "개",
    "spa_candidate_limit": "개",
}

# Comma-separated options whose valid values are a small known closed set --
# render these as checkboxes instead of a free-text CSV field, same idea as
# a dropdown but supporting multi-select (argparse choices= only covers
# single-value options; these are multi-value, so Combobox doesn't fit).
KNOWN_LIST_VALUES: dict[str, list[str]] = {
    "tech": ["tomcat", "apache", "nginx", "iis", "jboss", "db-backups"],
    "bypass_variants": [
        "raw", "html-entity-decimal", "html-entity-hex", "html-entity-named", "url-double-encode", "base64",
    ],
}

# Korean display name + Korean explanation per argparse `dest`, keyed by the
# same dest names introspection returns -- shown instead of/alongside the
# tool's own (English) --help text so the field reads naturally in Korean.
# The CLI's own --option-name is still shown (small, gray) under the label so
# nothing here has to touch the underlying tools' argparse definitions.
KOREAN_OPTIONS: dict[str, dict[str, str]] = {
    # -- positionals / targets --------------------------------------------
    "url": {"label": "대상 URL", "help": "검사할 대상 URL (scheme 포함, 예: https://example.com)."},
    "host": {"label": "대상 호스트", "help": "검사할 호스트명 또는 IP."},
    "target": {"label": "대상 호스트/IP", "help": "검사할 호스트/IP/CIDR (권한 있는 대상만)."},
    "value": {"label": "분석할 문자열", "help": "정체를 분석할 문자열(해시, 인코딩된 값 등)."},
    # -- common load/scope knobs -------------------------------------------
    "min_interval": {"label": "요청 주기", "help": "같은 서버로 보내는 요청 사이 최소 대기 시간. 줄이면 빨라지지만 서버 부하가 커짐."},
    "workers": {"label": "동시 요청 수", "help": "동시에 처리할 최대 요청 수. 늘리면 빨라지지만 서버 부하가 커짐."},
    "timeout": {"label": "요청 제한 시간", "help": "응답을 기다리는 최대 시간. 너무 짧으면 느린 서버에서 오탐(시간초과)이 늘어남."},
    "retries": {"label": "실패 시 재시도", "help": "일시적 연결 실패가 발생했을 때 다시 시도하는 횟수."},
    "max_pages": {"label": "최대 페이지 수", "help": "크롤러가 가져올 수 있는 전체 페이지 상한. 0 = 전체(지정한 깊이/범위 안에서 새 URL이 없을 때까지 탐색)."},
    "max_requests": {"label": "최대 요청 수", "help": "이 기능이 보낼 수 있는 전체 요청 상한 (예상 요청량이 아니라 안전 상한값)."},
    "output": {"label": "결과 형식", "help": "화면에 표시할지, JSON으로 만들지 선택."},
    "output_file": {"label": "결과 저장 파일", "help": "입력한 경우에만 결과를 이 경로에 파일로 추가 저장."},
    "user_agent": {"label": "User-Agent", "help": "요청에 사용할 User-Agent 문자열."},
    "force": {"label": "안전 상한 초과 허용", "help": "요청 수/속도 등 기본 안전 상한을 넘겨서 강제로 실행."},
    "verbose": {"label": "상세 로그", "help": "진행 상황을 자세히 출력."},
    "file": {"label": "파일에서 읽기", "help": "값을 직접 입력하는 대신 이 파일에서 읽음."},
    # -- crawler -------------------------------------------------------------
    "depth": {
        "label": "탐색 깊이",
        "help": "1단계 = 시작 URL만. 2단계 = 시작 페이지에서 발견한 링크까지. 3단계 = 그 다음 페이지에서 발견한 링크까지 "
        "(이하 동일). 화면에 보이는 단계 수는 실제 CLI --depth 값보다 1 큽니다 -- 실행 시 콘솔에 두 값을 함께 표시합니다.",
    },
    "allow_external": {"label": "외부 도메인 링크 따라가기", "help": "켜면 다른 도메인 링크까지 따라감 (검사 범위가 크게 넓어질 수 있음)."},
    "ignore_robots": {"label": "robots.txt 무시", "help": "켜면 robots.txt 규칙을 무시하고 크롤링 (기본은 준수)."},
    "spa_assist": {
        "label": "SPA 보조 탐색",
        "help": "일반 HTML 링크가 없는 SPA(Angular/React 등) 대상일 때 켜세요. 크롤링된 페이지의 JS 번들에서 "
        "API/라우트 경로 후보를 찾아 실제 요청으로 확인합니다 (SPA 기본 응답으로 판별되면 결과에서 제외)."
    },
    "js_bundle_limit": {"label": "JS 번들 최대 다운로드 수", "help": "SPA 보조 탐색에서 내려받을 JS 번들(<script src>) 최대 개수."},
    "spa_candidate_limit": {"label": "SPA 후보 경로 최대 확인 수", "help": "JS 번들에서 추출한 후보 경로 중 실제로 요청해볼 최대 개수."},
    # -- default content scanner ---------------------------------------------
    "tech": {"label": "서버 기술", "help": "어떤 서버 기술의 기본/샘플 파일 목록을 사용할지 선택."},
    "no_generic": {"label": "일반 민감파일 검사 끄기", "help": "내장된 공통 민감/기본 파일 목록 검사를 건너뜀."},
    "no_fingerprint": {"label": "기본 파일 탐지 전체 끄기", "help": "기본 파일 탐지 자체를 건너뜀 (경로탐색만 쓸 때 유용)."},
    "mutate": {"label": "백업 파일 변형 검사", "help": "기본 파일 탐지에서 발견된 경로마다 .bak/~/.old 등 변형도 추가로 확인 (요청 수가 크게 늘어남)."},
    "traversal": {"label": "경로탐색 검사", "help": "경로탐색(Path Traversal/LFI) 페이로드로 퍼징 (요청 수가 크게 늘어남)."},
    "param": {"label": "경로탐색 대상 파라미터", "help": "경로탐색 페이로드를 넣을 쿼리 파라미터 이름."},
    "url_template": {"label": "URL을 FUZZ 템플릿으로 취급", "help": "URL에 있는 FUZZ 문자열 자리에 페이로드를 대입."},
    "target_os": {"label": "대상 OS", "help": "경로탐색 페이로드를 어떤 OS 기준으로 만들지."},
    "traversal_limit": {"label": "경로탐색 최대 시도 수", "help": "경로탐색 페이로드 최대 개수 상한."},
    # -- infra vuln scanner ---------------------------------------------------
    "ports": {"label": "검사 포트 목록", "help": "명시적 포트 목록/범위 (예: 1-1000,3306). 비우면 상위 포트 수 설정을 사용."},
    "top_ports": {"label": "상위 포트 수", "help": "nmap 기준 가장 흔한 포트 N개를 검사 (검사 포트 목록 미지정 시 사용)."},
    "timing": {"label": "nmap 속도", "help": "빠를수록 서버/네트워크에 부담이 커지고 방화벽에 탐지될 가능성도 커짐."},
    "version_intensity": {"label": "서비스 버전 탐지 강도", "help": "0~9, 높을수록 정확하지만 느려짐."},
    "no_vuln_scripts": {"label": "취약점 스크립트 끄기", "help": "NSE 취약점 스크립트 없이 버전 탐지 + 자체 대조표만 사용."},
    "include_intrusive": {"label": "강한 취약점 스크립트 사용", "help": "안전(safe) 항목뿐 아니라 침입성(intrusive) 스크립트까지 사용 -- 대상에 영향을 줄 수 있음."},
    "nmap_timeout": {"label": "전체 실행 제한 시간", "help": "nmap 프로세스 전체에 대한 제한 시간."},
    # -- ssl/tls scanner -------------------------------------------------------
    "port": {"label": "포트", "help": "TLS 대상 포트."},
    "sni": {"label": "SNI 호스트명", "help": "TLS SNI로 보낼 호스트명 (비우면 대상 호스트값 사용)."},
    "scan_all_ips": {"label": "모든 IP 검사", "help": "호스트가 여러 IP로 풀리면 하나만이 아니라 전부 검사."},
    "no_openssl": {"label": "OpenSSL 보조 검사 끄기", "help": "OpenSSL 어댑터를 사용한 보조 점검을 비활성화."},
    "nmap": {"label": "nmap 교차검증", "help": "nmap 결과도 같이 수집해 근거자료로 남김 (교차검증용)."},
    "testssl": {"label": "testssl 교차검증", "help": "testssl.sh 결과도 같이 수집해 근거자료로 남김 (교차검증용)."},
    "policy_dir": {"label": "정책 파일 폴더", "help": "등급 산정 기준 YAML 정책 파일이 있는 폴더."},
    "save_evidence": {"label": "근거 자료 저장", "help": "원시 응답/증거 데이터를 파일로 저장."},
    "evidence_dir": {"label": "근거 자료 저장 폴더", "help": "근거 자료를 저장할 폴더."},
    # -- ffuf / gobuster --------------------------------------------------------
    "wordlist_limit": {"label": "워드리스트 최대 사용 줄 수", "help": "워드리스트가 이보다 크면 앞에서부터 이 개수만큼만 사용 (전체 요청 수의 실질적 상한)."},
    "extensions": {"label": "추가 확장자", "help": "각 후보 경로에 덧붙여서도 시도할 확장자 목록 (예: php,bak,zip)."},
    "match_codes": {"label": "매칭할 상태 코드", "help": "이 상태 코드에 해당하는 응답만 결과로 표시 (콤마/범위, 'all' 가능)."},
    "filter_codes": {"label": "제외할 상태 코드", "help": "이 상태 코드에 해당하는 응답은 결과에서 제외."},
    "filter_size": {"label": "제외할 응답 크기", "help": "이 크기(바이트)의 응답은 결과에서 제외 -- 반복되는 오탐 크기를 걸러낼 때 사용."},
    "exclude_length": {"label": "제외할 응답 크기 (gobuster)", "help": "지정하면 이 값이 항상 우선 적용되고 아래 wildcard 자동 감지는 건너뜀."},
    "no_auto_wildcard": {"label": "wildcard 자동 감지 끄기", "help": "존재하지 않는 경로에도 항상 같은 응답(리다이렉트 등)이 오는 대상을 자동으로 감지해 제외하는 기능을 끔 (기본은 켜짐)."},
    "wildcard_probes": {"label": "wildcard 확인 요청 수", "help": "무작위 경로로 몇 번 확인 요청을 보내 wildcard 여부를 판단할지."},
    "no_auto_baseline": {"label": "기준 응답 자동 감지 끄기", "help": "존재하지 않는 경로도 항상 같은 응답(SPA catch-all, 리다이렉트 등)이 오는 대상을 자동 감지해 최종 요약에서 제외하는 기능을 끔 (기본은 켜짐)."},
    "baseline_probes": {"label": "기준 응답 확인 요청 수", "help": "무작위 경로로 몇 번 확인 요청을 보내 기준(가짜) 응답 여부를 판단할지."},
    "show_baseline_excluded": {"label": "제외된 항목 표시", "help": "기준 응답으로 판별되어 최종 요약에서 제외된 개별 항목까지 나열."},
    "recursion": {"label": "재귀 탐색", "help": "찾은 디렉터리 안으로 들어가서 다시 탐색 (요청 수가 크게 늘어날 수 있음)."},
    "recursion_depth": {"label": "재귀 탐색 깊이", "help": "재귀 탐색을 몇 단계까지 들어갈지."},
    "data": {"label": "요청 본문", "help": "POST/PUT 본문 (FUZZ 키워드 포함 가능)."},
    "status_codes": {"label": "매칭할 상태 코드", "help": "이 상태 코드만 결과로 표시 (지정하면 '제외할 상태 코드' 대신 이쪽이 적용됨)."},
    "exclude_status_codes": {"label": "제외할 상태 코드", "help": "이 상태 코드는 결과에서 제외 (기본 404)."},
    "add_slash": {"label": "경로 끝에 / 추가", "help": "각 요청 경로 끝에 슬래시를 붙여서도 시도."},
    "follow_redirect": {"label": "리다이렉트 따라가기", "help": "끄면 리다이렉트 대상만 표시하고 따라가지 않음(기본)."},
    "insecure": {"label": "TLS 인증서 검증 생략", "help": "자체 서명 인증서 등 TLS 오류를 무시하고 진행."},
    # -- xss reflected/stored --------------------------------------------------
    "method": {"label": "요청 방식", "help": "GET / 폼 POST / JSON POST 중 페이로드를 어떤 방식으로 보낼지."},
    "params": {"label": "검사 파라미터", "help": "퍼징할 쿼리/폼/JSON 파라미터 이름 목록 (쉼표 구분)."},
    "cookie_params": {"label": "쿠키 파라미터", "help": "퍼징할 쿠키 이름 목록."},
    "header_params": {"label": "헤더 파라미터", "help": "퍼징할 요청 헤더 이름 목록."},
    "base_params": {"label": "기준 파라미터 (고정값)", "help": "테스트 대상이 아닌 파라미터에 고정으로 넣어줄 값 ('k=v&k2=v2' 형식)."},
    "base_json": {"label": "기준 JSON 본문 (고정값)", "help": "테스트 대상이 아닌 JSON 필드에 고정으로 넣어줄 값."},
    "cookies": {"label": "기준 쿠키", "help": "모든 요청에 공통으로 실어 보낼 쿠키 (예: 로그인 세션)."},
    "headers": {"label": "기준 헤더", "help": "모든 요청에 공통으로 실어 보낼 헤더 (여러 개 입력 가능)."},
    "bypass_variants": {"label": "우회 인코딩 검사", "help": "필터 우회용 인코딩 변형까지 추가로 시도 (요청 수가 늘어남)."},
    "batch_size": {"label": "한 요청에 검사할 파라미터", "help": "한 번의 요청에 몇 개 파라미터를 같이 채워 보낼지."},
    "check_url": {"label": "확인 페이지 URL", "help": "주입한 값이 저장되어 나타나는지 확인할 페이지. 반드시 입력해야 함."},
    # -- jwt / crypto identifier ------------------------------------------------
    "crack": {"label": "사전대입 크랙 시도", "help": "무솔트 해시로 추정되면 워드리스트로 직접 대입해봄."},
    "wordlist": {"label": "워드리스트", "help": "탐색/시도에 사용할 값 목록 파일 (경로 후보 또는 크랙용 비밀번호 후보)."},
    "limit": {"label": "최대 시도 단어 수", "help": "크랙 시도 시 워드리스트에서 최대 몇 단어까지 시도할지."},
    "crack_secret": {"label": "HMAC 시크릿 크랙 시도", "help": "HS256/384/512 시크릿을 워드리스트로 크랙 시도."},
    "gen_none": {"label": "alg=none 위조 토큰 생성", "help": "서명 검증 우회용 alg=none 변형 토큰을 만들어 보여줌."},
    "confusion_pubkey": {"label": "공개키 (컨퓨전용)", "help": "RS/ES/PS -> HMAC 알고리즘 컨퓨전 PoC를 만들 때 사용할 서버 공개키(PEM) 경로."},
    "confusion_alg": {"label": "컨퓨전 대상 HMAC 알고리즘", "help": "컨퓨전 PoC에서 흉내낼 HMAC 알고리즘."},
}

# Which options show up under "주요 설정" (always visible) vs. tucked away
# behind "고급 설정 펼치기" for each tool -- unlisted dests among a tool's
# optionals default to advanced. Picked to match the plan doc's 기본/고급
# split where it specifies one, and reasonable judgment (rarely-touched
# cross-validation/output-format/safety-override knobs) where it doesn't.
BASIC_DESTS_BY_TOOL: dict[str, set[str]] = {
    "crawler": {"depth", "max_pages", "min_interval", "workers", "ignore_robots", "spa_assist"},
    "infra_vuln": {"ports", "top_ports", "timing", "version_intensity", "nmap_timeout"},
    "ssl_tls": {"port", "timeout"},
    "xss_reflected": {"params", "method", "batch_size", "min_interval"},
    "xss_stored": {"check_url", "params", "method", "min_interval"},
    "crypto_identifier": {"crack"},
    "ffuf": {"wordlist_limit", "extensions", "match_codes", "workers", "min_interval"},
    "gobuster": {"wordlist_limit", "extensions", "exclude_status_codes", "workers", "min_interval"},
}

# Some CLI tools enforce a cross-field "at least one of these" requirement
# that argparse itself can't express (so introspection reports none of them
# as required=True) -- xss_reflected_scanner/xss_stored_scanner both exit(2)
# with "At least one of --params / --cookie-params / --header-params is
# required" if all three are empty. Checked explicitly in on_run() so the
# user gets that explanation before a subprocess launches, not after.
CROSS_FIELD_ANY_OF: dict[str, list[tuple[tuple[str, ...], str, str]]] = {
    "xss_reflected": [
        (("params", "cookie_params", "header_params"),
         "검사 파라미터 / 쿠키 파라미터 / 헤더 파라미터가 모두 비어 있습니다.",
         "위 세 항목 중 최소 하나에 값을 입력하세요. URL에 쿼리 파라미터가 있으면 대상 적용 시 자동으로 채워집니다."),
    ],
    "xss_stored": [
        (("params", "cookie_params", "header_params"),
         "검사 파라미터 / 쿠키 파라미터 / 헤더 파라미터가 모두 비어 있습니다.",
         "위 세 항목 중 최소 하나에 값을 입력하세요 (임의로 추측해서 채우지 않음)."),
    ],
}

# Wordlist-based tools (spec: 목록 진행·Infra·ffuf·Gobuster·HTTP History
# 개선명세서 §3, §14.1) -- mirrors each CLI's own MAX_WORDLIST_LIMIT so the
# GUI's pre-run safety confirmation fires at the same threshold the CLI
# itself would refuse past without --force.
WORDLIST_TOOL_CEILING: dict[str, int] = {"ffuf": 20000, "gobuster": 20000}

# Preset (요청 주기, 동시 요청 수) pairs -- only applied to dests a tool
# actually has (min_interval / workers), so tools without one of the two
# (e.g. ssl_tls has no min_interval) just get whichever field they do have.
LOAD_PRESETS: dict[str, tuple[float, int]] = {
    "낮은 부하": (1.0, 1),
    "권장": (0.5, 3),
    "빠른 검사": (0.2, 5),
}


# Widget types that already scroll themselves on mouse wheel -- the common
# scroll container below must never install its own wheel handler on (or
# inside) one of these, or it would fight the widget's own native scrolling
# (spec 4.4: "이미 스크롤 가능한 Text/ScrolledText/Treeview 영역과 휠 이벤트가
# 충돌하지 않도록"). A ttk.Combobox's own open dropdown is a separate toplevel
# window, not a descendant, so it's never touched by this at all.
_SELF_SCROLLING_TYPES = (tk.Text, ttk.Treeview, tk.Listbox)

# Classic tk.PanedWindow, not ttk.PanedWindow -- ttk's version has no visible
# sash styling (its default is a near-invisible 1-2px line under the 'clam'
# theme) and its sashpos-based sash_place call actually raises TclError
# through _bind_initial_sash, so the initial-height placement silently never
# applied. tab_jwt.py hit the same ttk limitation first (see its _SASH_KW) --
# same raised 6px gripper bar here for a resize handle that's actually visible
# and actually lands where _bind_initial_sash puts it (spec: user "실행버튼
# 위에 높이 조절 바").
_PANE_SASH_KW = dict(sashrelief=tk.RAISED, sashwidth=6, bg="#d0d0d0", bd=0)


class ScrollableFrame(ttk.Frame):
    """Canvas + inner Frame + Scrollbar vertical scroll container (spec
    4.4's mandated pattern), reused by every tool tab's option area instead
    of each one rolling its own. Put content inside `.body` (pack/grid
    against it exactly like any other Frame). The scrollbar auto-hides when
    everything fits; mouse wheel / PageUp / PageDown / Home / End all work
    once the pointer is over the area, without stealing wheel events from a
    Text/Treeview/Listbox nested inside."""

    def __init__(self, parent: tk.Widget, **kw) -> None:
        super().__init__(parent, **kw)
        self.canvas = tk.Canvas(self, highlightthickness=0, bd=0, takefocus=True)
        self.vsb = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._vsb_shown = False  # not packed initially -- shown only once content overflows

        self.body = ttk.Frame(self.canvas)
        self._window = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.body.bind("<Configure>", self._on_body_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        self.canvas.bind("<Button-1>", lambda _e: self.canvas.focus_set())

        for seq, amount in (("<Prior>", -1), ("<Next>", 1)):
            self.canvas.bind(seq, lambda _e, a=amount: self.canvas.yview_scroll(a, "pages"))
        self.canvas.bind("<Home>", lambda _e: self.canvas.yview_moveto(0))
        self.canvas.bind("<End>", lambda _e: self.canvas.yview_moveto(1))

        self._wheel_bound_widgets: list[tk.Widget] = []

    def bind_wheel_recursive(self) -> None:
        """Call once after all content has been added to .body -- walks the
        whole subtree and wires wheel scrolling onto every widget that isn't
        itself already self-scrolling."""
        self._bind_wheel(self.canvas)
        self._walk_and_bind(self.body)

    def _walk_and_bind(self, widget: tk.Widget) -> None:
        if isinstance(widget, _SELF_SCROLLING_TYPES):
            return  # leave it (and anything nested inside it) alone entirely
        self._bind_wheel(widget)
        for child in widget.winfo_children():
            self._walk_and_bind(child)

    def _bind_wheel(self, widget: tk.Widget) -> None:
        widget.bind("<MouseWheel>", self._on_mousewheel, add="+")
        widget.bind("<Button-4>", self._on_mousewheel, add="+")  # X11 scroll up
        widget.bind("<Button-5>", self._on_mousewheel, add="+")  # X11 scroll down

    def _on_mousewheel(self, event: tk.Event) -> None:
        if event.num == 4:
            self.canvas.yview_scroll(-1, "units")
        elif event.num == 5:
            self.canvas.yview_scroll(1, "units")
        else:
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _on_body_configure(self, _event: tk.Event) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self._update_scrollbar_visibility()

    def _on_canvas_configure(self, event: tk.Event) -> None:
        self.canvas.itemconfigure(self._window, width=event.width)
        self._update_scrollbar_visibility()

    def _update_scrollbar_visibility(self) -> None:
        bbox = self.canvas.bbox("all")
        needed = bbox is not None and (bbox[3] - bbox[1]) > self.canvas.winfo_height()
        if needed and not self._vsb_shown:
            self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
            self._vsb_shown = True
        elif not needed and self._vsb_shown:
            self.vsb.pack_forget()
            self._vsb_shown = False


MAX_OUTPUT_LINES = 5000  # scrollback cap shared by every result console -- spec (ffuf 실시간 진행 출력 §9.3):
# "콘솔 보관 줄 수 상한을 두되 잘린 사실을 표시한다"
_TRUNCATION_MARKER = "...(앞부분 생략 -- 콘솔 보관 줄 수 상한 초과)...\n"


def trim_console(output: tk.Text, max_lines: int = MAX_OUTPUT_LINES) -> None:
    """Deletes the oldest lines once a result console exceeds `max_lines`,
    leaving a one-time marker at the top so the truncation itself is never
    silent. Shared by every per-tab/per-mode output console in this suite
    (ToolTab._append_output and DefaultContentScannerTab's _ModeRunner)."""
    total_lines = int(output.index("end-1c").split(".")[0])
    if total_lines <= max_lines:
        return
    excess = total_lines - max_lines
    output.delete("1.0", f"{excess + 1}.0")
    if output.get("1.0", "1.end") != _TRUNCATION_MARKER.rstrip("\n"):
        output.insert("1.0", _TRUNCATION_MARKER)


def _self_invoke_prefix() -> list[str]:
    """Command prefix that re-launches this same app (frozen exe or `python
    main.py`) so worker mode (--introspect-tool / --run-tool) runs in a
    fresh, isolated process -- see main.py's docstring for why."""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    main_py = Path(__file__).resolve().parent / "main.py"
    return [sys.executable, str(main_py)]


class ToolTab(ttk.Frame):
    """One tab per CLI tool: builds a form from the tool's own build_arg_parser()
    (via a subprocess introspection helper -- keeps that tool's imports/sys.path
    out of this long-lived GUI process), runs it as a subprocess on demand, and
    streams its output into a text pane. `set_target()` lets the History tab
    push a URL/host straight into this tool's primary positional field."""

    # Shared across every ToolTab instance (they all live in this one GUI
    # process) -- lets a newly-started scan see how many other tabs are
    # already running and divide up the safe request rate accordingly (plan
    # doc 9.7, option 3: no separate coordinator process/IPC needed since the
    # GUI itself already is the single place that launches every subprocess).
    _running_tabs: set["ToolTab"] = set()

    def __init__(self, parent: tk.Widget, spec: ToolSpec) -> None:
        super().__init__(parent)
        self.spec = spec
        self.widgets: dict[str, tuple[str, tk.Variable]] = {}
        self.actions: list[dict] = []
        self.positional_dest: str | None = None
        self.proc: subprocess.Popen | None = None
        self._run_start: datetime | None = None
        self._user_stopped = False
        self._run_id: str | None = None
        self._infra_url_port: int | None = None
        self._build()

    def _build_run_summary_bar(self, parent: tk.Widget) -> None:
        """Short one-line run summary (target / start·end time / applied
        speed settings / finish status) shown above the raw console output,
        which stays untouched below it -- every _build() variant (base,
        DefaultContentScannerTab, JwtAnalyzerTab) calls this right before
        creating self.output."""
        self.run_summary_var = tk.StringVar(value="")
        ttk.Label(
            parent, textvariable=self.run_summary_var, foreground="#555",
            padding=(12, 0, 12, 2), justify=tk.LEFT, wraplength=1100,
        ).pack(side=tk.TOP, fill=tk.X)

    @staticmethod
    def _bind_initial_sash(paned: tk.PanedWindow, pos_from_size) -> None:
        """Force sash 0's initial position once real geometry has settled. A
        freshly-created PanedWindow fires several <Configure> events while
        Tk's geometry negotiation is still in progress (each with a
        different, not-yet-final size) before this tab is even mapped if it
        isn't the one selected at startup -- so this debounces: every
        Configure event reschedules the actual placement, and only the size
        from the last one (after events stop arriving for a bit) gets
        applied. Fires once total; later Configure events (real user window
        resizes) are left alone so a user drag is never overridden."""
        state = {"done": False, "job": None}
        horizontal = str(paned.cget("orient")) == "horizontal"

        def _apply(size: int) -> None:
            state["job"] = None
            if state["done"]:
                return
            state["done"] = True
            pos = pos_from_size(size)
            try:
                paned.sash_place(0, pos, 0) if horizontal else paned.sash_place(0, 0, pos)
            except tk.TclError:
                pass

        def _on_configure(event: tk.Event) -> None:
            if state["done"]:
                return
            size = event.width if horizontal else event.height
            if size <= 4:  # not really mapped yet
                return
            if state["job"] is not None:
                paned.after_cancel(state["job"])
            state["job"] = paned.after(120, _apply, size)

        paned.bind("<Configure>", _on_configure, add="+")

    def _build_options_and_bottom(
        self, parent: tk.Widget, *, min_options: int = 90, max_ratio: float = 0.55
    ) -> tuple[ttk.Frame, ttk.Frame]:
        """Common layout for every tab: a scrollable options area on top (so
        it never pushes the run/stop buttons or output off-screen on a short
        window -- spec 4.3's recommended fix) and a bottom area (run/stop
        buttons, always pinned and visible, + output) that gets whatever
        space is left. Split by a visible, draggable sash (spec: user
        "실행버튼 위에 높이 조절 바") -- same tk.PanedWindow + _PANE_SASH_KW
        style already used for tab_jwt.py's resizable splits. The *initial*
        split still favors a sane default (options height capped to
        `max_ratio` of the tab's current height, same heuristic as before)
        so a tool with only 3 fields doesn't reserve half the window as
        blank canvas by default -- but that placement happens exactly once;
        a user drag is never overridden afterward."""
        paned = tk.PanedWindow(parent, orient=tk.VERTICAL, **_PANE_SASH_KW)
        paned.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        scroll = ScrollableFrame(paned)
        bottom = ttk.Frame(paned)
        paned.add(scroll, minsize=60, stretch="always")
        paned.add(bottom, minsize=150, stretch="always")

        def _pos_from_size(paned_h: int) -> int:
            content_h = scroll.body.winfo_reqheight()
            cap = max(min_options, int(paned_h * max_ratio))
            return min(content_h, cap) if content_h > 1 else cap

        self._bind_initial_sash(paned, _pos_from_size)
        self._scroll_areas = getattr(self, "_scroll_areas", [])
        self._scroll_areas.append(scroll)
        return scroll.body, bottom

    def _finalize_scroll_areas(self) -> None:
        """Call once at the very end of _build(), after every widget that
        should participate in wheel/keyboard scrolling has been created."""
        for scroll in getattr(self, "_scroll_areas", []):
            scroll.bind_wheel_recursive()

    # -- setup ---------------------------------------------------------------
    def _introspect(self) -> dict:
        result = subprocess.run(
            [*_self_invoke_prefix(), "--introspect-tool", str(self.spec.script)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20,
            cwd=str(self.spec.script.parent),
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip()[-1500:] or "알 수 없는 오류")
        return json.loads(result.stdout)

    def _build(self) -> None:
        self._build_header()
        try:
            info = self._introspect()
        except Exception as exc:  # noqa: BLE001
            app_logging.log_exception(_logger, "tool_failed", f"{self.spec.key} 도구 정보 조회 실패", sys.exc_info(), tool=self.spec.key)
            ttk.Label(self, text=f"이 도구 정보를 불러오지 못함:\n{exc}", foreground="#c0392b", justify=tk.LEFT).pack(
                padx=12, pady=10, anchor=tk.W
            )
            return
        self.actions = info["actions"]

        options_body, bottom = self._build_options_and_bottom(self)
        form = ttk.Frame(options_body, padding=(12, 8))
        form.pack(side=tk.TOP, fill=tk.X)
        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=2)

        positionals = [a for a in self.actions if not a["option_strings"]]
        optionals = [a for a in self.actions if a["option_strings"]]
        basic_dests = BASIC_DESTS_BY_TOOL.get(self.spec.key, set())
        basic = [a for a in optionals if a["dest"] in basic_dests]
        advanced = [a for a in optionals if a["dest"] not in basic_dests]

        # Build the advanced section's widgets up front, into their own frame
        # that isn't attached to `form` yet (stays hidden until toggled) --
        # this has to happen before the "주요 설정" section below so that a
        # load-preset combobox there can safely reach self.widgets["workers"]
        # even for a tool where --workers happens to be classified advanced
        # (e.g. ssl_tls), regardless of the on-screen row order.
        self.advanced_frame: ttk.Frame | None = None
        if advanced:
            self._advanced_count = len(advanced)
            self._advanced_shown = False
            self.advanced_frame = ttk.Frame(form)
            self.advanced_frame.columnconfigure(1, weight=1)
            self.advanced_frame.columnconfigure(3, weight=2)
            if len(advanced) > self.TWO_COLUMN_THRESHOLD:
                self._build_two_column_fields(self.advanced_frame, 0, advanced)
            else:
                arow = 0
                for a in advanced:
                    arow = self._build_field(self.advanced_frame, arow, a)

        row = 0
        if positionals:
            row = self._build_section(form, row, "필수 값", positionals)
        if basic:
            if positionals:
                ttk.Separator(form, orient=tk.HORIZONTAL).grid(row=row, column=0, columnspan=4, sticky=tk.EW, pady=6)
                row += 1
            row = self._build_section(form, row, "주요 설정", basic)
            all_optional_dests = {a["dest"] for a in optionals}
            if "min_interval" in all_optional_dests or "workers" in all_optional_dests:
                row = self._build_load_preset(form, row)
        if self.spec.key == "crawler":
            row = self._build_crawler_history_section(form, row)
        if self.spec.key == "infra_vuln":
            row = self._build_infra_port_scope_section(form, row)
        if advanced:
            ttk.Separator(form, orient=tk.HORIZONTAL).grid(row=row, column=0, columnspan=4, sticky=tk.EW, pady=6)
            row += 1
            self.advanced_toggle_btn = ttk.Button(
                form, text=f"▸ 고급 설정 펼치기 ({self._advanced_count}개)", command=self._toggle_advanced
            )
            self.advanced_toggle_btn.grid(row=row, column=0, columnspan=4, sticky=tk.W, pady=(0, 4))
            row += 1
            self._advanced_grid_row = row
            row += 1

        self._build_list_estimate_bar(bottom)

        btn_frame = ttk.Frame(bottom, padding=(12, 4))
        btn_frame.pack(side=tk.TOP, fill=tk.X)
        self.run_btn = ttk.Button(btn_frame, text="▶ 실행", style="Accent.TButton", command=self.on_run)
        self.run_btn.pack(side=tk.LEFT)
        self.stop_btn = ttk.Button(btn_frame, text="■ 중지", command=self.on_stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="출력 지우기", command=self.on_clear_output).pack(side=tk.LEFT, padx=4)

        self._build_run_summary_bar(bottom)
        self.output = scrolledtext.ScrolledText(bottom, wrap=tk.WORD, font=("Consolas", 9), borderwidth=1, relief=tk.SOLID)
        self.output.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4, 10))
        self.output.configure(state=tk.DISABLED)
        self._finalize_scroll_areas()

    def _build_header(self) -> None:
        header = ttk.Frame(self, padding=(12, 10, 12, 6))
        header.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(header, text=self.spec.name, font=("", 12, "bold")).pack(anchor=tk.W)
        ttk.Label(
            header, text=self.spec.description, foreground="#555", wraplength=1100, justify=tk.LEFT
        ).pack(anchor=tk.W, pady=(2, 0))
        ttk.Separator(self, orient=tk.HORIZONTAL).pack(side=tk.TOP, fill=tk.X, padx=12)

    # Sections with more fields than this are laid out as two side-by-side
    # single-column blocks instead of one long vertical list -- halves the
    # vertical scroll length and puts related fields within eye-span of each
    # other (spec: user 가독성 요청, 옵션창 2열 정렬).
    TWO_COLUMN_THRESHOLD = 4

    def _build_section(self, form: ttk.Frame, start_row: int, title: str, actions: list[dict]) -> int:
        ttk.Label(form, text=title, font=("", 9, "bold"), foreground="#333").grid(
            row=start_row, column=0, columnspan=4, sticky=tk.W, pady=(0, 4)
        )
        row = start_row + 1
        if len(actions) > self.TWO_COLUMN_THRESHOLD:
            return self._build_two_column_fields(form, row, actions)
        for a in actions:
            row = self._build_field(form, row, a)
        return row

    def _build_two_column_fields(
        self, parent: ttk.Frame, start_row: int, actions: list[dict], widget_store: dict | None = None
    ) -> int:
        container = ttk.Frame(parent)
        container.grid(row=start_row, column=0, columnspan=4, sticky=tk.NSEW)
        container.columnconfigure(0, weight=1)
        container.columnconfigure(1, weight=1)
        left = ttk.Frame(container)
        right = ttk.Frame(container)
        left.grid(row=0, column=0, sticky=tk.NSEW, padx=(0, 24))
        right.grid(row=0, column=1, sticky=tk.NSEW)
        left.columnconfigure(1, weight=1)
        left.columnconfigure(3, weight=2)
        right.columnconfigure(1, weight=1)
        right.columnconfigure(3, weight=2)
        half = (len(actions) + 1) // 2
        row_l = 0
        for a in actions[:half]:
            row_l = self._build_field(left, row_l, a, widget_store, wraplength=260)
        row_r = 0
        for a in actions[half:]:
            row_r = self._build_field(right, row_r, a, widget_store, wraplength=260)
        return start_row + 1

    def _build_field(
        self, form: ttk.Frame, row: int, a: dict, widget_store: dict | None = None, wraplength: int = 420
    ) -> int:
        """widget_store defaults to self.widgets -- DefaultContentScannerTab
        passes its own per-mode dict instead, so its 3 independent execution
        units (which share the same underlying script/argparse actions) each
        get their own separate tk.Variable per field instead of the 3 modes
        overwriting each other's entry in one shared dict."""
        store = self.widgets if widget_store is None else widget_store
        dest = a["dest"]
        cli_name = dest if not a["option_strings"] else a["option_strings"][0]
        ko = KOREAN_OPTIONS.get(dest, {})
        label_text = ko.get("label", cli_name)
        help_text = ko.get("help") or a.get("help") or ""
        required = not a["option_strings"] and a.get("required", True) is not False and a.get("nargs") != "?"

        label_col = ttk.Frame(form)
        label_col.grid(row=row, column=0, sticky=tk.NW, padx=(0, 8), pady=3)
        name_label = ttk.Label(label_col, text=(label_text + " *") if required else label_text)
        if required:
            name_label.configure(foreground="#b3261e")
        name_label.pack(anchor=tk.W)
        # CLI option name kept small underneath -- lets an existing --help
        # user recognize the field without translating the whole form.
        ttk.Label(label_col, text=cli_name, foreground="#aaa", font=("", 8)).pack(anchor=tk.W)

        if dest in KNOWN_LIST_VALUES:
            default_set = set()
            if a["default"] not in (None, False):
                default_set = {v.strip() for v in str(a["default"]).split(",") if v.strip()}
            check_vars: dict[str, tk.BooleanVar] = {}
            box = ttk.Frame(form)
            box.grid(row=row, column=1, columnspan=2, sticky=tk.EW)
            for i, val in enumerate(KNOWN_LIST_VALUES[dest]):
                v = tk.BooleanVar(value=val in default_set)
                check_vars[val] = v
                ttk.Checkbutton(box, text=val, variable=v).grid(row=i // 3, column=i % 3, sticky=tk.W, padx=(0, 12))
            store[dest] = ("checklist", check_vars)
            if not a["option_strings"] and self.positional_dest is None:
                self.positional_dest = dest
            help_label = ttk.Label(form, text=help_text, foreground="#666", wraplength=wraplength, justify=tk.LEFT)
            help_label.grid(row=row, column=3, sticky=tk.NSEW, padx=6)
            self._bind_responsive_wrap(help_label)
            return row + 1
        elif a["action_type"] == "_StoreTrueAction":
            var = tk.BooleanVar(value=bool(a["default"]))
            ttk.Checkbutton(form, variable=var).grid(row=row, column=1, sticky=tk.W)
            store[dest] = ("bool", var)
        elif a["choices"]:
            var = tk.StringVar(value="" if a["default"] is None else str(a["default"]))
            entry_width = 26 if wraplength >= 420 else 16
            ttk.Combobox(
                form, textvariable=var, values=[str(c) for c in a["choices"]], width=entry_width, state="readonly"
            ).grid(row=row, column=1, sticky=tk.EW)
            store[dest] = ("str", var)
            if dest in UNIT_HINTS:
                ttk.Label(form, text=UNIT_HINTS[dest], foreground="#888").grid(row=row, column=2, sticky=tk.W, padx=6)
        elif a["action_type"] == "_AppendAction":
            var = tk.StringVar(value="")
            entry_width = 46 if wraplength >= 420 else 24
            ttk.Entry(form, textvariable=var, width=entry_width).grid(row=row, column=1, sticky=tk.EW)
            ttk.Label(form, text="쉼표로 여러 개", foreground="#888").grid(row=row, column=2, sticky=tk.W, padx=6)
            store[dest] = ("list_csv", var)
        else:
            # Pre-fill with the tool's own default so a field with a sensible
            # default (--timeout 10, --batch-size 10, ...) never looks empty
            # or forces the user to go look up what it defaults to.
            default_text = "" if a["default"] in (None, False) else str(a["default"])
            if self.spec.key == "crawler" and dest == "depth" and default_text:
                # 화면 표시 단계 = 내부 --depth 값 + 1 (1단계 = 시작 URL만) --
                # converted back on the way into argv, see _build_argv.
                default_text = str(int(default_text) + 1)
            var = tk.StringVar(value=default_text)
            entry_width = 46 if wraplength >= 420 else 24
            ttk.Entry(form, textvariable=var, width=entry_width).grid(row=row, column=1, sticky=tk.EW)
            store[dest] = ("str", var)
            if not a["option_strings"] and self.positional_dest is None:
                self.positional_dest = dest
            if dest in UNIT_HINTS:
                ttk.Label(form, text=UNIT_HINTS[dest], foreground="#888").grid(row=row, column=2, sticky=tk.W, padx=6)

        help_label = ttk.Label(form, text=help_text, foreground="#666", wraplength=wraplength, justify=tk.LEFT)
        help_label.grid(row=row, column=3, sticky=tk.NSEW, padx=6)
        self._bind_responsive_wrap(help_label)
        return row + 1

    @staticmethod
    def _bind_responsive_wrap(label: ttk.Label) -> None:
        """Help-text labels reflow to their *actual* allocated column width
        instead of a fixed wraplength -- so widening the window (or the
        options panel) actually gives longer lines more room instead of
        wrapping at a size chosen for the old fixed window (spec: user
        '고정크기가 아니라 크기 조절 가능하게' 요청)."""
        label.bind("<Configure>", lambda e: label.configure(wraplength=max(e.width - 4, 60)))

    # -- advanced-section collapse/expand -------------------------------------
    def _toggle_advanced(self) -> None:
        self._advanced_shown = not self._advanced_shown
        if self._advanced_shown:
            self.advanced_frame.grid(row=self._advanced_grid_row, column=0, columnspan=4, sticky=tk.EW)
            self.advanced_toggle_btn.configure(text="▾ 고급 설정 접기")
        else:
            self.advanced_frame.grid_forget()
            self.advanced_toggle_btn.configure(text=f"▸ 고급 설정 펼치기 ({self._advanced_count}개)")

    # -- 속도 프리셋 -----------------------------------------------------------
    def _build_load_preset(self, form: ttk.Frame, row: int) -> int:
        """Presets a tool's request-pacing fields (whichever of min_interval /
        workers it actually has) to one of 3 canned (요청 주기, 동시 요청 수)
        pairs. Editing a paced field by hand flips the selector to '사용자
        설정' so a manual tweak is never silently overwritten later."""
        frame = ttk.Frame(form)
        frame.grid(row=row, column=0, columnspan=4, sticky=tk.W, pady=(2, 8))
        ttk.Label(frame, text="속도 프리셋", foreground="#333").pack(side=tk.LEFT, padx=(0, 8))
        self.preset_var = tk.StringVar(value="권장")
        combo = ttk.Combobox(
            frame, textvariable=self.preset_var, values=list(LOAD_PRESETS) + ["사용자 설정"],
            width=12, state="readonly",
        )
        combo.pack(side=tk.LEFT)
        combo.bind("<<ComboboxSelected>>", self._on_preset_selected)
        self.preset_hint_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.preset_hint_var, foreground="#b35c00").pack(side=tk.LEFT, padx=(10, 0))

        self._applying_preset = False
        self._apply_preset("권장")
        for dest in ("min_interval", "workers"):
            if dest in self.widgets:
                self.widgets[dest][1].trace_add("write", self._on_field_manually_changed)
        return row + 1

    def _on_preset_selected(self, _event: tk.Event | None = None) -> None:
        name = self.preset_var.get()
        if name != "사용자 설정":
            self._apply_preset(name)

    def _apply_preset(self, name: str) -> None:
        interval, workers = LOAD_PRESETS[name]
        self._applying_preset = True
        try:
            if "min_interval" in self.widgets:
                self.widgets["min_interval"][1].set(str(interval))
            if "workers" in self.widgets:
                self.widgets["workers"][1].set(str(workers))
        finally:
            self._applying_preset = False
        self.preset_hint_var.set("서버 부하가 커질 수 있음" if name == "빠른 검사" else "")

    def _on_field_manually_changed(self, *_args: object) -> None:
        if self._applying_preset:
            return
        if self.preset_var.get() != "사용자 설정":
            self.preset_var.set("사용자 설정")
            self.preset_hint_var.set("")

    # -- 목록 기반 도구(ffuf/gobuster) 예상 요청 수 표시 --------------------
    # spec: 목록 진행·Infra·ffuf·Gobuster·HTTP History 개선명세서 §3.1-3.2,
    # §3.3 "0=전체". Only these two tools have a plain external wordlist
    # file + --wordlist-limit + --extensions combo today; default_content_
    # scanner's own candidate counting lives in tab_default_content.py since
    # it has a bespoke multi-mode tab instead of this generic form.
    _WORDLIST_ESTIMATE_DESTS = ("wordlist", "wordlist_limit", "extensions")

    def _is_wordlist_tool(self) -> bool:
        return self.spec.key in WORDLIST_TOOL_CEILING and all(d in self.widgets for d in self._WORDLIST_ESTIMATE_DESTS)

    @staticmethod
    def _count_wordlist_file(path_str: str) -> tuple[int, int] | None:
        """Returns (원본 후보, 유효 후보) or None if the path doesn't exist /
        can't be read -- mirrors ffuf_scanner.py/gobuster_scanner.py's own
        `_count_wordlist()` so the GUI shows the same numbers the CLI will
        actually use."""
        try:
            path = Path(path_str)
            if not path.is_file():
                return None
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None
        seen: set[str] = set()
        valid = 0
        for line in raw_lines:
            s = line.strip()
            if not s or s in seen:
                continue
            seen.add(s)
            valid += 1
        return len(raw_lines), valid

    def _compute_list_estimate(self) -> dict | None:
        if not self._is_wordlist_tool():
            return None
        counts = self._count_wordlist_file(self._field_value("wordlist"))
        if counts is None:
            return {"error": "워드리스트 파일을 찾을 수 없음"}
        original, valid = counts
        limit_raw = self._field_value("wordlist_limit").strip()
        try:
            limit = int(limit_raw) if limit_raw else 0
        except ValueError:
            return {"error": f"워드리스트 최대 사용 줄 수 값이 올바르지 않음: {limit_raw!r}"}
        unlimited = limit == 0
        used = valid if unlimited else max(0, min(limit, original))
        ext_raw = self._field_value("extensions").strip()
        exts = [e.strip() for e in ext_raw.split(",") if e.strip()]
        combo = 1 + len(exts)
        expected_max = used * combo
        return {
            "error": None, "original": original, "valid": valid, "used": used,
            "unlimited": unlimited, "ext_count": len(exts), "combo": combo,
            "expected_max": expected_max, "ceiling": WORDLIST_TOOL_CEILING[self.spec.key],
        }

    def _refresh_list_estimate(self, *_args: object) -> None:
        if not hasattr(self, "list_estimate_var"):
            return
        est = self._compute_list_estimate()
        if est is None:
            return
        if est["error"]:
            self.list_estimate_var.set(est["error"])
            return
        used_display = f"전체 {est['used']:,}개" if est["unlimited"] else f"{est['used']:,}개"
        self.list_estimate_var.set(
            f"목록: 유효 {est['valid']:,}개 / 원본 {est['original']:,}개  |  "
            f"사용: {used_display}{' (제한값 0 = 전체)' if est['unlimited'] else ''}  |  "
            f"조합: 기본 경로 1개 + 확장자 {est['ext_count']}개 = 후보당 최대 {est['combo']}회  |  "
            f"예상 최대 요청: {est['expected_max']:,}회"
        )

    def _build_list_estimate_bar(self, parent: tk.Widget) -> None:
        if not self._is_wordlist_tool():
            return
        self.list_estimate_var = tk.StringVar(value="")
        ttk.Label(
            parent, textvariable=self.list_estimate_var, foreground="#333",
            padding=(12, 2, 12, 0), justify=tk.LEFT, wraplength=1100,
        ).pack(side=tk.TOP, fill=tk.X)
        for dest in self._WORDLIST_ESTIMATE_DESTS:
            self.widgets[dest][1].trace_add("write", self._refresh_list_estimate)
        self._refresh_list_estimate()

    def _confirm_unlimited_wordlist(self) -> bool:
        """spec §3.4: 0=전체 선택 + 예상 요청 수가 안전 상한을 넘으면 실행 전
        명확한 확인창을 띄운다. 사용자가 계속하면 그 도구의 --force 체크박스를
        자동으로 켜서 argv에 실제로 반영되게 한다 (CLI 쪽도 동일 상한을
        --force 없이는 거부하므로, 승인 사실이 실제로 전달돼야 함)."""
        est = self._compute_list_estimate()
        if not est or est.get("error") or not est["unlimited"]:
            return True
        if est["original"] <= est["ceiling"]:
            return True
        interval = self._field_value("min_interval") or "(기본값)"
        proceed = messagebox.askyesno(
            "전체 목록 사용 확인",
            f"전체 목록을 사용합니다.\n유효 후보: {est['valid']:,}개\n예상 최대 요청: {est['expected_max']:,}회\n"
            f"현재 요청 간격: {interval}초\n\n대상 서버 부하와 긴 실행 시간이 발생할 수 있습니다. 계속하시겠습니까?",
        )
        if not proceed:
            app_logging.log_event(
                _logger, "INFO", "unlimited_list_selected", f"{self.spec.key}: 0=전체 사용자 취소",
                tool=self.spec.key, confirmed=False, **{k: v for k, v in est.items() if k != "error"},
            )
            return False
        if "force" in self.widgets:
            self.widgets["force"][1].set(True)
        app_logging.log_event(
            _logger, "INFO", "unlimited_list_selected", f"{self.spec.key}: 0=전체 사용자 승인",
            tool=self.spec.key, confirmed=True, **{k: v for k, v in est.items() if k != "error"},
        )
        return True

    # -- external API (called from the History tab's "보내기") --------------
    def set_target(self, value: str) -> None:
        if self.positional_dest and self.positional_dest in self.widgets:
            _, var = self.widgets[self.positional_dest]
            var.set(value)

    def set_port(self, port: int) -> None:
        if "port" in self.widgets:
            kind, var = self.widgets["port"]
            if kind == "str":
                var.set(str(port))

    def apply_target(self, ctx: TargetContext) -> None:
        """Called when the common target bar at the top of the window is
        applied. Skipped for a tab whose run is already in flight -- an
        in-progress scan's target must not change out from under it."""
        if self.proc is not None:
            return
        kind = self.spec.target_kind
        if kind == "url":
            self.set_target(ctx.url)
            if self.spec.key == "xss_reflected":
                self._autofill_query_params(ctx.url)
        elif kind == "host":
            self.set_target(ctx.host)
            if self.spec.key == "infra_vuln" and ctx.port_explicit:
                self._autofill_infra_port(ctx.port)
        elif kind == "host_port":
            self.set_target(ctx.host)
            self.set_port(ctx.port)

    # -- Infra Vuln Scanner: 검사 범위 선택 (spec: 목록 진행·Infra·ffuf·
    # Gobuster·HTTP History 개선명세서 §4) -----------------------------------
    _INFRA_WELL_KNOWN = "1-1023"
    _INFRA_WELL_KNOWN_COUNT = 1023

    def _autofill_infra_port(self, port: int) -> None:
        """Infra Vuln Scanner only: an explicit port on the applied target
        URL gets ADDED to the default well-known range (spec §4.2) instead
        of replacing it outright -- the old behavior silently scanned only
        that one port. '선택한 URL 포트만' is still available as its own
        explicit radio choice for when a user genuinely wants that."""
        self._infra_url_port = port
        if hasattr(self, "infra_scope_var"):
            self._refresh_infra_port_display()
        self._append_output(f"[대상 URL의 포트({port})를 검사 범위 계산에 반영함 -- 아래 '실제 검사 포트' 참고]\n")

    def _build_infra_port_scope_section(self, form: ttk.Frame, row: int) -> int:
        ttk.Separator(form, orient=tk.HORIZONTAL).grid(row=row, column=0, columnspan=4, sticky=tk.EW, pady=6)
        row += 1
        ttk.Label(form, text="검사 범위", font=("", 9, "bold"), foreground="#333").grid(
            row=row, column=0, columnspan=4, sticky=tk.W, pady=(0, 4)
        )
        row += 1
        self.infra_scope_var = tk.StringVar(value="well_known")
        radios = [
            ("well_known", f"Well-known TCP 포트 {self._INFRA_WELL_KNOWN} [기본]"),
            ("top_ports", "nmap 상위 포트 (아래 '상위 포트 수' 값 사용)"),
            ("custom", "직접 입력 (아래 '검사 포트 목록' 값 사용)"),
            ("selected_url_port", "선택한 URL 포트만"),
        ]
        for value, text in radios:
            ttk.Radiobutton(
                form, text=text, value=value, variable=self.infra_scope_var,
                command=self._refresh_infra_port_display,
            ).grid(row=row, column=0, columnspan=4, sticky=tk.W)
            row += 1
        self.infra_url_port_add_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            form, text="URL에 지정한 비표준 포트를 기본 범위에 추가", variable=self.infra_url_port_add_var,
            command=self._refresh_infra_port_display,
        ).grid(row=row, column=0, columnspan=4, sticky=tk.W, pady=(4, 0))
        row += 1
        self.infra_effective_ports_var = tk.StringVar(value="")
        ttk.Label(form, textvariable=self.infra_effective_ports_var, foreground="#2f6fed").grid(
            row=row, column=0, columnspan=4, sticky=tk.W, pady=(4, 0)
        )
        row += 1
        for dest in ("ports", "top_ports"):
            if dest in self.widgets:
                self.widgets[dest][1].trace_add("write", lambda *_a: self._refresh_infra_port_display())
        # trace_add (not just each widget's own command=) so a programmatic
        # change -- not just a live user click -- always keeps the "실제 검사
        # 포트" line honest (command= alone only fires on direct interaction).
        self.infra_scope_var.trace_add("write", lambda *_a: self._refresh_infra_port_display())
        self.infra_url_port_add_var.trace_add("write", lambda *_a: self._refresh_infra_port_display())
        self._refresh_infra_port_display()
        return row

    def _infra_effective_ports(self) -> tuple[str | None, str | None, int]:
        """Returns (--ports 값 or None, --top-ports 값 or None, 총 포트 수 -- 알 수
        없으면 -1)."""
        scope = self.infra_scope_var.get()
        url_port = self._infra_url_port
        if scope == "selected_url_port":
            if url_port is None:
                return None, None, -1
            return str(url_port), None, 1
        if scope == "custom":
            raw = self._field_value("ports").strip()
            return (raw or None), None, -1
        if scope == "top_ports":
            raw = self._field_value("top_ports").strip() or "1000"
            return None, raw, (int(raw) if raw.isdigit() else -1)
        # well_known (default)
        add_url_port = self.infra_url_port_add_var.get()
        if add_url_port and url_port and not (1 <= url_port <= self._INFRA_WELL_KNOWN_COUNT):
            return f"{self._INFRA_WELL_KNOWN},{url_port}", None, self._INFRA_WELL_KNOWN_COUNT + 1
        return self._INFRA_WELL_KNOWN, None, self._INFRA_WELL_KNOWN_COUNT

    def _refresh_infra_port_display(self) -> None:
        if not hasattr(self, "infra_effective_ports_var"):
            return
        ports_val, top_ports_val, count = self._infra_effective_ports()
        if self.infra_scope_var.get() == "selected_url_port" and ports_val is None:
            self.infra_effective_ports_var.set("실제 검사 포트: (대상 URL에 포트가 지정되지 않음 -- 먼저 URL을 적용하세요)")
            return
        expr = ports_val if ports_val else f"nmap 상위 {top_ports_val}개"
        count_display = f" (총 {count:,}개)" if count >= 0 else ""
        self.infra_effective_ports_var.set(f"실제 검사 포트: {expr}{count_display}")

    def _apply_infra_port_scope(self) -> None:
        if not hasattr(self, "infra_scope_var"):
            return
        ports_val, top_ports_val, _ = self._infra_effective_ports()
        if "ports" in self.widgets:
            self.widgets["ports"][1].set(ports_val or "")
        if "top_ports" in self.widgets and top_ports_val is not None:
            self.widgets["top_ports"][1].set(top_ports_val)

    def _autofill_query_params(self, url: str) -> None:
        """Reflected XSS only: pull query-string param names straight from
        the target URL into the '검사 파라미터' field. Never invents params
        when the URL has none -- the on_run() cross-field check (see
        CROSS_FIELD_ANY_OF) is what tells the user to fill one in by hand
        in that case, instead of this guessing something that isn't there."""
        if "params" not in self.widgets:
            return
        names = list(dict.fromkeys(k for k, _ in parse_qsl(urlparse(url).query)))
        _, var = self.widgets["params"]
        if names:
            var.set(",".join(names))
            self._append_output(f"[URL에서 파라미터 자동 추출: {', '.join(names)}]\n")
        else:
            var.set("")
            self._append_output(
                "[검사할 파라미터가 없습니다 -- URL에 쿼리 파라미터가 없음. "
                "'검사 파라미터' 란에 직접 입력하거나 쿠키/헤더 파라미터를 사용하세요.]\n"
            )

    # -- run/stop --------------------------------------------------------------
    def _build_argv(self, widgets: dict | None = None) -> list[str]:
        """widgets defaults to self.widgets -- pass a per-mode dict (see
        _build_field's widget_store) to build argv for one of
        DefaultContentScannerTab's independent execution units instead."""
        widgets = self.widgets if widgets is None else widgets
        positional_values: list[str] = []
        optional_args: list[str] = []
        for a in self.actions:
            dest = a["dest"]
            if dest not in widgets:
                continue  # not rendered anywhere (e.g. an internal-only flag like --estimate-only)
            kind, var = widgets[dest]
            if kind == "bool":
                if var.get():
                    optional_args.append(a["option_strings"][0])
                continue
            if kind == "checklist":
                # Always emit explicitly, even as "" when nothing is checked --
                # some of these dests (e.g. --tech) default to a non-empty set
                # on the CLI side, so silently omitting the flag when the user
                # unchecks everything would fall back to that CLI default
                # instead of actually running with nothing selected.
                selected = ",".join(name for name, bv in var.items() if bv.get())
                if a["option_strings"]:
                    optional_args += [a["option_strings"][0], selected]
                else:
                    positional_values.append(selected)
                continue
            value = var.get().strip()
            if self.spec.key == "crawler" and dest == "depth" and value.lstrip("-").isdigit():
                # 화면 단계 -> 내부 --depth (see _build_field's matching +1)
                value = str(int(value) - 1)
            if not a["option_strings"]:
                if value:
                    positional_values.append(value)
                continue
            if not value:
                continue
            if kind == "list_csv":
                for item in (x.strip() for x in value.split(",")):
                    if item:
                        optional_args += [a["option_strings"][0], item]
            else:
                optional_args += [a["option_strings"][0], value]
        return positional_values + optional_args

    def _field_value(self, dest: str, widgets: dict | None = None) -> str:
        widgets = self.widgets if widgets is None else widgets
        if dest not in widgets:
            return ""
        kind, var = widgets[dest]
        if kind == "bool":
            return "1" if var.get() else ""
        if kind == "checklist":
            return ",".join(name for name, bv in var.items() if bv.get())
        return var.get().strip()

    def _missing_required(self, widgets: dict | None = None) -> list[str]:
        """Fields marked with the red ' *' that are still empty. Checking this
        directly (instead of "is argv empty?") matters because argv is never
        actually empty once optional fields are pre-filled with their
        defaults -- an empty *required* field would otherwise slip through
        and get run anyway, only to have argparse itself reject it a moment
        later with a bare 'the following arguments are required: ...'."""
        widgets = self.widgets if widgets is None else widgets
        missing = []
        for a in self.actions:
            dest = a["dest"]
            if dest not in widgets:
                continue  # handled by a bespoke widget outside the generic form (e.g. JWT tab's token box)
            value = self._field_value(dest, widgets)
            if not a["option_strings"]:
                if a.get("nargs") != "?" and not value:
                    missing.append(dest)
            elif a.get("required", False) and not value:
                missing.append(a["option_strings"][0])
        return missing

    def _cross_field_errors(self) -> list[tuple[str, str]]:
        """Some tools reject an argparse-legal combination at runtime (see
        CROSS_FIELD_ANY_OF) -- argparse's own required= can't express an
        "at least one of these" rule, so this is checked separately here.
        Returns (원인, 조치) pairs."""
        errors = []
        for dests, cause, action in CROSS_FIELD_ANY_OF.get(self.spec.key, []):
            if not any(self._field_value(d) for d in dests):
                errors.append((cause, action))
        return errors

    def _blocking_dependency_error(self) -> tuple[str, str] | None:
        """Unlike ssl_tls (which degrades individual checks to UNKNOWN when
        an optional external tool is missing), infra_vuln_scanner.py hard
        exit(2)s with a bare English log line if nmap isn't found at all --
        exactly the '오류만 나오고 종료' pattern users hit before any of
        this scan even starts. Caught here so it's a clear Korean (원인,
        조치) pair before a subprocess even launches."""
        if self.spec.key == "infra_vuln" and _find_nmap() is None:
            return (
                "nmap.exe를 찾을 수 없습니다 (PATH 및 기본 설치 경로 확인함).",
                "nmap을 설치한 뒤 다시 실행하세요 (https://nmap.org/download.html).",
            )
        return None

    def _dependency_warning(self) -> str | None:
        """ssl_tls_scanner degrades gracefully (UNKNOWN, not a crash) when
        one of its optional cross-validation tools is missing -- so this is
        informational only, never blocks the run."""
        if self.spec.key != "ssl_tls":
            return None
        missing = []
        if not self._field_value("no_openssl") and shutil.which("openssl") is None:
            missing.append("OpenSSL")
        if self._field_value("nmap") and _find_nmap() is None:
            missing.append("nmap")
        if self._field_value("testssl") and shutil.which("testssl.sh") is None:
            missing.append("testssl.sh")
        if not missing:
            return None
        return f"다음 외부 도구가 없어 해당 검사만 UNKNOWN으로 표시됨: {', '.join(missing)} (실행 자체는 계속 진행됨)"

    def _confirm_before_run(self) -> bool:
        """infra_vuln only: scanning "top N ports" (the default when no
        explicit port list is set) is a much larger request volume than
        scanning one chosen port -- ask before firing that off instead of
        just quietly running it."""
        if self.spec.key == "infra_vuln" and hasattr(self, "infra_scope_var"):
            scope = self.infra_scope_var.get()
            if scope == "selected_url_port" and self._infra_url_port is None:
                self._reject(
                    "'선택한 URL 포트만'을 선택했지만 아직 대상 URL에 포트가 지정되지 않았습니다.",
                    "상단 대상 표시줄에 포트가 포함된 URL을 적용하거나 다른 검사 범위를 선택하세요.",
                )
                return False
            if scope == "top_ports":
                top_ports = self._field_value("top_ports") or "1000"
                if not messagebox.askyesno(
                    "포트 범위 확인",
                    f"nmap 기준 상위 {top_ports}개 포트를 스캔합니다 (요청량이 클 수 있음).\n\n계속할까요?",
                ):
                    return False
            self._apply_infra_port_scope()
            app_logging.log_event(
                _logger, "INFO", "port_scope_selected", f"infra_vuln 검사 범위: {scope}", tool=self.spec.key, scope=scope,
            )
            ports_val, top_ports_val, count = self._infra_effective_ports()
            app_logging.log_event(
                _logger, "INFO", "effective_ports_built", "infra_vuln 최종 포트 구성", tool=self.spec.key,
                ports=ports_val, top_ports=top_ports_val, port_count=count,
            )
        if self._is_wordlist_tool():
            return self._confirm_unlimited_wordlist()
        return True

    def _reject(self, cause: str, action: str) -> None:
        self._append_output(f"실행할 수 없습니다.\n원인: {cause}\n조치: {action}\n\n")

    def _crawler_depth_error(self) -> tuple[str, str] | None:
        """crawler only (spec 5.3): '빈 값이나 숫자가 아닌 값은 실행 전에
        차단한다' -- --depth isn't argparse-required (it has a default), so
        _missing_required() alone would let an emptied or non-numeric field
        silently fall back to the CLI's own default (or crash the
        subprocess on a bad int) instead of being caught here first."""
        if self.spec.key != "crawler":
            return None
        raw = self._field_value("depth").strip()
        if not raw:
            return ("탐색 깊이가 비어 있습니다.", "1 이상의 정수(단계 수)를 입력하세요.")
        if not raw.lstrip("-").isdigit() or int(raw) < 1:
            return (f"탐색 깊이 값이 올바르지 않습니다: {raw!r}", "1 이상의 정수(단계 수)를 입력하세요 (1단계 = 시작 URL만).")
        return None

    def _crawler_pre_run_summary(self) -> str | None:
        """crawler only (spec 5.3): shown at the very top of the result
        console before the run starts, so the 화면 단계<->내부 --depth
        conversion is never a silent surprise."""
        if self.spec.key != "crawler":
            return None
        display_depth = self._field_value("depth").strip()
        internal_depth = str(int(display_depth) - 1) if display_depth.lstrip("-").isdigit() else "?"
        max_pages_raw = self._field_value("max_pages")
        max_pages = "전체 (제한값 0 = 전체, 새 URL이 없을 때까지 탐색)" if max_pages_raw == "0" else max_pages_raw or "(기본값)"
        min_interval = self._field_value("min_interval") or "(기본값)"
        workers = self._field_value("workers") or "(기본값)"
        return (
            f"설정한 탐색 깊이: {display_depth}단계\n"
            f"내부 최대 깊이: {internal_depth}\n"
            f"최대 페이지: {max_pages}개\n"
            f"요청 주기: 호스트당 최소 {min_interval}초\n"
            f"동시 요청: {workers}개\n\n"
        )

    # -- Burp History -> SPA 크롤링 후보 (crawler only, spec 6.3) --------------
    _LOCAL_HOST_ALIASES = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})

    def _build_crawler_history_section(self, form: ttk.Frame, row: int) -> int:
        ttk.Separator(form, orient=tk.HORIZONTAL).grid(row=row, column=0, columnspan=4, sticky=tk.EW, pady=6)
        row += 1
        ttk.Label(form, text="Burp History 연동 (SPA 보조 탐색)", font=("", 9, "bold"), foreground="#333").grid(
            row=row, column=0, columnspan=4, sticky=tk.W, pady=(0, 4)
        )
        row += 1
        self.crawler_use_history_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            form, text="Burp History에서 같은 대상의 경로/API를 후보로 가져와 확인",
            variable=self.crawler_use_history_var,
        ).grid(row=row, column=0, columnspan=4, sticky=tk.W)
        row += 1
        self.crawler_local_equiv_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            form, text="로컬 주소 동등 취급 (localhost / 127.0.0.1 / [::1]을 같은 대상으로 간주)",
            variable=self.crawler_local_equiv_var,
        ).grid(row=row, column=0, columnspan=4, sticky=tk.W)
        row += 1
        self.crawler_use_session_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            form, text="세션 쿠키 사용 (History에 기록된 쿠키를 후보 요청에도 재사용 -- 로그인 상태 의존)",
            variable=self.crawler_use_session_var,
        ).grid(row=row, column=0, columnspan=4, sticky=tk.W)
        row += 1
        ttk.Label(
            form,
            text="Proxy · HTTP History에 Burp Browser 트래픽이 쌓여 있어야 후보가 나옵니다 (Proxy 탭의 Burp 연동 참고).",
            foreground="#666", wraplength=1000, justify=tk.LEFT,
        ).grid(row=row, column=0, columnspan=4, sticky=tk.W, pady=(0, 6))
        row += 1
        return row

    def _apply_crawler_history_candidates(self, argv: list[str]) -> list[str]:
        if self.spec.key != "crawler" or not getattr(self, "crawler_use_history_var", None):
            return argv
        if not self.crawler_use_history_var.get():
            return argv
        provider = getattr(self, "history_provider", None)
        if provider is None:
            self._append_output("[참고: Burp History 연동을 사용할 수 없음 -- History 제공자가 연결되지 않음]\n")
            return argv
        target_url = self._field_value(self.positional_dest) if self.positional_dest else ""
        target = urlparse(target_url)
        if not target.hostname:
            return argv
        local_equiv = self.crawler_local_equiv_var.get()

        def _host_matches(host: str) -> bool:
            if host == target.hostname:
                return True
            if local_equiv and host in self._LOCAL_HOST_ALIASES and target.hostname in self._LOCAL_HOST_ALIASES:
                return True
            return False

        static_ext_re = re.compile(
            r"\.(png|jpe?g|gif|svg|webp|ico|css|scss|woff2?|ttf|eot|otf|mp4|webm|mp3|wav|map)(\?|$)", re.IGNORECASE
        )
        target_port = target.port or (443 if target.scheme == "https" else 80)
        try:
            max_pages = int(self._field_value("max_pages") or "200")
        except ValueError:
            max_pages = 200

        seen: set[str] = set()
        candidates: list[str] = []
        cookie_header = ""
        for record in provider():
            if not _host_matches(record.host) or record.port != target_port:
                continue
            if static_ext_re.search(record.url):
                continue
            if record.url in seen:
                continue
            seen.add(record.url)
            candidates.append(record.url)
            if self.crawler_use_session_var.get() and not cookie_header:
                for line in (record.req_headers or "").splitlines():
                    if line.lower().startswith("cookie:"):
                        cookie_header = line.split(":", 1)[1].strip()
            if len(candidates) >= max_pages:
                break

        if not candidates:
            self._append_output("[Burp History 연동: 같은 대상의 후보 경로를 찾지 못함]\n")
            return argv
        self._append_output(f"[Burp History 연동: 후보 {len(candidates)}개를 SPA 보조 탐색에 추가함]\n")
        argv = argv + ["--extra-urls", ",".join(candidates)]
        if cookie_header:
            argv = argv + ["--extra-header", f"Cookie: {cookie_header}"]
        return argv

    def on_run(self) -> None:
        if self.proc is not None:
            return
        missing = self._missing_required()
        if missing:
            self._reject(
                f"필수 값이 비어 있습니다 (빨간 * 표시 항목): {', '.join(missing)}",
                "위 항목에 값을 입력한 뒤 다시 실행하세요.",
            )
            return
        for cause, action in self._cross_field_errors():
            self._reject(cause, action)
            return
        depth_error = self._crawler_depth_error()
        if depth_error:
            self._reject(*depth_error)
            return
        dep_error = self._blocking_dependency_error()
        if dep_error:
            self._reject(*dep_error)
            return
        if not self._confirm_before_run():
            self._append_output("[사용자가 실행을 취소함]\n")
            return
        dep_warning = self._dependency_warning()
        if dep_warning:
            self._append_output(f"[참고: {dep_warning}]\n")
        argv = self._build_argv()
        if not argv:
            self._reject("입력된 값이 없습니다.", "위 항목에 값을 입력한 뒤 다시 실행하세요.")
            return
        argv = self._apply_crawler_history_candidates(argv)
        argv = self._apply_concurrency_scaling(argv)
        pre_run_summary = self._crawler_pre_run_summary()
        if pre_run_summary:
            self._append_output(pre_run_summary)
        self._append_output(f"$ python {self.spec.script.name} {' '.join(argv)}\n\n")
        self.run_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self._user_stopped = False
        self._run_start = datetime.now()
        self._run_id = app_logging.new_run_id()
        app_logging.log_event(
            _logger, "INFO", "tool_started", f"{self.spec.key} 실행 시작", run_id=self._run_id,
            tool=self.spec.key, target=self._current_target_display(), argv=log_redaction.redact_argv(argv),
        )
        list_est = self._compute_list_estimate()
        if list_est and not list_est.get("error"):
            app_logging.log_event(
                _logger, "INFO", "list_counted", f"{self.spec.key} 목록 후보 수", run_id=self._run_id,
                tool=self.spec.key, original=list_est["original"], valid=list_est["valid"], used=list_est["used"],
                unlimited=list_est["unlimited"],
            )
            app_logging.log_event(
                _logger, "INFO", "combination_estimated", f"{self.spec.key} 예상 최대 요청", run_id=self._run_id,
                tool=self.spec.key, combo=list_est["combo"], expected_max=list_est["expected_max"],
            )
        if self.spec.key == "ffuf" and "--no-auto-baseline" not in argv:
            app_logging.log_event(
                _logger, "INFO", "baseline_probed", "ffuf 기준 응답 사전 확인", run_id=self._run_id, tool=self.spec.key,
            )
        elif self.spec.key == "gobuster" and "--no-auto-wildcard" not in argv and "--exclude-length" not in argv:
            app_logging.log_event(
                _logger, "INFO", "baseline_probed", "gobuster wildcard 사전 확인", run_id=self._run_id, tool=self.spec.key,
            )
        self.run_summary_var.set(
            f"대상: {self._current_target_display()}  |  시작: {self._run_start:%H:%M:%S}  |  "
            f"{self._run_settings_display()}  |  실행 중..."
        )
        self._set_tab_state("실행 중")
        ToolTab._running_tabs.add(self)
        threading.Thread(target=self._run_subprocess, args=(argv,), daemon=True).start()

    def _current_target_display(self) -> str:
        if self.positional_dest and self.positional_dest in self.widgets:
            value = self._field_value(self.positional_dest)
            if value:
                return value
        return "(미지정)"

    def _run_settings_display(self) -> str:
        parts = []
        if hasattr(self, "preset_var"):
            parts.append(f"속도 프리셋: {self.preset_var.get()}")
        for dest in ("min_interval", "workers", "timeout"):
            if dest in self.widgets:
                label = KOREAN_OPTIONS.get(dest, {}).get("label", dest)
                parts.append(f"{label} {self._field_value(dest)}")
        return ", ".join(parts) if parts else "설정: 기본값"

    def _set_tab_state(self, suffix: str | None) -> None:
        # spec.name (bare), not spec.label -- the sub-notebook tab strip is
        # already scoped to one category, so repeating "Recon · " etc. on
        # every tab would be pure clutter (spec 8.2).
        title = self.spec.name if not suffix else f"{self.spec.name} ({suffix})"
        try:
            self.master.tab(self, text=title)
        except tk.TclError:
            pass
        self._update_category_indicator()

    def _update_category_indicator(self) -> None:
        """Flags the top-level category tab (e.g. "Recon ●") whenever any
        tool tab within it is currently running -- spec 8.2: "실행 중인
        도구가 있으면 해당 하위 탭과 상위 분류에 실행 상태를 표시한다".
        gui.py sets _category_notebook/_category_tab_widget/_category_base_label
        on each ToolTab after construction; a tab built standalone (e.g. in
        a test) without those set just skips this, no error."""
        cat_nb = getattr(self, "_category_notebook", None)
        cat_tab_widget = getattr(self, "_category_tab_widget", None)
        base_label = getattr(self, "_category_base_label", None)
        if cat_nb is None or cat_tab_widget is None or base_label is None:
            return
        sub_nb = self.master
        any_running = False
        for tab_id in sub_nb.tabs():
            widget = sub_nb.nametowidget(tab_id)
            # run_btn's disabled state, not self.proc -- proc is only set a
            # moment later inside the background thread once Popen() actually
            # returns, but run_btn is disabled synchronously the instant a
            # run starts, so it's the race-free signal here (same reasoning
            # DefaultContentScannerTab's _ModeRunner.run_btn follows).
            run_btn = getattr(widget, "run_btn", None)
            if run_btn is not None and str(run_btn["state"]) == "disabled":
                any_running = True
                break
            runners = getattr(widget, "_runners", None)  # DefaultContentScannerTab's 3 independent modes
            if runners and any(str(r.run_btn["state"]) == "disabled" for r in runners.values()):
                any_running = True
                break
        text = f"{base_label} ●" if any_running else base_label
        try:
            cat_nb.tab(cat_tab_widget, text=text)
        except tk.TclError:
            pass

    def _apply_concurrency_scaling(self, argv: list[str]) -> list[str]:
        """If other tabs are already scanning, stretch this run's request
        interval so the combined rate against (possibly) the same host
        doesn't just add up unchecked -- simple division of a safe rate
        across concurrent runs, not true global coordination, but requires
        no IPC since every tab's subprocess is launched from this one
        process anyway."""
        others = ToolTab._running_tabs - {self}
        if not others:
            return argv
        min_interval_action = next((a for a in self.actions if a["dest"] == "min_interval"), None)
        if not min_interval_action or not min_interval_action["option_strings"]:
            return argv
        flag = min_interval_action["option_strings"][0]
        if flag not in argv:
            return argv
        idx = argv.index(flag)
        try:
            current = float(argv[idx + 1])
        except (ValueError, IndexError):
            return argv
        scale = len(others) + 1
        scaled = round(current * scale, 3)
        argv[idx + 1] = str(scaled)
        self._append_output(
            f"[다른 진단 {len(others)}개가 동시 실행 중 -- 합산 부하를 줄이기 위해 "
            f"요청 주기를 {current}초 -> {scaled}초로 자동 조정]\n"
        )
        return argv

    # -- ffuf/Gobuster wildcard 이벤트 로깅 (spec §11) -----------------------
    # ffuf_scanner.py/gobuster_scanner.py already print/log these facts as
    # plain Korean text (captured verbatim into the worker-<run_id>.log
    # regardless) -- this re-emits the same facts as structured JSON events
    # so they're queryable without grepping worker logs, matching the named
    # events spec §11 lists (baseline_probed/wildcard_detected/
    # wildcard_rule_applied/automatic_retry_started/raw_hits_counted/
    # actionable_hits_summarized). Text-marker matching, not IPC, since the
    # scanners run as opaque subprocesses by design (see tool_worker.py).
    _WILDCARD_LOG_PATTERNS: list[tuple[str, re.Pattern]] = [
        ("wildcard_detected", re.compile(
            r"(?:\[기준 응답 감지\] 존재하지 않는 경로도 상태 (?P<status>\d+)(?: -> (?P<pattern>\S+))?, 크기 (?P<lengths>[\d,]+)B로 응답함"
            r"|wildcard 감지: 존재하지 않는 경로가 모두 (?P<status2>\d+)로 (?P<pattern2>\S+) 응답함 \(크기 (?P<lengths2>[\d,]+)\))"
        )),
        ("automatic_retry_started", re.compile(
            r"\[자동 보정\] (?:Gobuster가 wildcard (?P<status>\d+)/(?P<length>\d+)B를 감지했습니다|"
            r"--exclude-length (?P<retry_length>\d+)를 적용하여 1회 재시도합니다)"
        )),
        ("raw_hits_counted", re.compile(r"^실시간 매칭: (?P<count>[\d,]+)개$")),
        ("actionable_hits_summarized", re.compile(r"^최종 확인 대상: (?P<count>[\d,]+)개$")),
        ("actionable_hits_summarized", re.compile(r"^찾은 항목: (?P<count>[\d,]+)개\s*$")),
        ("wildcard_rule_applied", re.compile(
            r"wildcard 제외: (?P<count>\d+)개 \(기준: 상태 (?P<status>\d+), 패턴 (?P<pattern>.+)\)"
        )),
    ]

    def _scan_wildcard_log_line(self, line: str) -> None:
        if self.spec.key not in ("ffuf", "gobuster"):
            return
        stripped = line.strip()
        if not stripped:
            return
        for event, pattern in self._WILDCARD_LOG_PATTERNS:
            m = pattern.search(stripped)
            if not m:
                continue
            fields = {k: v for k, v in m.groupdict().items() if v is not None}
            app_logging.log_event(
                _logger, "INFO", event, f"{self.spec.key}: {event}", run_id=self._run_id,
                tool=self.spec.key, **fields,
            )
            return  # one event per line is enough -- patterns are mutually exclusive by construction

    def _run_subprocess(self, argv: list[str]) -> None:
        code: int | None = None
        start = time.monotonic()
        worker_log_path = app_logging.new_worker_log_path(self._run_id)
        try:
            with open(worker_log_path, "w", encoding="utf-8") as wf:
                wf.write(f"# tool={self.spec.key} run_id={self._run_id} argv={log_redaction.redact_argv(argv)}\n")
                self.proc = subprocess.Popen(
                    [*_self_invoke_prefix(), "--run-tool", str(self.spec.script), *argv],
                    cwd=str(self.spec.script.parent),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                )
                assert self.proc.stdout is not None
                for line in self.proc.stdout:
                    self.after(0, self._append_output, line)
                    wf.write(app_logging.redact_worker_line(line) + "\n")
                    self._scan_wildcard_log_line(line)
                self.proc.wait()
                code = self.proc.returncode
                wf.write(
                    f"# exit_code={code} elapsed_seconds={time.monotonic() - start:.3f} "
                    f"user_stopped={self._user_stopped}\n"
                )
            self.after(0, self._append_output, f"\n[종료 코드: {code}]\n")
        except Exception as exc:  # noqa: BLE001
            self.after(0, self._append_output, f"\n[실행 오류: {exc}]\n")
            app_logging.log_exception(
                _logger, "tool_failed", f"{self.spec.key} 실행 오류", sys.exc_info(),
                run_id=self._run_id, tool=self.spec.key,
            )
        finally:
            self.proc = None
            ToolTab._running_tabs.discard(self)
            self.after(0, self._on_finished, code)

    def _on_finished(self, code: int | None = None) -> None:
        self.run_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        if self._user_stopped:
            status = "중지됨"
        elif code == 0:
            status = "완료"
        else:
            status = "실행 실패"
        end = datetime.now()
        elapsed = f"{(end - self._run_start).total_seconds():.1f}초" if self._run_start else "?"
        start_str = f"{self._run_start:%H:%M:%S}" if self._run_start else "?"
        code_note = f" (종료 코드 {code})" if code not in (0, None) else ""
        self.run_summary_var.set(
            f"대상: {self._current_target_display()}  |  시작: {start_str}  |  종료: {end:%H:%M:%S} "
            f"(소요 {elapsed})  |  {self._run_settings_display()}  |  종료 상태: {status}{code_note}"
        )
        self._set_tab_state(status)
        app_logging.log_event(
            _logger, "INFO" if status == "완료" else "WARNING", "tool_finished",
            f"{self.spec.key} 실행 종료: {status}", run_id=self._run_id, tool=self.spec.key,
            exit_code=code, status=status,
            elapsed_seconds=(end - self._run_start).total_seconds() if self._run_start else None,
        )

    def on_stop(self) -> None:
        if self.proc is not None:
            self._user_stopped = True
            try:
                self.proc.terminate()
            except Exception:  # noqa: BLE001
                app_logging.log_exception(
                    _logger, "tool_failed", f"{self.spec.key} 중지 요청 실패", sys.exc_info(),
                    run_id=self._run_id, tool=self.spec.key,
                )

    def on_clear_output(self) -> None:
        self.output.configure(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.output.configure(state=tk.DISABLED)

    def _append_output(self, text: str) -> None:
        self.output.configure(state=tk.NORMAL)
        self.output.insert(tk.END, text)
        trim_console(self.output)
        self.output.see(tk.END)
        self.output.configure(state=tk.DISABLED)
