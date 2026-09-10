from __future__ import annotations

import json
import os
import queue
import secrets
import shutil
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk
from urllib.parse import urlparse

import app_logging
import app_paths
import import_ca
import launch_browser
import licenses
import log_redaction
import system_proxy
import target_context
from burp_bridge import BurpBridgeServer, _extension_jar_path
from history_filter import HistoryFilterState
from history_filter import matches as history_record_matches
from history_store import HistoryStore
from models import FlowRecord
from proxy_engine import ProxyEngine
from text_search import TextSearchBar
from tab_default_content import DefaultContentScannerTab
from tab_encoder import EncoderDecoderTab
from tab_jwt import JwtAnalyzerTab
from tool_registry import TOOLS
from tool_tab import ScrollableFrame, ToolTab

_TAB_OVERRIDES: dict[str, type[ToolTab]] = {
    "default_content": DefaultContentScannerTab,
    "jwt_analyzer": JwtAnalyzerTab,
}

# 인증서 저장/사용 위치 (spec: 단일 EXE 휴대용 배포 §6.3/§7 -- 개인 환경의
# 기존 ~/.mitmproxy CA는 최초 실행 시 한 번만 그대로 복사해 이어서 쓴다,
# 새로 만들지 않음. 아래 _migrate_legacy_ca()가 그 1회성 복사를 담당).
DEFAULT_CONFDIR = str(app_paths.CERTIFICATES_DIR)
_LEGACY_CONFDIR = os.path.expanduser("~/.mitmproxy")


def _migrate_legacy_ca() -> None:
    legacy = Path(_LEGACY_CONFDIR) / "mitmproxy-ca.pem"
    target = app_paths.CERTIFICATES_DIR / "mitmproxy-ca.pem"
    if legacy.is_file() and not target.is_file():
        try:
            app_paths.CERTIFICATES_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(legacy, target)
        except OSError:
            app_logging.log_exception(
                app_logging.get_logger("startup"), "tool_failed", "레거시 CA 인증서 이전 실패", sys.exc_info()
            )

# Burp-style double-click word selection. Tk's default double-click-select-word
# is inconsistent about where it stops on delimiter-dense text like a query
# string -- easiest to define the boundary explicitly: alnum/_/-/. is "word",
# everything else (whitespace AND special chars like & = ? / : ; , " ' etc.)
# is a boundary. Clicking directly on a delimiter selects just that one char.
_WORD_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")


def word_bounds(line_text: str, col: int) -> tuple[int | None, int | None]:
    """Pure function (no Tk) so it's directly testable: given one line of text
    and a column, return (start, end) of the token under that column the way
    a double-click should select it. Returns (None, None) for an out-of-range
    column (e.g. clicking past the end of the line)."""
    if not line_text or col >= len(line_text):
        return None, None
    if line_text[col] not in _WORD_CHARS:
        return col, col + 1
    start_col = col
    while start_col > 0 and line_text[start_col - 1] in _WORD_CHARS:
        start_col -= 1
    end_col = col
    while end_col < len(line_text) and line_text[end_col] in _WORD_CHARS:
        end_col += 1
    return start_col, end_col

def _drain_queue(q: "queue.Queue[FlowRecord]", max_items: int = 200) -> list[FlowRecord]:
    items: list[FlowRecord] = []
    for _ in range(max_items):
        try:
            items.append(q.get_nowait())
        except queue.Empty:
            break
    return items


SEVERITY_TAG = {"HIGH": "sev_high", "MEDIUM": "sev_medium", "LOW": "sev_low"}
SEVERITY_COLOR = {"HIGH": "#ffb3b3", "MEDIUM": "#ffe0a3", "LOW": "#fff6b3"}

_HISTORY_TREE_COLUMNS = ("seq", "time", "method", "host", "path", "status", "mime", "length", "flags")
_HISTORY_TREE_HEADERS = {
    "seq": ("#", 40), "time": ("시각", 90), "method": ("메소드", 60),
    "host": ("호스트", 170), "path": ("경로", 280), "status": ("상태", 70),
    "mime": ("MIME", 110), "length": ("길이", 70), "flags": ("의심 표시", 200),
}

_HISTORY_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "기타")
_HISTORY_STATUS_BUCKETS = ("응답 없음", "2xx", "3xx", "4xx", "5xx")
_HISTORY_MIME_CATEGORIES = ("HTML", "Script", "JSON/API", "XML", "CSS", "Image", "Font", "Media", "Binary", "기타")


class HistoryFilterDialog(tk.Toplevel):
    """Full categorized filter panel (spec §8.2) -- opened on demand from
    the always-visible bar's '필터 설정' button. Edits a *copy* of the
    current HistoryFilterState; nothing takes effect until '적용'."""

    def __init__(self, parent: tk.Tk, current: HistoryFilterState, on_apply) -> None:
        super().__init__(parent)
        self.title("History 필터 설정")
        self.transient(parent)
        self.resizable(False, False)
        self._on_apply = on_apply
        self._current = current

        outer = ttk.Frame(self, padding=10)
        outer.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            outer, text="같은 항목 안 여러 선택은 OR, 서로 다른 항목끼리는 AND로 적용됩니다.",
            foreground="#666",
        ).pack(anchor=tk.W, pady=(0, 8))

        # -- 요청 방식 --------------------------------------------------------
        ttk.Label(outer, text="요청 방식", font=("", 9, "bold")).pack(anchor=tk.W)
        method_frame = ttk.Frame(outer)
        method_frame.pack(anchor=tk.W, pady=(2, 8))
        self._method_vars: dict[str, tk.BooleanVar] = {}
        for i, m in enumerate(_HISTORY_METHODS):
            v = tk.BooleanVar(value=m in current.methods)
            self._method_vars[m] = v
            ttk.Checkbutton(method_frame, text=m, variable=v).grid(row=i // 4, column=i % 4, sticky=tk.W, padx=(0, 10))

        # -- 응답 상태 --------------------------------------------------------
        ttk.Label(outer, text="응답 상태", font=("", 9, "bold")).pack(anchor=tk.W)
        status_frame = ttk.Frame(outer)
        status_frame.pack(anchor=tk.W, pady=(2, 2))
        self._status_vars: dict[str, tk.BooleanVar] = {}
        for i, s in enumerate(_HISTORY_STATUS_BUCKETS):
            v = tk.BooleanVar(value=s in current.statuses)
            self._status_vars[s] = v
            ttk.Checkbutton(status_frame, text=s, variable=v).grid(row=0, column=i, sticky=tk.W, padx=(0, 10))
        status_custom_frame = ttk.Frame(outer)
        status_custom_frame.pack(anchor=tk.W, pady=(0, 8))
        ttk.Label(status_custom_frame, text="직접 입력 (예: 429 또는 500-599)").pack(side=tk.LEFT)
        self._status_custom_var = tk.StringVar(value=current.status_custom)
        ttk.Entry(status_custom_frame, textvariable=self._status_custom_var, width=20).pack(side=tk.LEFT, padx=(6, 0))

        # -- MIME 유형 --------------------------------------------------------
        ttk.Label(outer, text="MIME 유형", font=("", 9, "bold")).pack(anchor=tk.W)
        mime_frame = ttk.Frame(outer)
        mime_frame.pack(anchor=tk.W, pady=(2, 8))
        self._mime_vars: dict[str, tk.BooleanVar] = {}
        for i, mm in enumerate(_HISTORY_MIME_CATEGORIES):
            v = tk.BooleanVar(value=mm in current.mimes)
            self._mime_vars[mm] = v
            ttk.Checkbutton(mime_frame, text=mm, variable=v).grid(row=i // 5, column=i % 5, sticky=tk.W, padx=(0, 10))

        # -- 대상 범위 --------------------------------------------------------
        ttk.Label(outer, text="대상 범위", font=("", 9, "bold")).pack(anchor=tk.W)
        scope_frame = ttk.Frame(outer)
        scope_frame.pack(anchor=tk.W, pady=(2, 8), fill=tk.X)
        self._scope_var = tk.StringVar(value=current.scope)
        scope_options = [
            ("all", "전체 History"), ("current_target", "현재 상단 진단 대상만"),
            ("host", "선택한 host"), ("port", "선택한 port"),
            ("burp", "Burp 연동 수신 항목만"), ("independent", "독립 프록시 캡처 항목만"),
        ]
        for i, (val, label) in enumerate(scope_options):
            ttk.Radiobutton(scope_frame, text=label, value=val, variable=self._scope_var).grid(
                row=i // 2, column=i % 2, sticky=tk.W, padx=(0, 16)
            )
        host_row = ttk.Frame(outer)
        host_row.pack(anchor=tk.W, pady=(0, 8))
        ttk.Label(host_row, text="host").pack(side=tk.LEFT)
        self._scope_host_var = tk.StringVar(value=current.scope_host)
        ttk.Entry(host_row, textvariable=self._scope_host_var, width=24).pack(side=tk.LEFT, padx=(4, 16))
        ttk.Label(host_row, text="port").pack(side=tk.LEFT)
        self._scope_port_var = tk.StringVar(value=current.scope_port)
        ttk.Entry(host_row, textvariable=self._scope_port_var, width=8).pack(side=tk.LEFT, padx=(4, 0))

        # -- URL/파일 --------------------------------------------------------
        ttk.Label(outer, text="URL/파일", font=("", 9, "bold")).pack(anchor=tk.W)
        url_row1 = ttk.Frame(outer)
        url_row1.pack(anchor=tk.W, fill=tk.X, pady=(2, 2))
        ttk.Label(url_row1, text="URL/경로 포함 문자열").pack(side=tk.LEFT)
        self._url_contains_var = tk.StringVar(value=current.url_contains)
        ttk.Entry(url_row1, textvariable=self._url_contains_var, width=40).pack(side=tk.LEFT, padx=(6, 0))
        url_row2 = ttk.Frame(outer)
        url_row2.pack(anchor=tk.W, fill=tk.X, pady=(2, 2))
        ttk.Label(url_row2, text="확장자 포함").pack(side=tk.LEFT)
        self._ext_include_var = tk.StringVar(value=current.ext_include)
        ttk.Entry(url_row2, textvariable=self._ext_include_var, width=16).pack(side=tk.LEFT, padx=(4, 16))
        ttk.Label(url_row2, text="확장자 제외").pack(side=tk.LEFT)
        self._ext_exclude_var = tk.StringVar(value=current.ext_exclude)
        ttk.Entry(url_row2, textvariable=self._ext_exclude_var, width=16).pack(side=tk.LEFT, padx=(4, 0))
        url_row3 = ttk.Frame(outer)
        url_row3.pack(anchor=tk.W, fill=tk.X, pady=(2, 8))
        ttk.Label(url_row3, text="query parameter").pack(side=tk.LEFT)
        self._has_query_var = tk.StringVar(value=current.has_query)
        ttk.Combobox(
            url_row3, textvariable=self._has_query_var, values=["any", "yes", "no"], width=6, state="readonly"
        ).pack(side=tk.LEFT, padx=(4, 16))
        self._hide_static_var = tk.BooleanVar(value=current.hide_static)
        ttk.Checkbutton(url_row3, text="정적 파일 숨기기", variable=self._hide_static_var).pack(side=tk.LEFT)

        # -- 내용 검색 --------------------------------------------------------
        ttk.Label(outer, text="내용 검색", font=("", 9, "bold")).pack(anchor=tk.W)
        content_row1 = ttk.Frame(outer)
        content_row1.pack(anchor=tk.W, fill=tk.X, pady=(2, 2))
        ttk.Label(content_row1, text="포함 문자열").pack(side=tk.LEFT)
        self._content_query_var = tk.StringVar(value=current.content_query)
        ttk.Entry(content_row1, textvariable=self._content_query_var, width=40).pack(side=tk.LEFT, padx=(6, 0))
        content_row2 = ttk.Frame(outer)
        content_row2.pack(anchor=tk.W, pady=(2, 8))
        self._content_where_var = tk.StringVar(value=current.content_where)
        ttk.Combobox(
            content_row2, textvariable=self._content_where_var,
            values=["request", "response", "both"], width=10, state="readonly",
        ).pack(side=tk.LEFT, padx=(0, 12))
        self._content_case_var = tk.BooleanVar(value=current.content_case_sensitive)
        ttk.Checkbutton(content_row2, text="대소문자 구분", variable=self._content_case_var).pack(side=tk.LEFT, padx=(0, 12))
        self._content_regex_var = tk.BooleanVar(value=current.content_regex)
        ttk.Checkbutton(content_row2, text="정규식", variable=self._content_regex_var).pack(side=tk.LEFT)

        # -- 기타 --------------------------------------------------------
        ttk.Label(outer, text="기타", font=("", 9, "bold")).pack(anchor=tk.W)
        misc_row1 = ttk.Frame(outer)
        misc_row1.pack(anchor=tk.W, pady=(2, 2))
        ttk.Label(misc_row1, text="의심 항목").pack(side=tk.LEFT)
        self._findings_var = tk.StringVar(value=current.findings)
        ttk.Combobox(
            misc_row1, textvariable=self._findings_var, values=["any", "yes", "no"], width=6, state="readonly",
        ).pack(side=tk.LEFT, padx=(4, 0))
        misc_row2 = ttk.Frame(outer)
        misc_row2.pack(anchor=tk.W, pady=(2, 8))
        ttk.Label(misc_row2, text="최소 길이").pack(side=tk.LEFT)
        self._min_length_var = tk.StringVar(value=current.min_length)
        ttk.Entry(misc_row2, textvariable=self._min_length_var, width=10).pack(side=tk.LEFT, padx=(4, 16))
        ttk.Label(misc_row2, text="최대 길이").pack(side=tk.LEFT)
        self._max_length_var = tk.StringVar(value=current.max_length)
        ttk.Entry(misc_row2, textvariable=self._max_length_var, width=10).pack(side=tk.LEFT, padx=(4, 0))

        btn_row = ttk.Frame(outer)
        btn_row.pack(anchor=tk.E, fill=tk.X, pady=(4, 0))
        ttk.Button(btn_row, text="취소", command=self.destroy).pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(btn_row, text="적용", style="Accent.TButton", command=self._apply).pack(side=tk.RIGHT)

    def _apply(self) -> None:
        new_state = HistoryFilterState(
            methods={m for m, v in self._method_vars.items() if v.get()},
            statuses={s for s, v in self._status_vars.items() if v.get()},
            status_custom=self._status_custom_var.get().strip(),
            mimes={m for m, v in self._mime_vars.items() if v.get()},
            scope=self._scope_var.get(),
            scope_host=self._scope_host_var.get().strip(),
            scope_port=self._scope_port_var.get().strip(),
            url_contains=self._url_contains_var.get().strip(),
            ext_include=self._ext_include_var.get().strip(),
            ext_exclude=self._ext_exclude_var.get().strip(),
            has_query=self._has_query_var.get(),
            hide_static=self._hide_static_var.get(),
            content_query=self._content_query_var.get(),
            content_where=self._content_where_var.get(),
            content_case_sensitive=self._content_case_var.get(),
            content_regex=self._content_regex_var.get(),
            findings=self._findings_var.get(),
            min_length=self._min_length_var.get().strip(),
            max_length=self._max_length_var.get().strip(),
        )
        self.destroy()
        self._on_apply(new_state)


class ProxyScannerApp:
    def __init__(self, root: tk.Tk, session_id: str | None = None) -> None:
        self.root = root
        self.session_id = session_id or app_logging.new_session_id()
        self.logger = app_logging.get_logger("gui")
        # Tkinter swallows widget-callback exceptions by default (prints to
        # stderr only, invisible in a --windowed build) -- route them into
        # the same crash log as main-thread/worker-thread exceptions.
        root.report_callback_exception = app_logging.tk_report_callback_exception(
            self.session_id, on_crash=self._show_crash_dialog
        )

        self.root.title("Proxy Scanner -- 개인용 패시브 트래픽 분석기")
        self.root.geometry("1500x900")

        self.engine = ProxyEngine()
        self.records: dict[int, FlowRecord] = {}
        self.selected_record: FlowRecord | None = None
        self.history_filter = HistoryFilterState()
        self._history_shown_count = 0
        self._history_sort_col: str | None = None  # None = original capture (seq) order
        self._history_sort_dir: str = "asc"
        self.tool_tabs: dict[str, ToolTab] = {}
        self._we_set_system_proxy = False
        self._chromium_proc: subprocess.Popen | None = None
        self.burp_bridge = BurpBridgeServer(queue.Queue())

        # -- per-user app-data folder (spec: 단일 EXE 휴대용 배포 §7) ----------
        failed_dirs = app_paths.ensure_app_dirs()
        if failed_dirs:
            app_logging.log_event(
                self.logger, "ERROR", "resource_root_selected", "사용자 데이터 폴더 생성 실패", failed_dirs=failed_dirs
            )
            messagebox.showwarning(
                "사용자 데이터 폴더 생성 실패",
                "다음 경로에 쓸 수 없습니다:\n" + "\n".join(failed_dirs) +
                "\n\nHistory/설정/인증서 저장이 정상 동작하지 않을 수 있습니다.",
            )
        _migrate_legacy_ca()
        acl_ok = app_paths.restrict_to_current_user(app_paths.CERTIFICATES_DIR)
        app_logging.log_event(
            self.logger, "INFO" if acl_ok else "WARNING", "cert_dir_acl_restricted",
            "인증서 폴더 ACL 현재 사용자로 제한", path=str(app_paths.CERTIFICATES_DIR), success=acl_ok,
        )

        import tool_registry
        app_logging.log_event(
            self.logger, "INFO", "app_started", "Proxy Scanner 시작",
            version="1.0.0.0", frozen=getattr(sys, "frozen", False),
            tools_root=str(tool_registry.TOOLS_ROOT),
            tools_root_is_personal=str(tool_registry.TOOLS_ROOT) == r"E:\temp\tools",
        )

        # -- persistent History store -----------------------------------------
        try:
            self.history_store: HistoryStore | None = HistoryStore()
        except Exception as exc:  # noqa: BLE001
            self.history_store = None
            app_logging.log_exception(self.logger, "tool_failed", "History DB 열기 실패", sys.exc_info())
        self._session_count = 0
        self._total_count = 0
        self._max_seq_seen = 0

        self._build_menu()
        self._build_controls()
        self._build_body()
        self._restore_history()
        self._load_settings()
        self._verify_bundled_integrity()
        self._poll()

    def _show_crash_dialog(self, error_id: str, exc_value: BaseException) -> None:
        try:
            messagebox.showerror(
                "예상치 못한 오류",
                f"처리되지 않은 오류가 발생했습니다.\n오류 ID: {error_id}\n\n{type(exc_value).__name__}: {exc_value}\n\n"
                "도움말 > 로그 폴더 열기에서 자세한 내용을 확인할 수 있습니다.",
            )
        except Exception:  # noqa: BLE001
            pass

    # -- menu / about --------------------------------------------------------
    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)
        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label="라이선스 및 고지 사항", command=lambda: licenses.show_licenses_window(self.root))
        help_menu.add_separator()
        self.verbose_log_var = tk.BooleanVar(value=app_logging.is_debug_enabled())
        help_menu.add_checkbutton(
            label="상세 로그 사용 (DEBUG)", variable=self.verbose_log_var, command=self.on_toggle_verbose_logging
        )
        help_menu.add_command(label="로그 폴더 열기", command=self.on_open_logs_folder)
        help_menu.add_command(label="로그 내보내기...", command=self.on_export_logs)
        help_menu.add_command(label="로그 지우기", command=self.on_clear_logs)
        menubar.add_cascade(label="도움말", menu=help_menu)
        self.root.config(menu=menubar)

    def on_toggle_verbose_logging(self) -> None:
        enabled = self.verbose_log_var.get()
        app_logging.set_debug_enabled(enabled)
        app_logging.log_event(self.logger, "INFO", "verbose_logging_toggled", "상세 로그 설정 변경", enabled=enabled)

    def on_open_logs_folder(self) -> None:
        try:
            app_logging.open_logs_folder()
        except OSError as exc:
            messagebox.showerror("로그 폴더 열기 실패", str(exc))

    def on_export_logs(self) -> None:
        default_name = f"proxy-scanner-logs-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
        dest = filedialog.asksaveasfilename(
            title="로그 내보내기", defaultextension=".zip", initialfile=default_name,
            filetypes=[("ZIP 파일", "*.zip")],
        )
        if not dest:
            return
        try:
            count = app_logging.export_logs(Path(dest), manifest_text=self._build_export_manifest())
        except OSError as exc:
            messagebox.showerror("로그 내보내기 실패", str(exc))
            return
        app_logging.log_event(self.logger, "INFO", "logs_exported", "로그 내보내기 완료", file_count=count, dest=str(dest))
        messagebox.showinfo("로그 내보내기 완료", f"{count}개 파일을 내보냈습니다:\n{dest}")

    def _build_export_manifest(self) -> str:
        """spec 5.10: 진단 로그 내보내기에 '버전 및 내장 자원 목록'과
        '설정값의 민감정보 제거 사본'을 함께 묶는다."""
        import tool_registry
        lines = [
            f"version: 1.0.0.0", f"frozen: {getattr(sys, 'frozen', False)}",
            f"tools_root: {tool_registry.TOOLS_ROOT}",
            f"tool_count: {len(tool_registry.TOOLS)}",
            "", "-- settings.json (민감정보 제거) --",
        ]
        try:
            raw = app_paths.SETTINGS_PATH.read_text(encoding="utf-8")
            data = json.loads(raw)
            if "target_url" in data:
                data["target_url"] = log_redaction.redact_url(data["target_url"])
            lines.append(json.dumps(data, ensure_ascii=False, indent=2))
        except (OSError, ValueError) as exc:
            lines.append(f"(설정 파일 없음 또는 읽기 실패: {exc})")
        return "\n".join(lines)

    def on_clear_logs(self) -> None:
        ok = messagebox.askyesno("로그 지우기", "저장된 모든 진단 로그를 삭제합니다.\n삭제 후에는 복구할 수 없습니다.\n\n계속할까요?")
        if not ok:
            return
        app_logging.clear_all_logs(self.session_id)
        app_logging.log_event(self.logger, "INFO", "logs_cleared", "사용자가 로그를 지움")
        messagebox.showinfo("로그 지우기 완료", "저장된 진단 로그를 삭제했습니다.")

    def _verify_bundled_integrity(self) -> None:
        """One-time startup check (spec §10: "EXE 내부 자원의 무결성을 시작
        시... 검증한다") -- only meaningful in a frozen/portable run using
        the bundled fallback resources (a personal-env dev run has its own,
        separately-maintained files and isn't "the EXE's own resources").
        Missing files here mean a corrupted or incomplete build, not
        something the user can fix by installing something -- surfaced as
        exactly the spec §9 error string, and never blocks startup."""
        if not getattr(sys, "frozen", False):
            return
        import tool_registry
        if tool_registry.TOOLS_ROOT != Path(getattr(sys, "_MEIPASS", "")):
            return  # resolved to the personal env path -- nothing bundled to verify
        missing = [str(spec.script) for spec in tool_registry.TOOLS if not spec.script.is_file()]
        app_logging.log_event(
            self.logger, "WARNING" if missing else "INFO", "resource_integrity_checked",
            "내장 자원 무결성 검사", missing_count=len(missing), missing=missing,
        )
        if missing:
            messagebox.showwarning(
                "내장 자원 손상 가능",
                "내장 도구를 불러오지 못했습니다. EXE가 손상되었을 수 있습니다.\n\n다음 파일이 없습니다:\n"
                + "\n".join(missing),
            )

    # -- settings persistence (spec §7: "settings.json 최근 설정과 UI 상태") --
    def _load_settings(self) -> None:
        try:
            data = json.loads(app_paths.SETTINGS_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            app_logging.log_event(
                self.logger, "INFO", "settings_loaded", "설정 파일 없음 또는 손상 -- 기본값 사용", error=str(exc)
            )
            return
        geometry = data.get("window_geometry")
        if isinstance(geometry, str) and geometry:
            try:
                self.root.geometry(geometry)
            except tk.TclError:
                pass
        target_url = data.get("target_url")
        if isinstance(target_url, str) and target_url:
            self.target_var.set(target_url)
        target_port = data.get("target_port")
        if isinstance(target_port, str):
            self.target_port_var.set(target_port)
        if target_url:
            self.on_apply_target()
        app_logging.log_event(self.logger, "INFO", "settings_loaded", "설정 로드됨")

    def _save_settings(self) -> None:
        data = {
            "window_geometry": self.root.geometry(),
            "target_url": self.target_var.get(),
            "target_port": self.target_port_var.get(),
        }
        try:
            app_paths.SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
            app_paths.SETTINGS_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            app_logging.log_event(self.logger, "INFO", "settings_saved", "설정 저장됨")
        except OSError as exc:
            app_logging.log_event(self.logger, "WARNING", "settings_saved", "설정 저장 실패", error=str(exc))

    # -- UI construction ---------------------------------------------------
    def _build_controls(self) -> None:
        self._build_target_bar()
        self._build_status_bar()

    def _build_target_bar(self) -> None:
        """The one thing the user actually has to set to start diagnosing
        something: a target URL. Every URL/host-based tool tab reads its
        starting values from here (target_context.TargetContext) instead of
        each tab asking for host/port separately."""
        self.target_ctx: target_context.TargetContext | None = None

        frame = ttk.Frame(self.root, padding=(8, 8, 8, 4))
        frame.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(frame, text="진단 대상 URL", font=("", 10, "bold")).grid(row=0, column=0, sticky=tk.W)
        self.target_var = tk.StringVar(value="")
        target_entry = ttk.Entry(frame, textvariable=self.target_var, width=48)
        target_entry.grid(row=0, column=1, sticky=tk.W, padx=(8, 16))
        target_entry.bind("<Return>", lambda _e: self.on_apply_target())

        ttk.Label(frame, text="포트 (선택)").grid(row=0, column=2, sticky=tk.W)
        self.target_port_var = tk.StringVar(value="")
        port_entry = ttk.Entry(frame, textvariable=self.target_port_var, width=8)
        port_entry.grid(row=0, column=3, sticky=tk.W, padx=(8, 16))
        port_entry.bind("<Return>", lambda _e: self.on_apply_target())

        ttk.Button(frame, text="대상 적용", style="Accent.TButton", command=self.on_apply_target).grid(
            row=0, column=4, sticky=tk.W
        )

        ttk.Label(
            frame, text="입력한 경우에만 URL의 포트보다 우선 적용됩니다.", foreground="#888"
        ).grid(row=1, column=1, columnspan=3, sticky=tk.W, padx=(8, 0), pady=(2, 0))

        self.target_display_var = tk.StringVar(value="아직 대상이 적용되지 않았습니다.")
        self.target_display_label = ttk.Label(
            self.root, textvariable=self.target_display_var, foreground="#888", padding=(8, 0, 8, 6)
        )
        self.target_display_label.pack(side=tk.TOP, fill=tk.X)

    def _build_status_bar(self) -> None:
        """Persistent top-level bar -- just a live status/capture-count
        readout now, shared by whichever capture path is populating History
        (Burp 연동 or 독립 프록시). Per the 후속_기능개선_통합_명세서 §3.1
        (which explicitly takes priority over the older Chromium 자동
        History spec), self-launching a dedicated Chromium is no longer the
        primary/default flow -- Burp Browser integration (Proxy 카테고리의
        'Burp 연동' 탭) is. The old 'Chromium 열기' button now lives inside
        '독립 프록시 설정' as a secondary/독립 옵션 instead of appearing
        here as the headline action."""
        status_frame = ttk.Frame(self.root, padding=(8, 0, 8, 4))
        status_frame.pack(side=tk.TOP, fill=tk.X)

        self.status_var = tk.StringVar(value="● 정지됨")
        ttk.Label(status_frame, textvariable=self.status_var, foreground="#888").pack(side=tk.RIGHT)
        self.capture_count_var = tk.StringVar(value="현재 세션 0개 | 전체 저장 0개")
        ttk.Label(status_frame, textvariable=self.capture_count_var, foreground="#2f6fed", font=("", 9, "bold")).pack(
            side=tk.RIGHT, padx=(0, 16)
        )

    def _build_burp_bridge_tab(self, parent: ttk.Frame) -> None:
        """Burp 연동 tab (spec: Burp Browser 연동 §3.3 최초 연결 흐름) --
        export the extension jar, show registration instructions, start/stop
        the local receiver, and reflect its live status. Clearly separate
        from 독립 프록시 설정: Burp Browser's own HTTPS handling means
        Proxy Scanner's own CA is never involved here (spec 3.6)."""
        scroll = ScrollableFrame(parent)
        scroll.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        body = ttk.Frame(scroll.body, padding=(10, 10))
        body.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(
            body,
            text="Burp Proxy 도구를 통과한 요청/응답을 이 프로그램의 HTTP History로 자동 전달합니다 "
            "(Burp Repeater/Scanner 등 다른 도구의 요청은 전달되지 않음). Montoya API가 구분해주는 것은 "
            "'Proxy 도구를 통과했는지'까지이므로, Burp 내장 브라우저와 같은 Proxy 리스너를 쓰는 별도 외부 "
            "브라우저가 있다면 그 트래픽까지는 완전히 구분되지 않을 수 있습니다. Burp Browser의 HTTPS는 "
            "Burp가 자체 처리하므로, 이 연동에는 아래 '독립 프록시 설정' 탭의 CA 인증서가 필요하지 않습니다.",
            foreground="#555", wraplength=1000, justify=tk.LEFT,
        ).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 10))

        step1 = ttk.Frame(body)
        step1.grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=(0, 10))
        ttk.Label(step1, text="1단계: 연동 확장 내보내기", font=("", 9, "bold")).pack(anchor=tk.W)
        ttk.Button(step1, text="연동 확장 파일 내보내기 (.jar)", command=self.on_export_burp_extension).pack(
            anchor=tk.W, pady=(4, 0)
        )
        ttk.Label(
            step1,
            text="내보낸 .jar 파일을 Burp Suite의 Extensions 화면(Extensions > Installed > Add)에서 "
            "'Extension type: Java'로 한 번만 등록하세요.",
            foreground="#666", wraplength=1000, justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(2, 0))

        step2 = ttk.Frame(body)
        step2.grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=(0, 10))
        ttk.Label(step2, text="2단계: 연결 대기 시작", font=("", 9, "bold")).pack(anchor=tk.W)

        port_row = ttk.Frame(step2)
        port_row.pack(anchor=tk.W, pady=(4, 0))
        ttk.Label(port_row, text="로컬 포트").pack(side=tk.LEFT)
        self.burp_port_var = tk.StringVar(value=str(self.burp_bridge.port))
        ttk.Entry(port_row, textvariable=self.burp_port_var, width=8).pack(side=tk.LEFT, padx=(6, 16))
        ttk.Label(port_row, text="세션 토큰 (이 프로그램이 생성 -- 기준값)").pack(side=tk.LEFT)
        self.burp_token_var = tk.StringVar(value=self.burp_bridge.token)
        ttk.Entry(port_row, textvariable=self.burp_token_var, width=52, state="readonly").pack(
            side=tk.LEFT, padx=(6, 8)
        )
        ttk.Button(port_row, text="토큰 복사", command=self.on_copy_burp_token).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(port_row, text="토큰 재발급", command=self.on_regenerate_burp_token).pack(side=tk.LEFT)
        ttk.Label(
            step2,
            text="'토큰 복사'로 복사한 뒤, Burp Extensions 화면에서 이 확장을 선택하면 나오는 'Proxy Scanner' "
            "탭의 세션 토큰 칸에 붙여넣고 '토큰 적용' -> '연결 테스트'로 확인하세요 -- 토큰은 이 프로그램이 "
            "만드는 값이 기준이며, Burp 쪽 값을 여기 붙여넣는 방식이 아닙니다.",
            foreground="#666", wraplength=1000, justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(4, 0))

        btn_row = ttk.Frame(step2)
        btn_row.pack(anchor=tk.W, pady=(8, 0))
        self.burp_connect_btn = ttk.Button(btn_row, text="연결 대기 시작", style="Accent.TButton", command=self.on_toggle_burp_bridge)
        self.burp_connect_btn.pack(side=tk.LEFT)

        status_row = ttk.Frame(body)
        status_row.grid(row=3, column=0, columnspan=3, sticky=tk.W, pady=(10, 0))
        self.burp_status_var = tk.StringVar(value=self.burp_bridge.status_text())
        ttk.Label(status_row, textvariable=self.burp_status_var, foreground="#888", font=("", 9, "bold")).pack(side=tk.LEFT)
        self.burp_count_var = tk.StringVar(value=f"수신 {self.burp_bridge.received_count}개")
        ttk.Label(status_row, textvariable=self.burp_count_var, foreground="#2f6fed").pack(side=tk.LEFT, padx=(16, 0))

        scroll.bind_wheel_recursive()

    def on_export_burp_extension(self) -> None:
        src = _extension_jar_path()
        if not src.is_file():
            messagebox.showerror(
                "내보내기 실패",
                f"연동 확장 파일을 찾을 수 없습니다: {src}\n(개발 환경이라면 burp_extension 폴더에서 먼저 빌드하세요.)",
            )
            return
        dest_dir = filedialog.askdirectory(title="연동 확장(.jar) 저장 폴더 선택")
        if not dest_dir:
            return
        dest = Path(dest_dir) / src.name
        try:
            shutil.copyfile(src, dest)
        except OSError as exc:
            messagebox.showerror("내보내기 실패", f"파일을 복사하지 못했습니다: {exc}")
            return
        messagebox.showinfo(
            "내보내기 완료",
            f"저장 위치: {dest}\n\nBurp Suite의 Extensions > Installed > Add에서 이 파일을 "
            "'Extension type: Java'로 등록하세요. 등록 후 나오는 'Proxy Scanner' 탭에 이 화면의 "
            "포트·토큰을 입력하면 연동됩니다.",
        )

    def on_regenerate_burp_token(self) -> None:
        if self.burp_bridge.running:
            messagebox.showwarning("토큰 재발급", "연결 대기 중에는 토큰을 바꿀 수 없습니다. 먼저 연결을 중지하세요.")
            return
        self.burp_bridge.token = secrets.token_hex(24)
        self.burp_token_var.set(self.burp_bridge.token)
        messagebox.showinfo("토큰 재발급됨", "Burp 확장 쪽에도 '토큰 복사'로 새 값을 다시 붙여넣고 적용해야 합니다.")

    def on_copy_burp_token(self) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(self.burp_bridge.token)

    def on_toggle_burp_bridge(self) -> None:
        if self.burp_bridge.running:
            self.burp_bridge.stop()
            self.burp_connect_btn.configure(text="연결 대기 시작")
            self.burp_status_var.set(self.burp_bridge.status_text())
            return
        try:
            port = int(self.burp_port_var.get())
        except ValueError:
            messagebox.showerror("오류", "포트는 숫자여야 함")
            return
        try:
            self.burp_bridge.start(port)
        except OSError as exc:
            messagebox.showerror("연결 대기 시작 실패", str(exc))
            self.burp_status_var.set(self.burp_bridge.status_text())
            return
        self.burp_connect_btn.configure(text="연결 중지")
        self.burp_status_var.set(self.burp_bridge.status_text())

    def _build_independent_proxy_tab(self, parent: ttk.Frame) -> None:
        """독립 프록시 설정 tab (Proxy category) -- listen address, manual
        시작/중지, this program's own dedicated-Chromium option, system-proxy
        toggle, CA import, history-clear. Secondary/독립 path now (spec
        3.1 -- Burp 연동 is the recommended default): still useful when Burp
        isn't running, or for auth-gated sites where the user wants Proxy
        Scanner's own CA installed in a dedicated browser profile."""
        # Scrollable so this stays reachable even in a short window (spec
        # 4.2: "프록시 고급 설정 영역").
        adv_scroll = ScrollableFrame(parent)
        adv_scroll.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        adv_body = adv_scroll.body

        ttk.Label(
            adv_body,
            text="Burp가 없거나 Burp 연동을 쓰지 않을 때를 위한 독립 실행 모드입니다. "
            "이 프로그램이 직접 프록시를 열고, 필요하면 전용 Chromium 창도 직접 엽니다.",
            foreground="#555", wraplength=1000, justify=tk.LEFT, padding=(10, 10, 10, 4),
        ).pack(side=tk.TOP, fill=tk.X)

        bar1 = ttk.Frame(adv_body, padding=(10, 4, 10, 0))
        bar1.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(bar1, text="리슨 주소", font=("", 9, "bold")).pack(side=tk.LEFT)
        self.host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(bar1, textvariable=self.host_var, width=12).pack(side=tk.LEFT, padx=(6, 2))
        ttk.Label(bar1, text=":").pack(side=tk.LEFT)
        # 8081, not Burp's default 8080 -- so running both at once doesn't
        # collide out of the box and require the user to notice/change it.
        self.port_var = tk.StringVar(value="8081")
        ttk.Entry(bar1, textvariable=self.port_var, width=6).pack(side=tk.LEFT, padx=(2, 10))

        self.start_btn = ttk.Button(bar1, text="▶ 시작", command=self.on_start)
        self.start_btn.pack(side=tk.LEFT, padx=4)
        self.stop_btn = ttk.Button(bar1, text="■ 중지", command=self.on_stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)
        ttk.Button(bar1, text="Chromium 열기 (독립 모드)", command=self.on_open_chromium).pack(side=tk.LEFT, padx=(16, 4))

        hint = ttk.Label(
            adv_body,
            text="↑ 이건 이 프록시 자체가 대기할 주소입니다 -- Burp 주소도 아니고 상단의 진단 대상 URL도 아님. "
            "'Chromium 열기'는 이 값을 자동으로 사용해 프록시를 필요하면 먼저 시작함 (신경 쓸 필요 없음). "
            "다른 브라우저를 수동으로 이 프록시에 연결하려면 그 브라우저 프록시 설정에 이 주소:포트를 직접 지정 "
            "(Burp와 동시에 켜려면 포트를 다르게).",
            foreground="#b35c00", padding=(10, 4, 10, 4), wraplength=1000, justify=tk.LEFT,
        )
        hint.pack(side=tk.TOP, fill=tk.X)

        bar2 = ttk.Frame(adv_body, padding=(10, 0, 10, 10))
        bar2.pack(side=tk.TOP, fill=tk.X)

        if system_proxy.IS_WINDOWS:
            self.sys_proxy_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(
                bar2,
                text="시작할 때 Windows 시스템 프록시로 자동 설정 (IE/Edge/Chrome만 적용됨 -- Firefox는 브라우저 자체 설정 필요)",
                variable=self.sys_proxy_var,
            ).pack(side=tk.LEFT)

        ttk.Button(bar2, text="CA 인증서 폴더 열기", command=self.on_open_cert_dir).pack(side=tk.LEFT, padx=(16, 4))
        ttk.Button(bar2, text="CA 가져오기 (PKCS#12)", command=self.on_import_ca).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar2, text="히스토리 지우기", command=self.on_clear).pack(side=tk.LEFT, padx=4)

        adv_scroll.bind_wheel_recursive()

    def on_apply_target(self) -> None:
        try:
            ctx = target_context.parse_target(self.target_var.get(), self.target_port_var.get())
        except target_context.TargetError as exc:
            self.target_ctx = None
            self.target_display_var.set(f"입력 오류: {exc}")
            self.target_display_label.configure(foreground="#b3261e")
            return
        self.target_ctx = ctx
        self.target_display_label.configure(foreground="#1b6b3a")
        self.target_display_var.set(f"현재 대상: {ctx.origin}  (전체 URL: {ctx.url})")
        for tab in self.tool_tabs.values():
            tab.apply_target(ctx)
        # "현재 대상만" (quick search checkbox and/or the filter dialog's
        # 대상 범위 선택) depends on target_ctx -- keep the tree in sync the
        # instant the target changes, not just on the next filter edit.
        if hasattr(self, "history_filter"):
            self._reapply_history_filter()

    # Category classification for the 2단 tab structure (spec 8.2) -- first
    # row picks one of these, second row shows only that category's own
    # feature tabs (bare names, no repeated "Recon ·" prefix).
    _CATEGORIES = ("Proxy", "Recon", "Scanner", "Decoder")

    def _build_body(self) -> None:
        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        top = ttk.Frame(paned)
        paned.add(top, weight=3)

        self.category_notebook = ttk.Notebook(top)
        self.category_notebook.pack(fill=tk.BOTH, expand=True)

        self.category_frames: dict[str, ttk.Frame] = {}
        self.category_subnotebooks: dict[str, ttk.Notebook] = {}
        for cat in self._CATEGORIES:
            frame = ttk.Frame(self.category_notebook)
            self.category_notebook.add(frame, text=cat)
            sub_nb = ttk.Notebook(frame)
            sub_nb.pack(fill=tk.BOTH, expand=True)
            self.category_frames[cat] = frame
            self.category_subnotebooks[cat] = sub_nb

        # -- Proxy category: HTTP History / Issues / 독립 프록시 설정 --------
        proxy_nb = self.category_subnotebooks["Proxy"]
        # Tab naming follows Burp Suite's own vocabulary: Burp's "Proxy" tab
        # has an "HTTP history" sub-tab for raw traffic, and its "Dashboard"
        # has an "Issues" list for findings -- same split here.
        all_frame = ttk.Frame(proxy_nb)
        proxy_nb.add(all_frame, text="HTTP History")
        self._build_history_filter_bar(all_frame)
        self.tree_all = self._make_tree(all_frame, sortable=True)

        sus_frame = ttk.Frame(proxy_nb)
        proxy_nb.add(sus_frame, text="Issues")
        self.tree_sus = self._make_tree(sus_frame)

        burp_frame = ttk.Frame(proxy_nb)
        proxy_nb.add(burp_frame, text="Burp 연동")
        self._build_burp_bridge_tab(burp_frame)

        proxy_settings_frame = ttk.Frame(proxy_nb)
        proxy_nb.add(proxy_settings_frame, text="독립 프록시 설정")
        self._build_independent_proxy_tab(proxy_settings_frame)

        # -- Recon/Scanner/Decoder categories: one sub-tab per tool ---------
        for spec in TOOLS:
            tab_cls = _TAB_OVERRIDES.get(spec.key, ToolTab)
            sub_nb = self.category_subnotebooks[spec.category]
            tab = tab_cls(sub_nb, spec)
            sub_nb.add(tab, text=spec.name)
            self.tool_tabs[spec.key] = tab
            # Lets ToolTab._set_tab_state() also flag the top-level category
            # tab (spec 8.2: "실행 중인 도구가 있으면 해당 하위 탭과 상위
            # 분류에 실행 상태를 표시한다").
            tab._category_notebook = self.category_notebook
            tab._category_tab_widget = self.category_frames[spec.category]
            tab._category_base_label = spec.category

        # spec 6.3: Crawler's Burp History 연동 checkbox reads the same
        # in-memory History dict the Proxy · HTTP History tree shows.
        self.tool_tabs["crawler"].history_provider = lambda: list(self.records.values())

        encoder_tab = EncoderDecoderTab(self.category_subnotebooks["Decoder"])
        self.category_subnotebooks["Decoder"].add(encoder_tab, text="Encoder/Decoder")

        bottom = ttk.Frame(paned)
        paned.add(bottom, weight=2)

        send_bar = ttk.Frame(bottom, padding=(4, 4))
        send_bar.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(send_bar, text="선택한 요청을 다음 도구로 보내기:").pack(side=tk.LEFT)
        self.send_target_var = tk.StringVar(value=next((s.label for s in TOOLS if s.target_kind != "none"), ""))
        sendable = [s.label for s in TOOLS if s.target_kind != "none"]
        ttk.Combobox(send_bar, textvariable=self.send_target_var, values=sendable, width=24, state="readonly").pack(
            side=tk.LEFT, padx=6
        )
        ttk.Button(send_bar, text="보내기", command=self.on_send_to_tool).pack(side=tk.LEFT)

        self.summary_var = tk.StringVar(value="(히스토리에서 요청을 선택하면 여기에 표시됨)")
        ttk.Label(bottom, textvariable=self.summary_var, padding=(4, 2), foreground="#333").pack(
            side=tk.TOP, fill=tk.X
        )

        self.findings_text = tk.Text(
            bottom, height=3, wrap=tk.WORD, font=("Consolas", 9), background="#fff8e1", borderwidth=1, relief=tk.SOLID
        )
        self.findings_text.pack(side=tk.TOP, fill=tk.X, padx=4, pady=(0, 4))
        self.findings_text.configure(state=tk.DISABLED)

        # Separate, independently resizable Request/Response panes (drag the
        # sash between them) -- this is what was missing before: everything
        # used to be one single undivided text blob, so there was nothing to
        # actually resize even though the outer top/bottom sash worked fine.
        detail_paned = ttk.PanedWindow(bottom, orient=tk.HORIZONTAL)
        detail_paned.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

        req_frame = ttk.Frame(detail_paned)
        detail_paned.add(req_frame, weight=1)
        ttk.Label(req_frame, text="Request", font=("", 9, "bold")).pack(anchor=tk.W)
        self.request_text = scrolledtext.ScrolledText(req_frame, wrap=tk.NONE, font=("Consolas", 9))
        self.request_text.pack(fill=tk.BOTH, expand=True)
        self.request_text.configure(state=tk.DISABLED)
        self._bind_smart_dblclick(self.request_text)
        self.request_search = TextSearchBar(req_frame, self.request_text)

        resp_frame = ttk.Frame(detail_paned)
        detail_paned.add(resp_frame, weight=1)
        ttk.Label(resp_frame, text="Response", font=("", 9, "bold")).pack(anchor=tk.W)
        self.response_text = scrolledtext.ScrolledText(resp_frame, wrap=tk.NONE, font=("Consolas", 9))
        self.response_text.pack(fill=tk.BOTH, expand=True)
        self.response_text.configure(state=tk.DISABLED)
        self._bind_smart_dblclick(self.response_text)
        self.response_search = TextSearchBar(resp_frame, self.response_text)

    # -- HTTP History 필터 (spec: 목록 진행·Infra·ffuf·Gobuster·HTTP History
    # 개선명세서 §8) -- always-visible summary/quick-search bar here; the
    # full categorized filter lives in a separate dialog (_open_history_
    # filter_dialog) since cramming ~20 conditions into this bar would just
    # be noise for the common case of "no filter, or a quick text search".
    # Only the main HTTP History tree is filtered -- the Issues tab keeps
    # showing every finding-bearing record regardless, a different view by
    # design, not an oversight.
    def _build_history_filter_bar(self, parent: ttk.Frame) -> None:
        bar = ttk.Frame(parent, padding=(4, 4, 4, 2))
        bar.pack(side=tk.TOP, fill=tk.X)
        self.history_filter_summary_var = tk.StringVar(value="Filter: Showing 0 of 0")
        ttk.Label(bar, textvariable=self.history_filter_summary_var, foreground="#333").pack(side=tk.LEFT)
        ttk.Button(bar, text="필터 설정", command=self._open_history_filter_dialog).pack(side=tk.LEFT, padx=(10, 2))
        ttk.Button(bar, text="초기화", command=self._reset_history_filter).pack(side=tk.LEFT)

        search_bar = ttk.Frame(parent, padding=(4, 0, 4, 4))
        search_bar.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(search_bar, text="빠른 검색").pack(side=tk.LEFT)
        self.quick_search_var = tk.StringVar(value="")
        ttk.Entry(search_bar, textvariable=self.quick_search_var, width=40).pack(side=tk.LEFT, padx=(6, 10))
        self.quick_search_current_target_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            search_bar, text="현재 대상만", variable=self.quick_search_current_target_var,
            command=self._reapply_history_filter,
        ).pack(side=tk.LEFT)
        self._quick_search_job: str | None = None
        self.quick_search_var.trace_add("write", self._on_quick_search_changed)

    def _on_quick_search_changed(self, *_args: object) -> None:
        if self._quick_search_job is not None:
            self.root.after_cancel(self._quick_search_job)
        self._quick_search_job = self.root.after(200, self._reapply_history_filter)

    def _current_target_host_port(self) -> tuple[str | None, int | None]:
        if self.target_ctx is None:
            return None, None
        return self.target_ctx.host, self.target_ctx.port

    def _history_record_visible(self, record: FlowRecord) -> bool:
        return history_record_matches(record, self.history_filter)

    # -- 열 정렬 (spec §9) -- 3단 토글: 오름차순 -> 내림차순 -> 원래 캡처(seq) 순.
    # 숫자 열은 실제 숫자로 비교해서 "100, 20, 3" 같은 문자열 정렬 오류를 피하고,
    # 동일 값은 항상 seq로 안정 정렬한다.
    _SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, None: 0}

    def _history_sort_key(self, col: str):
        if col == "seq":
            return lambda r: r.seq
        if col == "time":
            return lambda r: r.ts
        if col == "method":
            return lambda r: r.method
        if col == "host":
            return lambda r: (r.host, r.port)
        if col == "path":
            return lambda r: r.path
        if col == "status":
            # 응답 없음(None)은 항상 정수 상태코드보다 앞/뒤로 명확히 구분되도록
            # (있음, 코드) 튜플로 -- None을 0/음수로 뭉뚱그리면 실제 상태코드
            # 0이나 음수와 섞일 위험이 있다.
            return lambda r: (0, 0) if r.status is None else (1, r.status)
        if col == "mime":
            return lambda r: r.mime
        if col == "length":
            return lambda r: r.content_length
        if col == "flags":
            return lambda r: self._SEVERITY_RANK.get(r.max_severity, 0)
        return lambda r: r.seq

    def _on_history_sort_click(self, col: str) -> None:
        if self._history_sort_col != col:
            self._history_sort_col, self._history_sort_dir = col, "asc"
        elif self._history_sort_dir == "asc":
            self._history_sort_dir = "desc"
        else:
            self._history_sort_col, self._history_sort_dir = None, "asc"
        self._update_history_sort_headers()
        app_logging.log_event(
            self.logger, "INFO", "history_sort_changed", "History 정렬 변경",
            column=self._history_sort_col, direction=self._history_sort_dir if self._history_sort_col else "original",
        )
        self._reapply_history_filter()

    def _update_history_sort_headers(self) -> None:
        for c in _HISTORY_TREE_COLUMNS:
            base_text = _HISTORY_TREE_HEADERS[c][0]
            if c == self._history_sort_col:
                arrow = " ▲" if self._history_sort_dir == "asc" else " ▼"
                self.tree_all.heading(c, text=base_text + arrow)
            else:
                self.tree_all.heading(c, text=base_text)

    def _sorted_visible_records(self) -> list[FlowRecord]:
        visible = [r for r in self.records.values() if self._history_record_visible(r)]
        if self._history_sort_col is None:
            return sorted(visible, key=lambda r: r.seq)
        key_fn = self._history_sort_key(self._history_sort_col)
        # Stable sort + seq as a tiebreaker (Python's sort is already stable,
        # but sorting by seq ASC first, then by the real key, guarantees the
        # tiebreak is always seq order regardless of self.records' own dict
        # iteration order).
        visible.sort(key=lambda r: r.seq)
        visible.sort(key=key_fn, reverse=(self._history_sort_dir == "desc"))
        return visible

    def _reapply_history_filter(self) -> None:
        self._quick_search_job = None
        self.history_filter.quick_search = self.quick_search_var.get().strip()
        self.history_filter.quick_search_current_target_only = self.quick_search_current_target_var.get()
        self.history_filter.current_target_host, self.history_filter.current_target_port = self._current_target_host_port()

        prev_selection = self.tree_all.selection()
        for item in self.tree_all.get_children():
            self.tree_all.delete(item)
        shown = 0
        for record in self._sorted_visible_records():
            self._insert_history_row(self.tree_all, record)
            shown += 1
        self._history_shown_count = shown
        self._update_history_filter_summary()
        # spec §9.2: 정렬 후에도 선택 상태와 상세 화면을 유지한다 -- 상세
        # 텍스트 자체는 self.selected_record를 그대로 참조하므로 손대지 않고,
        # Treeview 쪽 강조 표시만 다시 걸어준다.
        if prev_selection and self.tree_all.exists(prev_selection[0]):
            self.tree_all.selection_set(prev_selection[0])
        app_logging.log_event(
            self.logger, "INFO", "history_filter_applied", "History 필터 적용",
            active=not self.history_filter.is_default(), shown=shown, total=len(self.records),
        )

    def _update_history_filter_summary(self) -> None:
        active = not self.history_filter.is_default()
        text = f"Filter: Showing {self._history_shown_count:,} of {len(self.records):,}"
        if active:
            text += "  (Filter is active)"
        self.history_filter_summary_var.set(text)

    def _reset_history_filter(self) -> None:
        self.history_filter = HistoryFilterState()
        self.quick_search_var.set("")
        self.quick_search_current_target_var.set(False)
        self._reapply_history_filter()

    def _open_history_filter_dialog(self) -> None:
        HistoryFilterDialog(self.root, self.history_filter, self._apply_history_filter_from_dialog)

    def _apply_history_filter_from_dialog(self, new_state: HistoryFilterState) -> None:
        # quick-search bar fields are owned by the always-visible bar, not
        # the dialog -- preserve whatever's currently typed there instead of
        # letting the dialog's (unrelated) defaults silently clear it.
        new_state.quick_search = self.history_filter.quick_search
        new_state.quick_search_current_target_only = self.history_filter.quick_search_current_target_only
        self.history_filter = new_state
        self._reapply_history_filter()

    def _insert_history_row(self, tree: ttk.Treeview, record: FlowRecord) -> None:
        flags = ", ".join(f"[{f.severity}] {f.category}" for f in record.findings)
        values = (
            record.seq, record.time_str, record.method, record.host_display, record.path,
            record.status_display, record.mime, record.content_length, flags,
        )
        sev = record.max_severity
        tag = (SEVERITY_TAG[sev],) if sev else ()
        tree.insert("", tk.END, iid=str(record.seq), values=values, tags=tag)

    def _make_tree(self, parent: ttk.Frame, sortable: bool = False) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=_HISTORY_TREE_COLUMNS, show="headings", selectmode="browse")
        for c in _HISTORY_TREE_COLUMNS:
            text, width = _HISTORY_TREE_HEADERS[c]
            if sortable:
                tree.heading(c, text=text, command=lambda col=c: self._on_history_sort_click(col))
            else:
                tree.heading(c, text=text)
            tree.column(c, width=width, anchor=tk.W)
        for sev, color in SEVERITY_COLOR.items():
            tree.tag_configure(SEVERITY_TAG[sev], background=color)
        vsb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        tree.bind("<<TreeviewSelect>>", self.on_select)
        return tree

    # -- proxy control -------------------------------------------------------
    def on_start(self) -> None:
        self._start_engine(apply_system_proxy=True, on_success=None, failed_status="● 정지됨 (시작 실패)")

    def _start_engine(self, *, apply_system_proxy: bool, on_success, failed_status: str) -> bool:
        """Shared by the manual '시작' button and the Chromium auto-start
        flow. Returns False immediately on an input error; the actual
        success/failure only becomes known ~700ms later via
        _check_start_health (mitmproxy's own bind happens on a delay -- see
        that method's docstring)."""
        try:
            port = int(self.port_var.get())
        except ValueError:
            messagebox.showerror("오류", "포트는 숫자여야 함")
            return False
        host = self.host_var.get().strip() or "127.0.0.1"
        self.engine.start(host, port, DEFAULT_CONFDIR)
        if self.engine.error:
            messagebox.showerror("프록시 시작 실패", str(self.engine.error))
            return False
        self.status_var.set(f"● 시작 중 -- {host}:{port}")
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.root.after(700, self._check_start_health, host, port, apply_system_proxy, on_success, failed_status)
        return True

    def _check_start_health(
        self, host: str, port: int, apply_system_proxy: bool, on_success, failed_status: str
    ) -> None:
        # The readiness signal fires as soon as the engine object exists, not
        # once the port is actually bound (that happens a beat later inside
        # mitmproxy's own startup) -- e.g. if Burp or another proxy is
        # already listening on the same port, the bind failure only shows up
        # a few hundred ms after start() already returned "successfully".
        # This delayed recheck is what actually catches that.
        if self.engine.error:
            messagebox.showerror(
                "프록시 시작 실패",
                f"{host}:{port} 에서 시작하지 못함 (다른 프록시가 이미 그 포트를 쓰고 있을 수 있음 -- "
                f"Burp 등이 켜져 있다면 포트를 바꾸거나 그쪽을 먼저 끄세요):\n\n{self.engine.error}",
            )
            self._reset_to_stopped(failed_status)
            return
        if not self.engine.running:
            messagebox.showerror("프록시 시작 실패", "원인 불명으로 프록시가 시작 직후 종료됨.")
            self._reset_to_stopped(failed_status)
            return
        self.status_var.set(f"● 실행 중 -- {host}:{port}")
        # Per the Chromium 자동 History 명세: the Chromium-open flow never
        # touches the Windows system proxy -- only the manual '시작' button
        # (with the checkbox explicitly opted in) does.
        if apply_system_proxy and system_proxy.IS_WINDOWS and self.sys_proxy_var.get():
            try:
                system_proxy.set_system_proxy(host, port)
                self._we_set_system_proxy = True
            except Exception as exc:  # noqa: BLE001
                messagebox.showwarning("시스템 프록시 자동 설정 실패", str(exc))
        if on_success is not None:
            on_success()

    def on_stop(self) -> None:
        self.status_var.set("● 정지 중...")
        self.stop_btn.configure(state=tk.DISABLED)
        threading.Thread(target=self._stop_worker, daemon=True).start()

    def _stop_worker(self) -> None:
        # engine.stop() blocks (joins the proxy thread) -- run off the GUI
        # thread so the window stays responsive instead of appearing frozen.
        self.engine.stop()
        self.root.after(0, self._on_stopped)

    def _on_stopped(self) -> None:
        if self._we_set_system_proxy:
            try:
                system_proxy.clear_system_proxy()
            except Exception:  # noqa: BLE001
                app_logging.log_exception(self.logger, "tool_failed", "시스템 프록시 해제 실패", sys.exc_info())
            self._we_set_system_proxy = False
        self._reset_to_stopped("● 정지됨")

    def _reset_to_stopped(self, status: str) -> None:
        self.status_var.set(status)
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)

    def on_open_chromium(self) -> None:
        """Primary entry point (spec: Chromium 자동 HTTP History): auto-starts
        the proxy with current settings if it isn't already running, then
        opens/refocuses this program's one dedicated Chromium session --
        no separate '시작' click required."""
        if self.engine.running:
            self._launch_chromium_now()
            return
        self.status_var.set("● Chromium 시작 준비 중")
        started = self._start_engine(
            apply_system_proxy=False, on_success=self._launch_chromium_now, failed_status="● 정지됨 (시작 실패)"
        )
        if not started:
            self._reset_to_stopped("● 정지됨")

    def _launch_chromium_now(self) -> None:
        host = self.host_var.get().strip() or "127.0.0.1"
        try:
            port = int(self.port_var.get())
        except ValueError:
            messagebox.showerror("오류", "포트는 숫자여야 함")
            return
        first_launch_this_session = self._chromium_proc is None or self._chromium_proc.poll() is not None
        try:
            proc = launch_browser.launch_proxied_browser(host, port)
        except RuntimeError as exc:
            messagebox.showerror("Chromium 열기 실패", str(exc))
            return
        if first_launch_this_session:
            self._chromium_proc = proc  # only the first launch is reliably trackable -- see _poll()'s note
            messagebox.showinfo(
                "Chromium 열림",
                "이 프로그램 전용 Chromium 창이 열림 (일반 Chrome 프로필과 별개, 로그인/방문 기록 무관).\n"
                "HTTPS 사이트에서 인증서 경고가 뜨면 CA가 아직 설치되지 않은 것 -- "
                "Proxy 카테고리의 '독립 프록시 설정' 탭에 있는 'CA 인증서 폴더 열기'로 설치 절차를 확인하세요.\n\n"
                "이후 '히스토리 지우기' 전까지는 모든 요청/응답이 Proxy · HTTP History에 자동으로 쌓이고 "
                "디스크에도 저장됩니다.",
            )
        self.status_var.set(f"● 자동 기록 중 -- {host}:{self.port_var.get()}")

    def on_open_cert_dir(self) -> None:
        os.makedirs(DEFAULT_CONFDIR, exist_ok=True)
        if sys.platform.startswith("win"):
            os.startfile(DEFAULT_CONFDIR)  # noqa: S606
        else:
            subprocess.Popen(["xdg-open", DEFAULT_CONFDIR])
        messagebox.showinfo(
            "CA 인증서 설치",
            "mitmproxy-ca-cert.pem (또는 .p12/.cer) 파일을 브라우저/OS 인증서 저장소에 "
            "'신뢰할 수 있는 루트 인증기관'으로 설치해야 HTTPS 트래픽을 볼 수 있음.\n"
            "프록시를 한 번 시작해야 파일이 생성됨.",
        )

    def on_import_ca(self) -> None:
        default_path = import_ca.DEFAULT_P12
        if default_path.parent.exists():
            initial_dir = str(default_path.parent)
        elif (Path.home() / "Documents").exists():
            initial_dir = str(Path.home() / "Documents")
        else:
            initial_dir = str(Path.home())
        path = filedialog.askopenfilename(
            title="CA 파일 선택 (PKCS#12, 개인키 포함 -- 예: Burp의 'Certificate and private key in PKCS#12' 내보내기)",
            initialdir=initial_dir,
            initialfile=default_path.name if default_path.exists() else "",
            filetypes=[("PKCS#12", "*.p12 *.pfx"), ("모든 파일", "*.*")],
        )
        if not path:
            return
        password = simpledialog.askstring("CA 가져오기", "PKCS#12 비밀번호 (없으면 비워두고 확인):", show="*", parent=self.root)
        if password is None:
            return
        try:
            info = import_ca.import_pkcs12(Path(path), password, Path(DEFAULT_CONFDIR))
        except ValueError as exc:
            messagebox.showerror("CA 가져오기 실패", str(exc))
            return
        restart_note = (
            "\n\n프록시가 이미 실행 중입니다 -- '중지' 후 다시 '시작'해야 이 CA로 서명합니다."
            if self.engine.running else ""
        )
        messagebox.showinfo(
            "CA 가져오기 완료",
            f"주체: {info.subject}\n발급자: {info.issuer}\n만료일: {info.not_valid_after_display}\n"
            f"지문(SHA-256): {info.fingerprint_sha256}\n\n저장 위치: {Path(DEFAULT_CONFDIR) / 'mitmproxy-ca.pem'}"
            f"{restart_note}",
        )

    def on_clear(self) -> None:
        total = self._total_count
        if total == 0 and not self.records:
            return
        ok = messagebox.askyesno(
            "히스토리 지우기",
            f"저장된 요청 {total}개와 본문 데이터가 삭제됩니다.\n삭제 후에는 복구할 수 없습니다.\n\n계속할까요?",
        )
        if not ok:
            return
        for tree in (self.tree_all, self.tree_sus):
            for item in tree.get_children():
                tree.delete(item)
        self.records.clear()
        if self.history_store is not None:
            try:
                self.history_store.clear()
            except Exception:  # noqa: BLE001
                app_logging.log_exception(self.logger, "tool_failed", "History 저장소 지우기 실패", sys.exc_info())
        self._session_count = 0
        self._total_count = 0
        self._max_seq_seen = 0
        self._history_shown_count = 0
        self._update_capture_count()
        self._update_history_filter_summary()
        self.selected_record = None
        self.summary_var.set("(히스토리에서 요청을 선택하면 여기에 표시됨)")
        self._set_text(self.findings_text, "")
        self._set_text(self.request_text, "")
        self._set_text(self.response_text, "")
        self.request_search.refresh_for_new_content()
        self.response_search.refresh_for_new_content()

    # -- persistent storage: startup restore ----------------------------------
    def _restore_history(self) -> None:
        if self.history_store is None:
            return
        if self.history_store.corrupted_backup is not None:
            messagebox.showwarning(
                "History 저장소 손상",
                f"기존 저장 파일이 손상되어 새로 만들었습니다.\n"
                f"손상된 파일은 삭제하지 않고 보존해둠: {self.history_store.corrupted_backup}",
            )
        try:
            records = self.history_store.load_recent()
        except Exception:  # noqa: BLE001
            error_id = app_logging.log_exception(
                self.logger, "tool_failed", "History 복원 실패", sys.exc_info(), path=str(self.history_store.path)
            )
            messagebox.showwarning("History 복원 실패", f"저장된 History를 불러오지 못했습니다.\n오류 ID: {error_id}")
            records = []
        self._max_seq_seen = max((r.seq for r in records), default=0)
        self._total_count = len(records)
        self._update_capture_count()
        self._restore_queue = records
        if records:
            self.root.after(1, self._restore_batch)

    def _restore_batch(self) -> None:
        # Added in chunks (not all 10,000 at once) so a large restored
        # History doesn't freeze the UI while it's being built.
        chunk, self._restore_queue = self._restore_queue[:200], self._restore_queue[200:]
        for record in chunk:
            self._add_record(record, persist=False)
        if self._restore_queue:
            self.root.after(1, self._restore_batch)

    def _update_capture_count(self) -> None:
        self.capture_count_var.set(f"현재 세션 {self._session_count}개 | 전체 저장 {self._total_count}개")

    # -- flow ingestion -------------------------------------------------------
    def _poll(self) -> None:
        for record in self.engine.drain():
            self._add_record(record, persist=True)
        for record in _drain_queue(self.burp_bridge.out_queue):
            self._add_record(record, persist=True)
        if hasattr(self, "burp_status_var"):
            self.burp_status_var.set(self.burp_bridge.status_text())
            self.burp_count_var.set(f"수신 {self.burp_bridge.received_count}개")
        # Best-effort "Chromium 종료됨" detection -- only the first Chromium
        # launch in a session is reliably trackable (a second launch against
        # an already-running profile just opens a new window in that
        # existing process and its own Popen handle exits almost
        # immediately, which is normal Chrome behavior, not a real exit).
        if (
            self._chromium_proc is not None
            and self._chromium_proc.poll() is not None
            and self.engine.running
            and self.status_var.get().startswith("● 자동 기록 중")
        ):
            self.status_var.set("● Chromium 종료됨")
        self.root.after(300, self._poll)

    def _evict_records(self, seqs: list[int]) -> None:
        """Mirrors HistoryStore's own retention eviction into the on-screen
        Treeview/self.records -- without this, a row the DB already deleted
        stays visible (and selectable) until the next restart, at which
        point _restore_history quietly no longer includes it (design review
        finding, spec 4.3: '실행 전후 목록이 달라진다')."""
        for seq in seqs:
            self.records.pop(seq, None)
            iid = str(seq)
            if self.tree_all.exists(iid):
                self.tree_all.delete(iid)
                self._history_shown_count = max(0, self._history_shown_count - 1)
            if self.tree_sus.exists(iid):
                self.tree_sus.delete(iid)
        self._total_count = max(0, self._total_count - len(seqs))
        self._update_history_filter_summary()

    def _add_record(self, record: FlowRecord, persist: bool) -> None:
        if persist:
            if self.history_store is not None:
                try:
                    record.seq, evicted = self.history_store.add(record)
                except Exception:  # noqa: BLE001
                    error_id = app_logging.log_exception(
                        self.logger, "tool_failed", "History 저장 실패", sys.exc_info(), path=str(self.history_store.path)
                    )
                    self._max_seq_seen += 1
                    record.seq = self._max_seq_seen
                    self.status_var.set(f"● 저장 오류 (오류 ID: {error_id})")
                else:
                    self._total_count += 1
                    if evicted:
                        self._evict_records(evicted)
            else:
                self._max_seq_seen += 1
                record.seq = self._max_seq_seen
            self._max_seq_seen = max(self._max_seq_seen, record.seq)
            self._session_count += 1
            self._update_capture_count()

        self.records[record.seq] = record
        # Filtering only ever hides rows from the tree -- collection/storage
        # above happens unconditionally either way (spec §8.3: "필터가
        # 요청을 숨겼다고 History 수집이나 저장을 중단해서는 안 된다").
        if self._history_sort_col is not None:
            # A non-default sort is active -- a plain end-of-tree append
            # would land the new row in capture order, not sort order, so a
            # full re-render is the only correct option here (spec §9.2's
            # "새 요청이 들어오면 ... 일정 주기로 묶어서 재정렬" fallback).
            self._reapply_history_filter()
        else:
            if self._history_record_visible(record):
                self._insert_history_row(self.tree_all, record)
                self._history_shown_count += 1
            self._update_history_filter_summary()
        if record.findings:
            flags = ", ".join(f"[{f.severity}] {f.category}" for f in record.findings)
            values = (
                record.seq, record.time_str, record.method, record.host_display, record.path,
                record.status_display, record.mime, record.content_length, flags,
            )
            sev = record.max_severity
            tag = (SEVERITY_TAG[sev],) if sev else ()
            self.tree_sus.insert("", tk.END, iid=str(record.seq), values=values, tags=tag)

    # -- detail view -------------------------------------------------------
    def on_select(self, event: tk.Event) -> None:
        tree: ttk.Treeview = event.widget
        sel = tree.selection()
        if not sel:
            return
        record = self.records.get(int(sel[0]))
        if not record:
            return
        self.selected_record = record
        self.summary_var.set(f"{record.method} {record.url}  ->  {record.status_display}")

        finding_lines = [
            f"[{f.severity}] {f.category}: {f.detail}  (evidence: {f.evidence!r})" for f in record.findings
        ]
        if record.error:
            finding_lines.insert(0, f"[응답 없음] {record.error}")
        if not finding_lines:
            finding_lines = ["(의심 항목 없음)"]
        self._set_text(self.findings_text, "\n".join(finding_lines))

        req = record.req_headers + (f"\n\n{record.req_body}" if record.req_body else "")
        if record.error:
            resp = f"(응답 없음 -- {record.error})"
        else:
            resp = record.resp_headers + (f"\n\n{record.resp_body}" if record.resp_body else "")
        self._set_text(self.request_text, req)
        self._set_text(self.response_text, resp)
        # spec §7.1: History 행을 바꾸면 같은 검색어를 새 내용에서 다시 계산.
        self.request_search.refresh_for_new_content()
        self.response_search.refresh_for_new_content()

    # -- send-to-tool -------------------------------------------------------
    def on_send_to_tool(self) -> None:
        if self.selected_record is None:
            messagebox.showinfo("보내기", "먼저 히스토리에서 요청을 선택하세요.")
            return
        label = self.send_target_var.get()
        spec = next((s for s in TOOLS if s.label == label), None)
        if spec is None:
            return
        parsed = urlparse(self.selected_record.url)
        value = self.selected_record.url
        tab = self.tool_tabs[spec.key]
        if spec.target_kind in ("host", "host_port"):
            value = parsed.hostname or self.selected_record.host
        tab.set_target(value)
        if spec.target_kind == "host_port" and parsed.port:
            tab.set_port(parsed.port)
        # Jump to the right category tab first, then the tool's own sub-tab
        # within it (spec 8.2: "History에서 도구로 보내기를 실행하면 올바른
        # 두 탭이 선택되는지 확인한다").
        self.category_notebook.select(self.category_frames[spec.category])
        self.category_subnotebooks[spec.category].select(tab)

    @staticmethod
    def _set_text(widget: tk.Text, text: str) -> None:
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, text)
        widget.configure(state=tk.DISABLED)

    def _bind_smart_dblclick(self, widget: tk.Text) -> None:
        def handler(event: tk.Event) -> str:
            index = widget.index(f"@{event.x},{event.y}")
            line, col = (int(p) for p in index.split("."))
            line_text = widget.get(f"{line}.0", f"{line}.end")
            start_col, end_col = word_bounds(line_text, col)
            if start_col is None:
                return "break"
            widget.tag_remove("sel", "1.0", tk.END)
            widget.tag_add("sel", f"{line}.{start_col}", f"{line}.{end_col}")
            widget.mark_set("insert", f"{line}.{end_col}")
            return "break"

        widget.bind("<Double-Button-1>", handler)

    def on_close(self) -> None:
        app_logging.log_event(self.logger, "INFO", "app_closed", "Proxy Scanner 종료")
        self._save_settings()
        if self._we_set_system_proxy:
            try:
                system_proxy.clear_system_proxy()
            except Exception:  # noqa: BLE001
                app_logging.log_exception(self.logger, "tool_failed", "시스템 프록시 해제 실패", sys.exc_info())
        if self.engine.running:
            self.engine.stop()
        if self.burp_bridge.running:
            try:
                self.burp_bridge.stop()
            except Exception:  # noqa: BLE001
                app_logging.log_exception(self.logger, "tool_failed", "Burp 브리지 종료 실패", sys.exc_info())
        if self.history_store is not None:
            try:
                self.history_store.close()
            except Exception:  # noqa: BLE001
                app_logging.log_exception(self.logger, "tool_failed", "History DB 닫기 실패", sys.exc_info())
        try:
            launch_browser.cleanup_stale_profiles()
        except Exception:  # noqa: BLE001
            app_logging.log_exception(self.logger, "tool_failed", "임시 브라우저 프로필 정리 실패", sys.exc_info())
        try:
            app_paths.clear_temp_dir()
        except Exception:  # noqa: BLE001
            app_logging.log_exception(self.logger, "tool_failed", "임시 폴더 정리 실패", sys.exc_info())
        app_logging.shutdown_logging()
        self.root.destroy()


def _configure_style(root: tk.Tk) -> None:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")  # 'vista'/'xpnative' ignore most custom colors on Windows
    except tk.TclError:
        pass
    style.configure("TNotebook.Tab", padding=(10, 5))
    style.configure(
        "Accent.TButton", background="#2f6fed", foreground="white", padding=(10, 5), font=("", 9, "bold")
    )
    style.map("Accent.TButton", background=[("active", "#2557c2"), ("disabled", "#9db6e8")])
    style.configure("Treeview", rowheight=22)
    style.configure("Treeview.Heading", font=("", 9, "bold"))


def main(session_id: str | None = None) -> int:
    root = tk.Tk()
    _configure_style(root)
    app = ProxyScannerApp(root, session_id=session_id)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
