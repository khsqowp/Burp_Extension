from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk
from urllib.parse import urljoin

import app_logging
import log_redaction
from tool_registry import ToolSpec
from tool_tab import ToolTab, _self_invoke_prefix, trim_console

_logger = app_logging.get_logger("tool_tab")

# default_content_scanner.py bundles 3 distinct probing modes behind one CLI
# (fingerprint sweep / backup-suffix mutation / path-traversal fuzzing).
# Per the 후속_기능개선_통합_명세서 §7, these become 3 fully independent
# execution units in the GUI -- each with its own run/stop/clear-output
# button and its own result console that never mixes with the others
# (previously there was exactly one shared 실행 button for all three modes
# combined, which is also why it could scroll off-screen with no way to
# tell which mode was actually about to run).
_FINGERPRINT_DESTS = ["tech", "no_generic"]
_TRAVERSAL_DESTS = ["param", "url_template", "target_os", "traversal_limit"]
_COMMON_DESTS = [
    "workers", "min_interval", "timeout", "retries", "max_requests", "ignore_robots", "user_agent", "force", "verbose",
]


@dataclass
class _ModeRunner:
    """One independently runnable subprocess unit -- DefaultContentScannerTab
    has 3 of these (기본 파일 탐지/백업 파일 탐지/경로탐색) instead of the
    single self.proc a plain ToolTab has."""
    key: str
    label: str
    output: scrolledtext.ScrolledText
    run_btn: ttk.Button
    stop_btn: ttk.Button
    run_summary_var: tk.StringVar
    tab_frame: ttk.Frame
    proc: subprocess.Popen | None = None
    run_start: datetime | None = None
    user_stopped: bool = False
    run_id: str | None = None
    active: bool = False  # True from _mode_start until _mode_finished -- true even in the brief
    # window before runner.proc itself is actually set by the background thread

    def append(self, text: str) -> None:
        self.output.configure(state=tk.NORMAL)
        self.output.insert(tk.END, text)
        trim_console(self.output)
        self.output.see(tk.END)
        self.output.configure(state=tk.DISABLED)

    def clear(self) -> None:
        self.output.configure(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.output.configure(state=tk.DISABLED)


class DefaultContentScannerTab(ToolTab):
    def __init__(self, parent: tk.Widget, spec: ToolSpec) -> None:
        self._last_fingerprint_hits: list[str] | None = None
        self._last_fingerprint_at: str | None = None
        self._estimate_jobs: dict[str, str | None] = {}
        self._runners: dict[str, _ModeRunner] = {}
        super().__init__(parent, spec)

    # -- layout ---------------------------------------------------------------
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
        self.by_dest = {a["dest"]: a for a in self.actions}

        # -- shared target URL field (all 3 modes read the same value) --------
        common = ttk.Frame(self, padding=(12, 8))
        common.pack(side=tk.TOP, fill=tk.X)
        common.columnconfigure(3, weight=1)
        row = 0
        for a in self.actions:
            if not a["option_strings"]:
                row = self._build_field(common, row, a)  # url (positional)

        self.sub = ttk.Notebook(self)
        self.sub.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=12, pady=(0, 10))

        self._build_fingerprint_mode()
        self._build_backup_mode()
        self._build_traversal_mode()

    def _mode_scaffold(self, title: str, desc: str) -> tuple[ttk.Frame, ttk.Frame, ttk.Frame]:
        """Common per-mode chrome: description + scrollable options area +
        bottom bar (btn_frame/run_summary/output always visible). Returns
        (tab_frame, options_body, bottom)."""
        frame = ttk.Frame(self.sub)
        self.sub.add(frame, text=title)
        ttk.Label(frame, text=desc, foreground="#555", wraplength=1000, justify=tk.LEFT, padding=(10, 8, 10, 4)).pack(
            side=tk.TOP, fill=tk.X
        )
        options_body, bottom = self._build_options_and_bottom(frame, min_options=70, max_ratio=0.5)
        return frame, options_body, bottom

    def _build_mode_bottom(
        self, runner_key: str, label: str, tab_frame: ttk.Frame, bottom: ttk.Frame, on_run
    ) -> _ModeRunner:
        btn_frame = ttk.Frame(bottom, padding=(10, 4))
        btn_frame.pack(side=tk.TOP, fill=tk.X)
        run_btn = ttk.Button(btn_frame, text=f"▶ {label} 실행", style="Accent.TButton", command=on_run)
        run_btn.pack(side=tk.LEFT)
        stop_btn = ttk.Button(btn_frame, text="■ 중지", state=tk.DISABLED)
        stop_btn.pack(side=tk.LEFT, padx=4)
        clear_btn = ttk.Button(btn_frame, text="결과 지우기")
        clear_btn.pack(side=tk.LEFT, padx=4)

        run_summary_var = tk.StringVar(value="")
        ttk.Label(bottom, textvariable=run_summary_var, foreground="#555", padding=(10, 0, 10, 2), justify=tk.LEFT, wraplength=1000).pack(
            side=tk.TOP, fill=tk.X
        )
        output = scrolledtext.ScrolledText(bottom, wrap=tk.WORD, font=("Consolas", 9), borderwidth=1, relief=tk.SOLID, height=10)
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=(2, 8))
        output.configure(state=tk.DISABLED)

        runner = _ModeRunner(
            key=runner_key, label=label, output=output, run_btn=run_btn, stop_btn=stop_btn,
            run_summary_var=run_summary_var, tab_frame=tab_frame,
        )
        stop_btn.configure(command=lambda: self._mode_stop(runner))
        clear_btn.configure(command=runner.clear)
        self._runners[runner_key] = runner
        return runner

    # -- 기본 파일 탐지 (Fingerprint) ------------------------------------------
    def _build_fingerprint_mode(self) -> None:
        tab_frame, body, bottom = self._mode_scaffold(
            "기본 파일 탐지",
            "설치 시 남는 기본/샘플/테스트/설정 파일 후보를 검사 (SecLists 서버별 목록 + 내장 공통 민감파일 목록). "
            "이 버튼만 누르면 바로 실행되며, 백업 변형이나 경로탐색은 함께 실행되지 않습니다.",
        )
        self.fp_widgets: dict[str, tuple[str, tk.Variable]] = {"url": self.widgets["url"]}
        form = ttk.Frame(body, padding=(0, 4))
        form.pack(side=tk.TOP, fill=tk.X)
        form.columnconfigure(3, weight=1)
        row = 0
        for dest in _FINGERPRINT_DESTS + _COMMON_DESTS:
            if dest in self.by_dest:
                row = self._build_field(form, row, self.by_dest[dest], widget_store=self.fp_widgets)

        estimate_var = tk.StringVar(value="예상 요청 수: 대상 URL을 입력하면 계산됩니다.")
        ttk.Label(body, textvariable=estimate_var, foreground="#2f6fed", font=("", 9, "bold"), padding=(0, 4, 0, 0)).pack(
            side=tk.TOP, anchor=tk.W
        )
        self.fp_last_var = tk.StringVar(value="직전 기본 탐지 결과: 없음 (백업 파일 탐지 탭에서 '직전 결과 사용' 기준으로 쓰임)")
        ttk.Label(body, textvariable=self.fp_last_var, foreground="#666", padding=(0, 2, 0, 0)).pack(side=tk.TOP, anchor=tk.W)

        self._wire_mode_estimate(
            "fingerprint", self.fp_widgets, ["url"] + _FINGERPRINT_DESTS + ["max_requests"], estimate_var, lambda: [],
        )

        def on_run() -> None:
            self._mode_start(self._runners["fingerprint"], lambda: self._fingerprint_argv_and_track())

        self._build_mode_bottom("fingerprint", "기본 파일 탐지", tab_frame, bottom, on_run)
        self._finalize_scroll_areas()

    # -- 백업 파일 탐지 (Mutate) ------------------------------------------------
    def _build_backup_mode(self) -> None:
        tab_frame, body, bottom = self._mode_scaffold(
            "백업 파일 탐지",
            "기준 경로마다 .bak/~/.old 등 백업 확장자 변형을 확인합니다. 기준 경로가 필요합니다 -- "
            "직전 기본 파일 탐지 결과, 현재 입력 URL 경로, 또는 직접 입력한 목록 중 하나를 고르세요.",
        )
        self.backup_widgets: dict[str, tuple[str, tk.Variable]] = {"url": self.widgets["url"]}

        src_frame = ttk.Frame(body, padding=(0, 4))
        src_frame.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(src_frame, text="기준 경로", font=("", 9, "bold")).grid(row=0, column=0, sticky=tk.W, columnspan=3, pady=(0, 4))
        self.backup_source_var = tk.StringVar(value="last")
        ttk.Radiobutton(src_frame, text="직전 기본 파일 탐지 결과 사용", variable=self.backup_source_var, value="last").grid(
            row=1, column=0, sticky=tk.W
        )
        ttk.Radiobutton(src_frame, text="현재 입력 URL 경로 사용", variable=self.backup_source_var, value="url").grid(
            row=2, column=0, sticky=tk.W
        )
        ttk.Radiobutton(src_frame, text="직접 입력", variable=self.backup_source_var, value="manual").grid(
            row=3, column=0, sticky=tk.NW
        )
        self.backup_manual_text = tk.Text(src_frame, height=3, width=60, font=("Consolas", 9))
        self.backup_manual_text.grid(row=3, column=1, sticky=tk.W, padx=(8, 0))
        ttk.Label(
            src_frame, text="한 줄에 하나씩 또는 쉼표로 구분 (전체 URL 또는 /path 형태 -- /path는 현재 대상 origin 기준으로 해석됨)",
            foreground="#666",
        ).grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=(2, 8))

        self.backup_last_hint_var = tk.StringVar(value="직전 기본 탐지 결과: 없음")
        ttk.Label(src_frame, textvariable=self.backup_last_hint_var, foreground="#666").grid(
            row=1, column=1, sticky=tk.W, padx=(8, 0)
        )

        ttk.Separator(body, orient=tk.HORIZONTAL).pack(side=tk.TOP, fill=tk.X, pady=6)
        form = ttk.Frame(body, padding=(0, 4))
        form.pack(side=tk.TOP, fill=tk.X)
        form.columnconfigure(3, weight=1)
        row = 0
        for dest in _COMMON_DESTS:
            if dest in self.by_dest:
                row = self._build_field(form, row, self.by_dest[dest], widget_store=self.backup_widgets)

        estimate_var = tk.StringVar(value="예상 요청 수: 기준 경로를 선택하면 계산됩니다.")
        ttk.Label(body, textvariable=estimate_var, foreground="#2f6fed", font=("", 9, "bold"), padding=(0, 4, 0, 0)).pack(
            side=tk.TOP, anchor=tk.W
        )

        def estimate_extra_argv() -> list[str] | None:
            urls = self._resolve_backup_base_urls(silent=True)
            if not urls:
                return None
            return ["--mutate-paths", ",".join(urls)]

        self._wire_mode_estimate(
            "backup", self.backup_widgets, ["url", "max_requests"], estimate_var, estimate_extra_argv,
            extra_watch_vars=[self.backup_source_var],
        )
        self.backup_manual_text.bind("<KeyRelease>", lambda _e: self._estimate_jobs_trigger("backup"))

        def on_run() -> None:
            self._mode_start(self._runners["backup"], self._backup_argv)

        combo_frame = ttk.Frame(bottom, padding=(10, 4, 10, 0))
        combo_frame.pack(side=tk.TOP, fill=tk.X)
        ttk.Button(combo_frame, text="▶▶ 기본 탐지 후 백업 탐지 (연속 실행)", command=self._run_fingerprint_then_backup).pack(
            side=tk.LEFT
        )
        ttk.Label(combo_frame, text="-- 기본 파일 탐지를 먼저 실행하고, 그 결과를 기준 경로로 이어서 백업 탐지를 실행합니다.", foreground="#666").pack(
            side=tk.LEFT, padx=(8, 0)
        )

        self._build_mode_bottom("backup", "백업 파일 탐지", tab_frame, bottom, on_run)
        self._finalize_scroll_areas()

    def _resolve_backup_base_urls(self, *, silent: bool) -> list[str] | None:
        source = self.backup_source_var.get()
        target_url = self._field_value("url", self.backup_widgets)
        if source == "last":
            if not self._last_fingerprint_hits:
                if not silent:
                    self._runners["backup"].append(
                        "실행할 수 없습니다.\n원인: 직전 기본 파일 탐지 결과가 없습니다.\n"
                        "조치: 먼저 '기본 파일 탐지' 탭에서 실행하거나, 기준 경로를 '현재 입력 URL 경로' 또는 "
                        "'직접 입력'으로 바꾸세요.\n\n"
                    )
                return None
            return list(self._last_fingerprint_hits)
        if source == "url":
            if not target_url:
                if not silent:
                    self._runners["backup"].append("실행할 수 없습니다.\n원인: 대상 URL이 비어 있습니다.\n조치: 상단에 대상 URL을 입력하세요.\n\n")
                return None
            return [target_url]
        # manual
        raw = self.backup_manual_text.get("1.0", tk.END)
        parts = [p.strip() for chunk in raw.splitlines() for p in chunk.split(",")]
        entries = [p for p in parts if p]
        if not entries:
            if not silent:
                self._runners["backup"].append("실행할 수 없습니다.\n원인: 직접 입력한 기준 경로가 없습니다.\n조치: 경로를 한 줄에 하나씩 입력하세요.\n\n")
            return None
        base = target_url or ""
        resolved = [e if e.startswith(("http://", "https://")) else urljoin(base, e) for e in entries]
        return resolved

    def _backup_argv(self) -> list[str] | None:
        urls = self._resolve_backup_base_urls(silent=False)
        if not urls:
            return None
        return self._build_argv(widgets=self.backup_widgets) + ["--mutate-paths", ",".join(urls)]

    def _run_fingerprint_then_backup(self) -> None:
        backup_runner = self._runners["backup"]
        fp_runner = self._runners["fingerprint"]
        if backup_runner.active:
            return
        if fp_runner.active:
            backup_runner.append("실행할 수 없습니다.\n원인: 기본 파일 탐지가 이미 다른 실행으로 사용 중입니다.\n조치: 해당 실행이 끝난 뒤 다시 시도하세요.\n\n")
            return
        missing = self._missing_required(self.fp_widgets)
        if missing:
            backup_runner.append(
                f"실행할 수 없습니다.\n원인: 필수 값이 비어 있습니다: {', '.join(missing)}\n조치: 대상 URL을 입력한 뒤 다시 실행하세요.\n\n"
            )
            return
        # Plain argv (no --output-file here) -- _combo_worker manages its
        # own dedicated temp file for this run, separate from a standalone
        # fingerprint-tab run's own (see _fingerprint_argv_and_track).
        argv = self._build_argv(widgets=self.fp_widgets)
        if not self._confirm_concurrent_load(backup_runner):
            return
        backup_runner.run_btn.configure(state=tk.DISABLED)
        backup_runner.stop_btn.configure(state=tk.NORMAL)
        backup_runner.user_stopped = False
        backup_runner.active = True
        backup_runner.run_start = datetime.now()
        backup_runner.run_id = app_logging.new_run_id()
        app_logging.log_event(
            _logger, "INFO", "tool_started", "default_content_scanner(fingerprint+backup combo) 실행 시작",
            run_id=backup_runner.run_id, tool=self.spec.key, mode="fingerprint+backup",
            argv=log_redaction.redact_argv(argv),
        )
        backup_runner.run_summary_var.set(f"시작: {backup_runner.run_start:%H:%M:%S}  |  실행 중 (1단계: 기본 파일 탐지)...")
        backup_runner.clear()
        self._set_sub_tab_state(backup_runner, "실행 중")
        self._update_category_indicator()
        threading.Thread(target=self._combo_worker, args=(backup_runner, argv), daemon=True).start()

    def _combo_worker(self, runner: _ModeRunner, fp_argv: list[str]) -> None:
        fd, tmp_path = tempfile.mkstemp(prefix="dc_fp_", suffix=".json")
        os.close(fd)
        full_fp_argv = fp_argv + ["--output", "console", "--output-file", tmp_path]
        self.after(0, runner.append, f"=== 1단계: 기본 파일 탐지 실행 ===\n$ python default_content_scanner.py {' '.join(full_fp_argv)}\n\n")
        code = self._stream_subprocess(runner, full_fp_argv)
        if runner.user_stopped or code != 0:
            Path(tmp_path).unlink(missing_ok=True)
            self.after(0, runner.append, "\n[백업 탐지 중단됨 -- 기본 파일 탐지가 정상적으로 끝나지 않음]\n")
            self.after(0, self._mode_finished, runner, code)
            return
        try:
            data = json.loads(Path(tmp_path).read_text(encoding="utf-8", errors="replace"))
            hits = [d["url"] for d in data if d.get("hit")]
        except Exception as exc:  # noqa: BLE001
            self.after(0, runner.append, f"\n[기본 탐지 결과 해석 실패: {exc}]\n")
            self.after(0, self._mode_finished, runner, 1)
            return
        finally:
            Path(tmp_path).unlink(missing_ok=True)
        self.after(0, self._record_fingerprint_hits, hits)
        if not hits:
            self.after(0, runner.append, "\n[백업 탐지 건너뜀 -- 기본 파일 탐지에서 발견된 경로가 없음]\n")
            self.after(0, self._mode_finished, runner, 0)
            return
        backup_argv = self._build_argv(widgets=self.backup_widgets) + ["--mutate-paths", ",".join(hits)]
        self.after(
            0, runner.append,
            f"\n=== 2단계: 백업 파일 탐지 실행 (발견된 {len(hits)}개 경로 기준) ===\n"
            f"$ python default_content_scanner.py {' '.join(backup_argv)}\n\n",
        )
        self.after(0, runner.run_summary_var.set, f"실행 중 (2단계: 백업 파일 탐지, 기준 경로 {len(hits)}개)...")
        backup_code = self._stream_subprocess(runner, backup_argv)
        self.after(0, self._mode_finished, runner, backup_code)

    # -- 경로탐색/LFI (Traversal) -----------------------------------------------
    def _build_traversal_mode(self) -> None:
        tab_frame, body, bottom = self._mode_scaffold(
            "경로탐색/LFI",
            "PayloadsAllTheThings의 Directory Traversal 페이로드로 지정한 파라미터 또는 URL의 FUZZ 위치를 퍼징합니다. "
            "기본 파일 탐지/백업 파일 탐지는 함께 실행되지 않습니다. 검사 파라미터 또는 FUZZ URL 템플릿 중 하나가 반드시 필요합니다.",
        )
        self.trav_widgets: dict[str, tuple[str, tk.Variable]] = {"url": self.widgets["url"]}
        form = ttk.Frame(body, padding=(0, 4))
        form.pack(side=tk.TOP, fill=tk.X)
        form.columnconfigure(3, weight=1)
        row = 0
        for dest in _TRAVERSAL_DESTS + _COMMON_DESTS:
            if dest in self.by_dest:
                row = self._build_field(form, row, self.by_dest[dest], widget_store=self.trav_widgets)

        estimate_var = tk.StringVar(value="예상 요청 수: 대상 URL을 입력하면 계산됩니다.")
        ttk.Label(body, textvariable=estimate_var, foreground="#2f6fed", font=("", 9, "bold"), padding=(0, 4, 0, 0)).pack(
            side=tk.TOP, anchor=tk.W
        )
        self._wire_mode_estimate(
            "traversal", self.trav_widgets, ["url"] + _TRAVERSAL_DESTS + ["max_requests"], estimate_var,
            lambda: ["--no-fingerprint", "--traversal"],
        )

        def on_run() -> None:
            self._mode_start(self._runners["traversal"], self._traversal_argv)

        self._build_mode_bottom("traversal", "경로탐색 실행", tab_frame, bottom, on_run)
        self._finalize_scroll_areas()

    def _traversal_argv(self) -> list[str] | None:
        runner = self._runners["traversal"]
        missing = self._missing_required(self.trav_widgets)
        if missing:
            runner.append(f"실행할 수 없습니다.\n원인: 필수 값이 비어 있습니다: {', '.join(missing)}\n조치: 대상 URL을 입력한 뒤 다시 실행하세요.\n\n")
            return None
        param = self._field_value("param", self.trav_widgets)
        url_template = self._field_value("url_template", self.trav_widgets)
        target_url = self._field_value("url", self.trav_widgets)
        if not param and not url_template:
            runner.append(
                "실행할 수 없습니다.\n원인: 검사 파라미터와 URL을 FUZZ 템플릿으로 취급 옵션이 모두 비어/꺼져 있습니다.\n"
                "조치: 둘 중 하나를 설정하세요 -- 쿼리 파라미터 이름을 입력하거나, URL에 FUZZ를 넣고 해당 옵션을 켜세요.\n\n"
            )
            return None
        if url_template and "FUZZ" not in target_url:
            runner.append(
                "실행할 수 없습니다.\n원인: 'URL을 FUZZ 템플릿으로 취급'이 켜져 있지만 URL에 FUZZ 문자열이 없습니다.\n"
                "조치: URL에 FUZZ를 포함시키거나 (예: https://example.com/dl?f=FUZZ), 대신 검사 파라미터를 입력하세요.\n\n"
            )
            return None
        return self._build_argv(widgets=self.trav_widgets) + ["--no-fingerprint"]

    # -- shared run/stop machinery for all 3 modes -----------------------------
    def _confirm_concurrent_load(self, runner: _ModeRunner) -> bool:
        others_running = [r for r in self._runners.values() if r.key != runner.key and r.active]
        if not others_running:
            return True
        names = ", ".join(r.label for r in others_running)
        return messagebox.askyesno(
            "동시 실행 확인",
            f"다른 모드가 이미 실행 중입니다 ({names}).\n같은 대상에 동시 실행하면 요청 부하가 커질 수 있습니다.\n\n계속할까요?",
        )

    def _mode_start(self, runner: _ModeRunner, argv_builder) -> None:
        if runner.active:
            return
        argv = argv_builder()
        if argv is None:
            return  # blocked -- argv_builder already appended the 원인/조치 message
        if not self._confirm_concurrent_load(runner):
            runner.append("[사용자가 실행을 취소함]\n")
            return
        runner.append(f"$ python default_content_scanner.py {' '.join(argv)}\n\n")
        runner.run_btn.configure(state=tk.DISABLED)
        runner.stop_btn.configure(state=tk.NORMAL)
        runner.user_stopped = False
        runner.active = True
        runner.run_start = datetime.now()
        runner.run_id = app_logging.new_run_id()
        app_logging.log_event(
            _logger, "INFO", "tool_started", f"default_content_scanner({runner.key}) 실행 시작",
            run_id=runner.run_id, tool=self.spec.key, mode=runner.key, argv=log_redaction.redact_argv(argv),
        )
        runner.run_summary_var.set(f"시작: {runner.run_start:%H:%M:%S}  |  실행 중...")
        self._set_sub_tab_state(runner, "실행 중")
        self._update_category_indicator()
        threading.Thread(target=self._mode_worker, args=(runner, argv), daemon=True).start()

    def _mode_worker(self, runner: _ModeRunner, argv: list[str]) -> None:
        code = self._stream_subprocess(runner, argv)
        if runner.key == "fingerprint":
            self._finish_fingerprint_run(runner, code)
        self.after(0, self._mode_finished, runner, code)

    def _finish_fingerprint_run(self, runner: _ModeRunner, code: int | None) -> None:
        """A plain (non-combo) fingerprint run also records its hits, so the
        백업 파일 탐지 tab's '직전 결과 사용' option stays current."""
        tmp_path = getattr(self, "_fp_tmp_path", None)
        self._fp_tmp_path = None
        if not tmp_path:
            return
        try:
            if code == 0 and not runner.user_stopped:
                data = json.loads(Path(tmp_path).read_text(encoding="utf-8", errors="replace"))
                hits = [d["url"] for d in data if d.get("hit")]
                self.after(0, self._record_fingerprint_hits, hits)
        except Exception:  # noqa: BLE001
            app_logging.log_exception(
                _logger, "tool_failed", "기본 파일 탐지 결과 해석 실패", sys.exc_info(),
                run_id=runner.run_id, tool=self.spec.key, mode=runner.key,
            )
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def _stream_subprocess(self, runner: _ModeRunner, argv: list[str]) -> int | None:
        code: int | None = None
        start = time.monotonic()
        worker_log_path = app_logging.new_worker_log_path(runner.run_id)
        try:
            with open(worker_log_path, "a", encoding="utf-8") as wf:
                wf.write(
                    f"# tool={self.spec.key} mode={runner.key} run_id={runner.run_id} "
                    f"argv={log_redaction.redact_argv(argv)}\n"
                )
                proc = subprocess.Popen(
                    [*_self_invoke_prefix(), "--run-tool", str(self.spec.script), *argv],
                    cwd=str(self.spec.script.parent), stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                    encoding="utf-8", errors="replace", bufsize=1,
                )
                runner.proc = proc
                assert proc.stdout is not None
                for line in proc.stdout:
                    self.after(0, runner.append, line)
                    wf.write(app_logging.redact_worker_line(line) + "\n")
                proc.wait()
                code = proc.returncode
                wf.write(f"# exit_code={code} elapsed_seconds={time.monotonic() - start:.3f} user_stopped={runner.user_stopped}\n")
            self.after(0, runner.append, f"\n[종료 코드: {code}]\n")
        except Exception as exc:  # noqa: BLE001
            self.after(0, runner.append, f"\n[실행 오류: {exc}]\n")
            app_logging.log_exception(
                _logger, "tool_failed", f"default_content_scanner({runner.key}) 실행 오류", sys.exc_info(),
                run_id=runner.run_id, tool=self.spec.key, mode=runner.key,
            )
        finally:
            runner.proc = None
        return code

    def _mode_finished(self, runner: _ModeRunner, code: int | None = None) -> None:
        runner.run_btn.configure(state=tk.NORMAL)
        runner.stop_btn.configure(state=tk.DISABLED)
        runner.active = False
        if runner.user_stopped:
            status = "중지됨"
        elif code in (0, None):
            status = "완료"
        else:
            status = "실행 실패"
        end = datetime.now()
        elapsed = f"{(end - runner.run_start).total_seconds():.1f}초" if runner.run_start else "?"
        start_str = f"{runner.run_start:%H:%M:%S}" if runner.run_start else "?"
        code_note = f" (종료 코드 {code})" if code not in (0, None) else ""
        runner.run_summary_var.set(
            f"시작: {start_str}  |  종료: {end:%H:%M:%S} (소요 {elapsed})  |  종료 상태: {status}{code_note}"
        )
        self._set_sub_tab_state(runner, status)
        self._update_category_indicator()
        app_logging.log_event(
            _logger, "INFO" if status == "완료" else "WARNING", "tool_finished",
            f"default_content_scanner({runner.key}) 실행 종료: {status}", run_id=runner.run_id,
            tool=self.spec.key, mode=runner.key, exit_code=code, status=status,
            elapsed_seconds=(end - runner.run_start).total_seconds() if runner.run_start else None,
        )

    def _mode_stop(self, runner: _ModeRunner) -> None:
        if runner.proc is not None:
            runner.user_stopped = True
            try:
                runner.proc.terminate()
            except Exception:  # noqa: BLE001
                app_logging.log_exception(
                    _logger, "tool_failed", f"default_content_scanner({runner.key}) 중지 요청 실패", sys.exc_info(),
                    run_id=runner.run_id, tool=self.spec.key, mode=runner.key,
                )

    def _set_sub_tab_state(self, runner: _ModeRunner, suffix: str | None) -> None:
        title = runner.label if not suffix else f"{runner.label} ({suffix})"
        try:
            self.sub.tab(runner.tab_frame, text=title)
        except tk.TclError:
            pass

    def _record_fingerprint_hits(self, hits: list[str]) -> None:
        self._last_fingerprint_hits = hits
        self._last_fingerprint_at = datetime.now().strftime("%H:%M:%S")
        text = f"직전 기본 탐지 결과: {len(hits)}개 경로 발견 ({self._last_fingerprint_at} 기준)"
        self.fp_last_var.set(text)
        self.backup_last_hint_var.set(text)

    def _fingerprint_argv_and_track(self) -> list[str] | None:
        """Builds the fingerprint run's argv, always including an internal
        --output-file the GUI reads afterward (see _finish_fingerprint_run)
        to know which paths were actual hits -- never shown to the user as
        a field, just how the 백업 파일 탐지 tab's '직전 결과' option gets
        its data."""
        missing = self._missing_required(self.fp_widgets)
        runner = self._runners.get("fingerprint")
        if missing:
            if runner is not None:
                runner.append(
                    f"실행할 수 없습니다.\n원인: 필수 값이 비어 있습니다: {', '.join(missing)}\n"
                    "조치: 대상 URL을 입력한 뒤 다시 실행하세요.\n\n"
                )
            return None
        fd, tmp_path = tempfile.mkstemp(prefix="dc_fp_", suffix=".json")
        os.close(fd)
        self._fp_tmp_path = tmp_path
        return self._build_argv(widgets=self.fp_widgets) + ["--output", "console", "--output-file", tmp_path]

    # -- 예상 요청 수 (per mode) ------------------------------------------------
    def _wire_mode_estimate(
        self, mode_key: str, widgets: dict, watch_dests: list[str], estimate_var: tk.StringVar, extra_argv_fn,
        extra_watch_vars: list[tk.Variable] | None = None,
    ) -> None:
        self._estimate_jobs[mode_key] = None

        def run() -> None:
            self._estimate_jobs[mode_key] = None
            url_val = self._field_value("url", widgets)
            if not url_val:
                estimate_var.set("예상 요청 수: 대상 URL을 입력하면 계산됩니다.")
                return
            extra = extra_argv_fn()
            if extra is None:
                estimate_var.set("예상 요청 수: 기준 경로/조건을 확인할 수 없어 계산할 수 없습니다.")
                return
            argv = self._build_argv(widgets=widgets) + extra + ["--estimate-only"]
            threading.Thread(target=self._estimate_worker, args=(argv, estimate_var), daemon=True).start()

        self._estimate_runs = getattr(self, "_estimate_runs", {})
        self._estimate_runs[mode_key] = run

        for dest in watch_dests:
            if dest not in widgets:
                continue
            kind, var = widgets[dest]
            if kind == "checklist":
                for bv in var.values():
                    bv.trace_add("write", lambda *_a, k=mode_key: self._estimate_jobs_trigger(k))
            else:
                var.trace_add("write", lambda *_a, k=mode_key: self._estimate_jobs_trigger(k))
        for var in extra_watch_vars or []:
            var.trace_add("write", lambda *_a, k=mode_key: self._estimate_jobs_trigger(k))

    def _estimate_jobs_trigger(self, mode_key: str) -> None:
        job = self._estimate_jobs.get(mode_key)
        if job is not None:
            self.after_cancel(job)
        self._estimate_jobs[mode_key] = self.after(400, self._estimate_runs[mode_key])

    def _estimate_worker(self, argv: list[str], estimate_var: tk.StringVar) -> None:
        try:
            result = subprocess.run(
                [*_self_invoke_prefix(), "--run-tool", str(self.spec.script), *argv],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20,
                cwd=str(self.spec.script.parent),
            )
            data = json.loads(result.stdout.strip().splitlines()[-1])
        except Exception:  # noqa: BLE001
            self.after(0, estimate_var.set, "예상 요청 수 계산 실패 (대상 URL/옵션을 확인하세요)")
            return
        self.after(0, self._show_estimate, estimate_var, data)

    @staticmethod
    def _show_estimate(estimate_var: tk.StringVar, data: dict) -> None:
        total = data["total_requests"]
        load = "낮음" if total <= 50 else "보통" if total <= 300 else "높음"
        # max_requests=0 means "전체 사용" (spec: 목록 진행·Infra·ffuf·Gobuster·
        # HTTP History 개선명세서 §3.3), not "최대 0회" -- showing the literal
        # 0 here would read as "capped at zero" right after it actually ran
        # the full candidate list.
        max_display = "전체 (제한값 0)" if data.get("unlimited") else f"{data['max_requests']}회"
        estimate_var.set(f"예상 요청: 약 {total}회 / 최대 {max_display}   예상 부하: {load}")
