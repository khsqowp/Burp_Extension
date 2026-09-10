from __future__ import annotations

import base64
import json
import tkinter as tk
from tkinter import scrolledtext, ttk

from tool_registry import ToolSpec
from tool_tab import ToolTab

_HEADER_TAG = "seg_header"
_PAYLOAD_TAG = "seg_payload"
_SIG_TAG = "seg_sig"
_DOT_TAG = "seg_dot"

_EXAMPLE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def _b64url_decode(segment: str) -> bytes:
    segment += "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment)


def _pretty_segment(segment: str) -> str:
    if not segment:
        return ""
    try:
        obj = json.loads(_b64url_decode(segment))
        return json.dumps(obj, indent=2, ensure_ascii=False)
    except Exception as exc:  # noqa: BLE001
        return f"(디코딩 실패: {exc})"


class JwtAnalyzerTab(ToolTab):
    """jwt.io-style layout: paste a token, header/payload decode live and
    color-coded (no subprocess -- pure local base64/json, instant feedback).
    The heavier checks (secret cracking, alg=none / algorithm-confusion PoC
    generation) still run the real jwt_analyzer.py tool as a subprocess,
    same as every other tab, via the inherited on_run/_run_subprocess."""

    def __init__(self, parent: tk.Widget, spec: ToolSpec) -> None:
        super().__init__(parent, spec)

    def _build(self) -> None:
        self._build_header()

        try:
            info = self._introspect()
        except Exception as exc:  # noqa: BLE001
            ttk.Label(self, text=f"이 도구 정보를 불러오지 못함:\n{exc}", foreground="#c0392b", justify=tk.LEFT).pack(
                padx=12, pady=10, anchor=tk.W
            )
            return
        self.actions = info["actions"]
        by_dest = {a["dest"]: a for a in self.actions}

        # -- encoded token input (color-coded like jwt.io) --------------------
        enc_frame = ttk.Frame(self, padding=(12, 4))
        enc_frame.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(enc_frame, text="Encoded JWT", font=("", 9, "bold")).pack(anchor=tk.W)
        self.encoded_text = tk.Text(enc_frame, height=4, wrap=tk.CHAR, font=("Consolas", 10), undo=True)
        self.encoded_text.pack(fill=tk.X, pady=(2, 0))
        self.encoded_text.tag_configure(_HEADER_TAG, foreground="#c0392b")
        self.encoded_text.tag_configure(_PAYLOAD_TAG, foreground="#8e44ad")
        self.encoded_text.tag_configure(_SIG_TAG, foreground="#2471a3")
        self.encoded_text.tag_configure(_DOT_TAG, foreground="#999")
        self.encoded_text.insert("1.0", _EXAMPLE)
        self.encoded_text.bind("<KeyRelease>", self._on_token_change)
        # positional_dest points send-from-history at this widget's owning dest ("token")
        self.positional_dest = None  # custom widget, not in self.widgets -- set_target() overridden below

        # -- decoded header/payload (top) + advanced analysis (bottom), in a
        # resizable split -- HEADER/PAYLOAD themselves are a nested left/right
        # split. Real draggable sashes with a per-pane minsize floor -- ttk's
        # PanedWindow has no minsize option at all (only -weight), so this
        # uses classic tk.PanedWindow instead, same as the spec allows.
        _SASH_KW = dict(sashrelief=tk.RAISED, sashwidth=6, bg="#d0d0d0", bd=0)

        outer_paned = tk.PanedWindow(self, orient=tk.VERTICAL, **_SASH_KW)
        outer_paned.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=12, pady=(4, 0))

        dec_frame = ttk.Frame(outer_paned)
        outer_paned.add(dec_frame, minsize=110, stretch="always")

        hpaned = tk.PanedWindow(dec_frame, orient=tk.HORIZONTAL, **_SASH_KW)
        hpaned.pack(fill=tk.BOTH, expand=True)

        header_pane = ttk.Frame(hpaned)
        hpaned.add(header_pane, minsize=160, stretch="always")
        ttk.Label(
            header_pane, text="HEADER", font=("", 9, "bold"),
            foreground=self.encoded_text.tag_cget(_HEADER_TAG, "foreground"),
        ).pack(anchor=tk.W)
        self.header_text = tk.Text(header_pane, font=("Consolas", 9), background="#fdf2f0")
        self.header_text.pack(fill=tk.BOTH, expand=True, padx=(0, 6))

        payload_pane = ttk.Frame(hpaned)
        hpaned.add(payload_pane, minsize=160, stretch="always")
        ttk.Label(
            payload_pane, text="PAYLOAD", font=("", 9, "bold"),
            foreground=self.encoded_text.tag_cget(_PAYLOAD_TAG, "foreground"),
        ).pack(anchor=tk.W)
        self.payload_text = tk.Text(payload_pane, font=("Consolas", 9), background="#f7f0fa")
        self.payload_text.pack(fill=tk.BOTH, expand=True)

        self._bind_initial_sash(hpaned, lambda w: w // 2)

        bottom_frame = ttk.Frame(outer_paned, padding=(0, 8, 0, 0))
        outer_paned.add(bottom_frame, minsize=260, stretch="always")
        self._bind_initial_sash(outer_paned, lambda _h: 160)

        # -- advanced checks (run the real tool as a subprocess) --------------
        adv_body, adv_bottom = self._build_options_and_bottom(bottom_frame, min_options=70, max_ratio=0.5)
        adv = ttk.Frame(adv_body)
        adv.pack(side=tk.TOP, fill=tk.X)
        ttk.Separator(adv, orient=tk.HORIZONTAL).grid(row=0, column=0, columnspan=4, sticky=tk.EW, pady=(0, 8))
        ttk.Label(adv, text="심화 분석 (실제 서버에 쓰기 전 로컬 검증)", font=("", 9, "bold")).grid(
            row=1, column=0, columnspan=4, sticky=tk.W, pady=(0, 4)
        )
        adv.columnconfigure(3, weight=1)

        row = 2
        self.crack_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(adv, text="시크릿 무차별 대입 (HS256/384/512)", variable=self.crack_var).grid(
            row=row, column=0, columnspan=2, sticky=tk.W
        )
        row += 1
        row = self._build_field(adv, row, by_dest["wordlist"])
        row = self._build_field(adv, row, by_dest["limit"])

        self.gen_none_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(adv, text="alg=none 변조 PoC 토큰 생성", variable=self.gen_none_var).grid(
            row=row, column=0, columnspan=2, sticky=tk.W, pady=(6, 0)
        )
        row += 1
        row = self._build_field(adv, row, by_dest["confusion_pubkey"])
        row = self._build_field(adv, row, by_dest["confusion_alg"])

        btn_frame = ttk.Frame(adv_bottom, padding=(0, 4))
        btn_frame.pack(side=tk.TOP, fill=tk.X)
        self.run_btn = ttk.Button(btn_frame, text="▶ 분석 실행", style="Accent.TButton", command=self.on_run)
        self.run_btn.pack(side=tk.LEFT)
        self.stop_btn = ttk.Button(btn_frame, text="■ 중지", command=self.on_stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="출력 지우기", command=self.on_clear_output).pack(side=tk.LEFT, padx=4)

        self._build_run_summary_bar(adv_bottom)
        self.output = scrolledtext.ScrolledText(adv_bottom, wrap=tk.WORD, font=("Consolas", 9), borderwidth=1, relief=tk.SOLID)
        self.output.pack(fill=tk.BOTH, expand=True, pady=(4, 4))
        self.output.configure(state=tk.DISABLED)
        self._finalize_scroll_areas()

        self._on_token_change()

    # -- live local decode (no subprocess) -----------------------------------
    def _on_token_change(self, event=None) -> None:
        token = self.encoded_text.get("1.0", tk.END).strip()
        self.encoded_text.tag_remove(_HEADER_TAG, "1.0", tk.END)
        self.encoded_text.tag_remove(_PAYLOAD_TAG, "1.0", tk.END)
        self.encoded_text.tag_remove(_SIG_TAG, "1.0", tk.END)
        self.encoded_text.tag_remove(_DOT_TAG, "1.0", tk.END)

        parts = token.split(".")
        header_seg = parts[0] if len(parts) > 0 else ""
        payload_seg = parts[1] if len(parts) > 1 else ""

        pos = 0
        for i, part in enumerate(parts[:3]):
            start = f"1.{pos}"
            end = f"1.{pos + len(part)}"
            tag = (_HEADER_TAG, _PAYLOAD_TAG, _SIG_TAG)[i]
            self.encoded_text.tag_add(tag, start, end)
            pos += len(part)
            if pos < len(token):
                self.encoded_text.tag_add(_DOT_TAG, f"1.{pos}", f"1.{pos + 1}")
                pos += 1

        self._set_text(self.header_text, _pretty_segment(header_seg))
        self._set_text(self.payload_text, _pretty_segment(payload_seg))

    @staticmethod
    def _set_text(widget: tk.Text, text: str) -> None:
        widget.delete("1.0", tk.END)
        widget.insert("1.0", text)

    # -- send-from-history override (custom widget, not the generic form) ---
    def set_target(self, value: str) -> None:
        self.encoded_text.delete("1.0", tk.END)
        self.encoded_text.insert("1.0", value)
        self._on_token_change()

    def _current_target_display(self) -> str:
        token = self.encoded_text.get("1.0", tk.END).strip()
        if not token:
            return "(미지정)"
        return token if len(token) <= 40 else token[:37] + "..."

    # -- argv for the real tool ------------------------------------------------
    def _build_argv(self) -> list[str]:
        token = self.encoded_text.get("1.0", tk.END).strip()
        if not token:
            return []
        argv = [token]
        if self.crack_var.get():
            argv.append("--crack-secret")
            _, wl_var = self.widgets["wordlist"]
            if wl_var.get().strip():
                argv += ["--wordlist", wl_var.get().strip()]
            _, limit_var = self.widgets["limit"]
            if limit_var.get().strip():
                argv += ["--limit", limit_var.get().strip()]
        if self.gen_none_var.get():
            argv.append("--gen-none")
        _, pubkey_var = self.widgets["confusion_pubkey"]
        if pubkey_var.get().strip():
            argv += ["--confusion-pubkey", pubkey_var.get().strip()]
            _, alg_var = self.widgets["confusion_alg"]
            if alg_var.get().strip():
                argv += ["--confusion-alg", alg_var.get().strip()]
        return argv
