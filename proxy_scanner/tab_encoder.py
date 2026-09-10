from __future__ import annotations

import base64
import binascii
import codecs
import html
import html.entities
import tkinter as tk
import urllib.parse
from tkinter import ttk

from tool_tab import ScrollableFrame


def _enc_base64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _enc_base64url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("ascii")


def _enc_base64_double(s: str) -> str:
    return _enc_base64(_enc_base64(s))


def _enc_url(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def _enc_url_double(s: str) -> str:
    return urllib.parse.quote(_enc_url(s), safe="")


def _enc_html_decimal(s: str) -> str:
    return "".join(f"&#{ord(c)};" for c in s)


def _enc_html_hex(s: str) -> str:
    return "".join(f"&#x{ord(c):x};" for c in s)


def _enc_html_named(s: str) -> str:
    out = []
    for c in s:
        name = html.entities.codepoint2name.get(ord(c))
        out.append(f"&{name};" if name else f"&#{ord(c)};")
    return "".join(out)


def _enc_hex(s: str) -> str:
    return s.encode("utf-8").hex()


def _enc_rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")


def _enc_unicode_escape(s: str) -> str:
    return s.encode("unicode_escape").decode("ascii")


ENCODERS: list[tuple[str, callable]] = [
    ("Base64", _enc_base64),
    ("Base64 (URL-safe)", _enc_base64url),
    ("Base64 (2중 인코딩)", _enc_base64_double),
    ("URL 인코딩", _enc_url),
    ("URL 인코딩 (2중)", _enc_url_double),
    ("HTML 엔티티 (named)", _enc_html_named),
    ("HTML 엔티티 (10진수)", _enc_html_decimal),
    ("HTML 엔티티 (16진수)", _enc_html_hex),
    ("Hex", _enc_hex),
    ("ROT13", _enc_rot13),
    ("Unicode escape", _enc_unicode_escape),
]


def _dec_base64(s: str) -> str:
    pad = s + "=" * (-len(s) % 4)
    return base64.b64decode(pad).decode("utf-8", errors="replace")


def _dec_base64url(s: str) -> str:
    pad = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(pad).decode("utf-8", errors="replace")


def _dec_url(s: str) -> str:
    return urllib.parse.unquote(s)


def _dec_url_double(s: str) -> str:
    return urllib.parse.unquote(urllib.parse.unquote(s))


def _dec_html(s: str) -> str:
    return html.unescape(s)


def _dec_hex(s: str) -> str:
    return bytes.fromhex(s.strip()).decode("utf-8", errors="replace")


def _dec_rot13(s: str) -> str:
    return codecs.decode(s, "rot_13")


DECODERS: list[tuple[str, callable]] = [
    ("Base64", _dec_base64),
    ("Base64 (URL-safe)", _dec_base64url),
    ("URL 디코딩", _dec_url),
    ("URL 디코딩 (2중)", _dec_url_double),
    ("HTML 엔티티", _dec_html),
    ("Hex", _dec_hex),
    ("ROT13", _dec_rot13),
]


class EncoderDecoderTab(ttk.Frame):
    """Burp Decoder-style: type/paste text, see it simultaneously encoded
    through every common scheme (and, below, decoded through every common
    scheme) -- no guessing which one you need, no subprocess, instant."""

    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self._build()

    def _build(self) -> None:
        header = ttk.Frame(self, padding=(12, 10, 12, 6))
        header.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(header, text="Encoder / Decoder", font=("", 12, "bold")).pack(anchor=tk.W)
        ttk.Label(
            header,
            text="입력한 값을 여러 인코딩으로 동시에 변환해서 보여줌 (원문→인코딩) / 인코딩된 값을 여러 방식으로 "
            "동시에 디코딩 시도(값→원문 후보). 정체불명 값의 포맷 자체를 추정하려면 Decoder · Crypto Identifier 사용.",
            foreground="#555", wraplength=1100, justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(2, 0))
        ttk.Separator(self, orient=tk.HORIZONTAL).pack(side=tk.TOP, fill=tk.X, padx=12)

        notebook = ttk.Notebook(self)
        notebook.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=12, pady=10)

        enc_frame = ttk.Frame(notebook, padding=8)
        notebook.add(enc_frame, text="인코딩 (원문 → 여러 인코딩)")
        self.enc_input_var = tk.StringVar()
        self._build_direction(enc_frame, self.enc_input_var, ENCODERS, self._run_encoders)

        dec_frame = ttk.Frame(notebook, padding=8)
        notebook.add(dec_frame, text="디코딩 (인코딩값 → 원문 후보)")
        self.dec_input_var = tk.StringVar()
        self._build_direction(dec_frame, self.dec_input_var, DECODERS, self._run_decoders)

    def _build_direction(self, parent: ttk.Frame, input_var: tk.StringVar, schemes, callback) -> None:
        ttk.Label(parent, text="입력:").pack(anchor=tk.W)
        entry = ttk.Entry(parent, textvariable=input_var, font=("Consolas", 10))
        entry.pack(fill=tk.X, pady=(2, 10))
        input_var.trace_add("write", lambda *_: callback())

        scroll = ScrollableFrame(parent)
        scroll.pack(fill=tk.BOTH, expand=True)
        rows = ttk.Frame(scroll.body)
        rows.pack(fill=tk.BOTH, expand=True)
        rows.columnconfigure(1, weight=1)

        result_vars: dict[str, tk.StringVar] = {}
        for i, (name, _fn) in enumerate(schemes):
            ttk.Label(rows, text=name, width=20).grid(row=i, column=0, sticky=tk.W, pady=2)
            var = tk.StringVar()
            result_vars[name] = var
            entry_out = ttk.Entry(rows, textvariable=var, font=("Consolas", 9), state="readonly")
            entry_out.grid(row=i, column=1, sticky=tk.EW, padx=6)
            ttk.Button(rows, text="복사", width=6, command=lambda v=var: self._copy(v.get())).grid(row=i, column=2)

        if schemes is ENCODERS:
            self._enc_vars = result_vars
        else:
            self._dec_vars = result_vars
        scroll.bind_wheel_recursive()

    def _run_encoders(self) -> None:
        text = self.enc_input_var.get()
        for name, fn in ENCODERS:
            try:
                self._enc_vars[name].set(fn(text) if text else "")
            except Exception as exc:  # noqa: BLE001
                self._enc_vars[name].set(f"(오류: {exc})")

    def _run_decoders(self) -> None:
        text = self.dec_input_var.get()
        for name, fn in DECODERS:
            if not text:
                self._dec_vars[name].set("")
                continue
            try:
                self._dec_vars[name].set(fn(text))
            except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
                self._dec_vars[name].set(f"(디코딩 실패: {exc})")
            except Exception as exc:  # noqa: BLE001
                self._dec_vars[name].set(f"(오류: {exc})")

    def _copy(self, text: str) -> None:
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)
