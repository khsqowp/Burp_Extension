"""Independent in-place search bar for a read-only tk.Text widget (spec:
목록 진행·Infra·ffuf·Gobuster·HTTP History 개선명세서 §7). One instance per
Text widget -- gui.py creates two (Request, Response) so their query text,
options, and current-match position never interfere with each other.

Search never mutates the underlying text -- only tag_add/tag_remove for
highlighting. Matches are recomputed (same query, new content) whenever the
caller invokes `refresh_for_new_content()`, e.g. after a different History
row is selected.
"""
from __future__ import annotations

import re
import tkinter as tk
from tkinter import ttk

_DEBOUNCE_MS = 200
_TAG_MATCH = "search_match"
_TAG_CURRENT = "search_match_current"
_TRUNCATION_MARKER = "(truncated,"  # matches addon.py's own _truncate() marker text


class TextSearchBar:
    def __init__(self, parent: tk.Widget, text_widget: tk.Text) -> None:
        self.text_widget = text_widget
        self.matches: list[tuple[str, str]] = []
        self.current_index = -1
        self._debounce_job: str | None = None

        text_widget.tag_configure(_TAG_MATCH, background="#fff3b0")
        text_widget.tag_configure(_TAG_CURRENT, background="#ffa500")

        self.frame = ttk.Frame(parent, padding=(4, 2, 4, 2))
        self.frame.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(self.frame, text="찾기").pack(side=tk.LEFT)
        self.query_var = tk.StringVar(value="")
        self.entry = ttk.Entry(self.frame, textvariable=self.query_var, width=22)
        self.entry.pack(side=tk.LEFT, padx=(4, 6))
        ttk.Button(self.frame, text="이전", width=4, command=self.prev).pack(side=tk.LEFT)
        ttk.Button(self.frame, text="다음", width=4, command=self.next).pack(side=tk.LEFT, padx=(2, 6))
        self.position_var = tk.StringVar(value="0/0")
        ttk.Label(self.frame, textvariable=self.position_var, width=8).pack(side=tk.LEFT)
        self.case_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.frame, text="대소문자", variable=self.case_var, command=self._schedule_search).pack(
            side=tk.LEFT, padx=(6, 0)
        )
        self.regex_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.frame, text="정규식", variable=self.regex_var, command=self._schedule_search).pack(
            side=tk.LEFT, padx=(6, 0)
        )
        self.error_var = tk.StringVar(value="")
        ttk.Label(self.frame, textvariable=self.error_var, foreground="#b3261e").pack(side=tk.LEFT, padx=(8, 0))
        self.truncated_hint_var = tk.StringVar(value="")
        ttk.Label(self.frame, textvariable=self.truncated_hint_var, foreground="#888").pack(side=tk.LEFT, padx=(8, 0))

        self.query_var.trace_add("write", lambda *_a: self._schedule_search())
        self.entry.bind("<Return>", self._on_enter)
        self.entry.bind("<Shift-Return>", self._on_shift_enter)
        self.entry.bind("<Escape>", self._on_escape)
        text_widget.bind("<Control-f>", self._on_ctrl_f, add="+")
        text_widget.bind("<Control-F>", self._on_ctrl_f, add="+")

    # -- key bindings ---------------------------------------------------------
    def _on_enter(self, _event: tk.Event) -> str:
        self.next()
        return "break"

    def _on_shift_enter(self, _event: tk.Event) -> str:
        self.prev()
        return "break"

    def _on_escape(self, _event: tk.Event) -> str:
        if self.query_var.get():
            self.clear()
        else:
            self.text_widget.focus_set()
        return "break"

    def _on_ctrl_f(self, _event: tk.Event) -> str:
        self.entry.focus_set()
        self.entry.selection_range(0, tk.END)
        return "break"

    # -- search -----------------------------------------------------------------
    def _schedule_search(self) -> None:
        if self._debounce_job is not None:
            self.entry.after_cancel(self._debounce_job)
        self._debounce_job = self.entry.after(_DEBOUNCE_MS, self._run_search)

    def _offset_to_index(self, offset: int) -> str:
        return self.text_widget.index(f"1.0+{offset}c")

    def _run_search(self) -> None:
        self._debounce_job = None
        self.error_var.set("")
        self.text_widget.tag_remove(_TAG_MATCH, "1.0", tk.END)
        self.text_widget.tag_remove(_TAG_CURRENT, "1.0", tk.END)
        self.matches = []
        self.current_index = -1

        query = self.query_var.get()
        content = self.text_widget.get("1.0", "end-1c")
        self.truncated_hint_var.set("표시된 내용에서만 검색됨" if _TRUNCATION_MARKER in content else "")
        if not query:
            self._update_position_label()
            return

        if self.regex_var.get():
            try:
                flags = 0 if self.case_var.get() else re.IGNORECASE
                pattern = re.compile(query, flags)
            except re.error as exc:
                self.error_var.set(f"정규식 오류: {exc}")
                self._update_position_label()
                return
            for m in pattern.finditer(content):
                if m.start() == m.end():
                    continue  # zero-length match -- nothing to highlight/navigate to
                self.matches.append((self._offset_to_index(m.start()), self._offset_to_index(m.end())))
        else:
            haystack = content if self.case_var.get() else content.lower()
            needle = query if self.case_var.get() else query.lower()
            start = 0
            while True:
                pos = haystack.find(needle, start)
                if pos == -1:
                    break
                self.matches.append((self._offset_to_index(pos), self._offset_to_index(pos + len(needle))))
                start = pos + len(needle)

        for s, e in self.matches:
            self.text_widget.tag_add(_TAG_MATCH, s, e)
        if self.matches:
            self.current_index = 0
            self._highlight_current()
        self._update_position_label()

    def _highlight_current(self) -> None:
        self.text_widget.tag_remove(_TAG_CURRENT, "1.0", tk.END)
        if 0 <= self.current_index < len(self.matches):
            s, e = self.matches[self.current_index]
            self.text_widget.tag_add(_TAG_CURRENT, s, e)
            self.text_widget.see(s)
        self._update_position_label()

    def _update_position_label(self) -> None:
        if not self.matches:
            self.position_var.set("0/0")
        else:
            self.position_var.set(f"{self.current_index + 1}/{len(self.matches)}")

    def next(self) -> None:
        if not self.matches:
            return
        self.current_index = (self.current_index + 1) % len(self.matches)
        self._highlight_current()

    def prev(self) -> None:
        if not self.matches:
            return
        self.current_index = (self.current_index - 1) % len(self.matches)
        self._highlight_current()

    def clear(self) -> None:
        # Bypasses the debounce entirely -- Escape/"검색어가 비어 있으면
        # 강조 표시를 제거한다" should feel instant, not wait out the same
        # 200ms window a live keystroke would.
        if self._debounce_job is not None:
            self.entry.after_cancel(self._debounce_job)
            self._debounce_job = None
        self.query_var.set("")
        self._run_search()

    def refresh_for_new_content(self) -> None:
        """Call after the widget's text has been replaced (e.g. a different
        History row was selected) -- keeps the same query/options, just
        recomputes matches against the new content (spec §7.1: "History
        행을 바꾸면 해당 요청/응답 내용에서 같은 검색어를 다시 계산한다")."""
        if self._debounce_job is not None:
            self.entry.after_cancel(self._debounce_job)
            self._debounce_job = None
        self._run_search()
