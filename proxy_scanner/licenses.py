"""Third-party license/notice text for everything this program bundles or
launches (spec: 단일 EXE 휴대용 배포 §10 "네이티브 도구, Chromium, 워드리스트의
재배포 조건과 라이선스를 확인하여 고지문을 EXE에서 열람할 수 있게 한다").
gui.py's 도움말 > 라이선스 정보 menu shows this text; kept as plain data here
so it's easy to review/update independently of the UI code."""
from __future__ import annotations

import sys
from pathlib import Path

import tool_registry


def _read_bundled(rel_path: str) -> str:
    """Reads a bundled LICENSE file via the same dual-path root the tools
    themselves use, so this works identically in personal-env and portable
    (frozen, bundled-resource) runs."""
    p = tool_registry.TOOLS_ROOT / rel_path
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return f"(라이선스 파일을 찾을 수 없음: {p})"


NOTICE_TEXT = f"""\
Proxy Scanner는 다음 외부 도구/데이터를 실행하거나 내장합니다. 각 항목의
원 저작권과 라이선스는 해당 프로젝트에 있습니다.

============================================================
ffuf (https://github.com/ffuf/ffuf)
============================================================
{_read_bundled("ffuf/LICENSE")}

============================================================
gobuster (https://github.com/OJ/gobuster)
============================================================
{_read_bundled("gobuster/LICENSE")}

============================================================
Burp Suite Montoya API (net.portswigger.burp.extensions:montoya-api)
============================================================
PortSwigger가 배포하는 Burp 확장 개발용 API 라이브러리입니다.
이 프로그램이 내장하는 Burp History Bridge 확장(burp_extension/)이
컴파일 시 의존성으로 사용합니다. 라이선스 조건은
https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/set-up/manual-setup
문서 및 Maven Central 배포판을 참고하세요.

============================================================
SecLists (https://github.com/danielmiessler/SecLists)
============================================================
MIT License. 이 프로그램은 SecLists의 극히 일부 파일(기본 진단에 실제
사용하는 워드리스트만)을 선별해 내장합니다.

============================================================
PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings)
============================================================
MIT License. Directory Traversal 페이로드 목록 일부를 내장합니다.

============================================================
nmap (https://nmap.org)
============================================================
설치되어 있는 경우에만 사용합니다 -- 이 프로그램은 nmap 실행 파일이나
Npcap 드라이버를 내장/설치하지 않습니다 (Npcap은 관리자 권한 드라이버
설치가 필요해 "관리자 권한 불필요" 기본 원칙과 맞지 않음). Infra Vuln
Scanner를 쓰려면 nmap을 별도로 설치하세요: https://nmap.org/download.html
"""


def show_licenses_window(parent) -> None:
    import tkinter as tk
    from tkinter import scrolledtext, ttk

    win = tk.Toplevel(parent)
    win.title("라이선스 및 고지 사항")
    win.geometry("800x600")
    text = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Consolas", 9))
    text.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
    text.insert("1.0", NOTICE_TEXT)
    text.configure(state=tk.DISABLED)
    ttk.Button(win, text="닫기", command=win.destroy).pack(pady=(0, 8))
