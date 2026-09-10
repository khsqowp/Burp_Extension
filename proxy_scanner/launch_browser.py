"""Launches this program's single dedicated Chromium instance, pre-configured
to route through this proxy -- the same trick Burp's own embedded Chromium
uses: a per-process --proxy-server flag plus --proxy-bypass-list="<-loopback>"
to defeat Chromium's hardcoded "never proxy localhost/127.0.0.1" rule.

Per the Chromium 자동 HTTP History 기능명세서: exactly one designated
Chromium-family executable is supported (Chrome), not "Chrome or Edge" --
searching multiple browser vendors would make it ambiguous which traffic is
even supposed to be captured. The dedicated profile (--user-data-dir) is
reused for the lifetime of this process (module-level, reset on every fresh
launch of proxy_scanner itself) so repeated "Chromium 열기" clicks open new
windows in the same tracked session instead of spinning up a fresh, unrelated
profile each time -- and QUIC is disabled so a fallback HTTP/3 connection
can't quietly route around the proxy.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from pathlib import Path

import app_paths

_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
]

_session_profile_dir: str | None = None


def find_browser() -> Path | None:
    for c in _CANDIDATES:
        p = Path(c)
        if p.is_file():
            return p
    return None


def get_session_profile_dir() -> str:
    """One dedicated profile dir per proxy_scanner process lifetime -- lets
    a second "Chromium 열기" click reuse the same session (a second Chrome
    launch against an already-running profile just opens a new window in
    the existing process, which is plain Chrome behavior, not something
    this needs to special-case) instead of creating an unrelated profile
    each time. Lives under the managed per-user app-data folder (spec: 단일
    EXE 휴대용 배포 §5.4/§7: "Chromium 프로필은 사용자 데이터 폴더 아래
    전용 위치에 생성"), a fresh subfolder per session rather than reusing
    one persistent profile across restarts (out of scope per the Chromium
    자동 History spec)."""
    global _session_profile_dir
    if _session_profile_dir is None:
        app_paths.PROFILES_DIR.mkdir(parents=True, exist_ok=True)
        session_dir = app_paths.PROFILES_DIR / f"session-{uuid.uuid4().hex[:12]}"
        session_dir.mkdir(parents=True, exist_ok=True)
        _session_profile_dir = str(session_dir)
    return _session_profile_dir


def reset_session_profile_dir() -> None:
    """Forces the next launch to start a brand new dedicated profile/session
    instead of reusing the current one."""
    global _session_profile_dir
    _session_profile_dir = None


def cleanup_stale_profiles() -> None:
    """Best-effort removal of previous sessions' profile folders on a clean
    exit, so PROFILES_DIR doesn't grow across every app restart -- never
    touches the CURRENT session's own folder (only relevant if this is
    called while a session is still active, which on_close() doesn't do)."""
    if not app_paths.PROFILES_DIR.is_dir():
        return
    for child in app_paths.PROFILES_DIR.iterdir():
        if str(child) == _session_profile_dir:
            continue
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)


def launch_proxied_browser(host: str, port: int, url: str | None = None) -> subprocess.Popen:
    browser = find_browser()
    if browser is None:
        raise RuntimeError(
            "Chrome를 찾지 못함 (표준 설치 경로가 아니면, 원하는 Chromium 계열 브라우저를 아래 옵션과 함께 직접 실행: "
            f'--proxy-server={host}:{port} --proxy-bypass-list="<-loopback>" --disable-quic)'
        )
    profile_dir = get_session_profile_dir()
    args = [
        str(browser),
        f"--proxy-server={host}:{port}",
        '--proxy-bypass-list=<-loopback>',
        "--disable-quic",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    if url:
        args.append(url)
    return subprocess.Popen(args)
