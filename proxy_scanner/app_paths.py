"""Per-user application data paths (spec: 단일 EXE 휴대용 배포 §7). Every
piece of state this program keeps between runs -- History, certificates,
Chromium profile, settings, logs, managed temp files -- lives under here
instead of next to the EXE (which may be read-only: Desktop/Downloads/USB)
or scattered across ad-hoc system temp locations.

    %LOCALAPPDATA%\\ProxyScanner\\
    +- certificates\\   converted proxy CA + backups
    +- history\\        HistoryStore's sqlite3 db
    +- profiles\\       dedicated Chromium profile (독립 프록시 모드)
    +- settings.json    last-used settings / UI state
    +- logs\\           sanitized error log
    +- temp\\           managed scratch files, cleared on clean exit
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _app_root() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        base = str(Path.home() / "AppData" / "Local")
    return Path(base) / "ProxyScanner"


APP_ROOT = _app_root()
CERTIFICATES_DIR = APP_ROOT / "certificates"
HISTORY_DIR = APP_ROOT / "history"
PROFILES_DIR = APP_ROOT / "profiles"
LOGS_DIR = APP_ROOT / "logs"
TEMP_DIR = APP_ROOT / "temp"
SETTINGS_PATH = APP_ROOT / "settings.json"

_ALL_DIRS = (CERTIFICATES_DIR, HISTORY_DIR, PROFILES_DIR, LOGS_DIR, TEMP_DIR)


def ensure_app_dirs() -> list[str]:
    """Creates every subfolder if missing. Returns the list of paths that
    failed to create (empty list = all OK) -- spec 7: "생성 실패 시 어떤
    경로에 쓰지 못했는지 한글로 안내한다" needs to know exactly which one,
    not just that "something" failed."""
    failed: list[str] = []
    for d in _ALL_DIRS:
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError:
            failed.append(str(d))
    return failed


def restrict_to_current_user(path: Path) -> bool:
    """Windows ACL hardening for a path holding CA private-key material
    (design review finding: 'chmod(0o600)만으로 Windows ACL 요구를 완전히
    충족한다고 볼 수 없다' -- chmod is a no-op for real Windows ACLs, it
    only flips the read-only attribute bit). Strips inherited ACEs and
    grants Full Control to the current user only; applied to a directory,
    (OI)(CI) makes files created inside it afterward inherit the same
    restriction -- covers mitmproxy's own first-run CA auto-generation, not
    just an explicit import. Best-effort: a failure here leaves whatever
    ACL the OS default already had (typically already
    user-and-Administrators-only under %LOCALAPPDATA%) and never blocks
    the app -- kept deliberately dependency-free (no pywin32) since
    icacls.exe ships with every supported Windows version."""
    if sys.platform != "win32":
        return True
    user = os.environ.get("USERNAME", "")
    if not user:
        return False
    domain = os.environ.get("USERDOMAIN", "")
    account = f"{domain}\\{user}" if domain else user
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{account}:(OI)(CI)F"],
            capture_output=True, text=True, timeout=10, check=True,
        )
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def clear_temp_dir() -> None:
    """Best-effort cleanup on clean exit -- spec 7: "종료 시 임시 파일은
    정리하되 History, 설정, 인증서는 유지한다". Never touches the other
    subfolders."""
    if not TEMP_DIR.is_dir():
        return
    for child in TEMP_DIR.iterdir():
        try:
            if child.is_dir():
                import shutil
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)
        except OSError:
            pass
