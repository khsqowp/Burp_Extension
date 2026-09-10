"""Windows-only helper: toggle the system HTTP proxy setting (the same
setting Windows Settings > Network > Proxy edits). This is what makes
IE/Edge/Chrome (WinINet-based) actually route traffic through our listener
without the user having to dig through browser settings by hand -- Firefox
does NOT follow this (it has its own independent proxy config) and needs to
be pointed at the same host:port manually."""
from __future__ import annotations

import sys

IS_WINDOWS = sys.platform.startswith("win")

_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_INTERNET_OPTION_SETTINGS_CHANGED = 39
_INTERNET_OPTION_REFRESH = 37


def _notify_system() -> None:
    import ctypes

    wininet = ctypes.windll.wininet  # type: ignore[attr-defined]
    wininet.InternetSetOptionW(0, _INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
    wininet.InternetSetOptionW(0, _INTERNET_OPTION_REFRESH, 0, 0)


def set_system_proxy(host: str, port: int) -> None:
    if not IS_WINDOWS:
        raise RuntimeError("Windows에서만 지원됨")
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PATH, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    _notify_system()


def clear_system_proxy() -> None:
    if not IS_WINDOWS:
        raise RuntimeError("Windows에서만 지원됨")
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PATH, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    _notify_system()
