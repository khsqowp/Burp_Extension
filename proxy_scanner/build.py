"""Rebuild proxy_scanner.exe from source.

Run this any time main.py / gui.py / rules.py / addon.py / proxy_engine.py /
models.py change (or anything under a bundled tool folder -- see
BUNDLED_TOOL_DIRS below). Output: dist/proxy_scanner.exe
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS_ROOT = HERE.parent

# -- portable single-EXE bundling (spec: 단일 EXE 휴대용 배포 §5) -----------
# Previously the other 8 tools were loaded dynamically at runtime purely
# from their real E:\temp\tools\... location (tool_registry.py's TOOLS_ROOT
# hardcoded that path even in frozen builds) -- meaning the exe only ever
# worked on this one dev machine. Bundling each tool's own directory here,
# preserving the exact same relative path it already has under
# E:\temp\tools, is what makes tool_registry.py's dual-path fallback (see
# its _tools_root()) actually have somewhere real to fall back to: each
# tool script's own `Path(__file__).resolve().parent.parent` internal
# wordlist/data lookups keep working completely unchanged, because
# `__file__` resolves inside sys._MEIPASS with the identical layout.
BUNDLED_TOOL_DIRS = [
    "site_depth_crawler",
    "default_content_scanner",
    "infra_vuln_scanner",
    "ssl_tls_scanner",
    "xss_reflected_scanner",
    "xss_stored_scanner",
    "jwt_analyzer",
    "crypto_identifier",
    "ffuf_scanner",
    "gobuster_scanner",
]

# Deliberately NOT the full SecLists-master (2.7GB) / PayloadsAllTheThings
# checkout -- just the handful of files the bundled tools' own defaults
# actually read (spec 5.3: "대용량 SecLists 전체를 무조건 포함하지 않고,
# 기본 진단에 실제 사용하는 목록만 선별"). Personal-env users keep using
# their full local checkout via tool_registry.py's dual-path resolution;
# this subset is only what a portable/휴대용-mode run falls back to.
MINIMAL_WORDLISTS = [
    "SecLists-master/Discovery/Web-Content/common.txt",
    "SecLists-master/Discovery/Web-Content/Web-Servers/Apache-Tomcat.txt",
    "SecLists-master/Discovery/Web-Content/Web-Servers/Apache.txt",
    "SecLists-master/Discovery/Web-Content/Web-Servers/nginx.txt",
    "SecLists-master/Discovery/Web-Content/Web-Servers/IIS.txt",
    "SecLists-master/Discovery/Web-Content/Web-Servers/JBoss.txt",
    "SecLists-master/Discovery/Web-Content/Common-DB-Backups.txt",
    "SecLists-master/Passwords/Common-Credentials/10k-most-common.txt",
    "SecLists-master/Passwords/scraped-JWT-secrets.txt",
    "PayloadsAllTheThings-master/Directory Traversal/Intruder/directory_traversal.txt",
    "PayloadsAllTheThings-master/Directory Traversal/Intruder/deep_traversal.txt",
    "PayloadsAllTheThings-master/Directory Traversal/Intruder/traversals-8-deep-exotic-encoding.txt",
]

# (relative source under TOOLS_ROOT, dest folder inside the bundle)
NATIVE_BINARIES = [
    ("ffuf/ffuf.exe", "ffuf"),
    ("ffuf/LICENSE", "ffuf"),
    ("gobuster/gobuster.exe", "gobuster"),
    ("gobuster/LICENSE", "gobuster"),
]

# Burp History Bridge extension jar (spec: Burp Browser 연동 §3.2 "EXE 내장
# 자원 -- Burp 확장 파일을 EXE 안에 포함"). Built separately via
# burp_extension's own `mvn package`; this just bundles the already-built
# jar, it does not invoke Maven itself.
BURP_EXTENSION_JAR = TOOLS_ROOT / "burp_extension" / "target" / "burp-history-bridge.jar"


def _add_data_args() -> list[str]:
    args: list[str] = []
    for d in BUNDLED_TOOL_DIRS:
        args += ["--add-data", f"{TOOLS_ROOT / d};{d}"]
    for rel in MINIMAL_WORDLISTS:
        src = TOOLS_ROOT / rel
        dest_dir = str(Path(rel).parent)
        if not src.is_file():
            print(f"WARNING: expected wordlist not found, skipping: {src}")
            continue
        args += ["--add-data", f"{src};{dest_dir}"]
    for rel_src, dest_dir in NATIVE_BINARIES:
        src = TOOLS_ROOT / rel_src
        if not src.is_file():
            print(f"WARNING: expected native binary not found, skipping: {src}")
            continue
        args += ["--add-binary", f"{src};{dest_dir}"]
    if BURP_EXTENSION_JAR.is_file():
        args += ["--add-data", f"{BURP_EXTENSION_JAR};burp_extension"]
    else:
        print(f"WARNING: Burp extension jar not built yet, skipping: {BURP_EXTENSION_JAR} "
              f"(run 'mvn package' in burp_extension/ first)")
    return args


CMD = [
    sys.executable, "-m", "PyInstaller",
    "--noconfirm",
    "--onefile",
    "--windowed",  # spec §10: GUI app -- no separate console window
    "--name", "proxy_scanner",
    "--version-file", str(HERE / "version_info.txt"),  # spec §10: 버전 정보/제품명/파일 설명
    "--distpath", str(HERE / "dist"),
    "--workpath", str(HERE / "build"),
    "--specpath", str(HERE),
    "--collect-all", "mitmproxy",
    "--collect-all", "mitmproxy_rs",
    "--hidden-import", "gui",
    "--hidden-import", "models",
    "--hidden-import", "rules",
    "--hidden-import", "addon",
    "--hidden-import", "proxy_engine",
    "--hidden-import", "tool_registry",
    "--hidden-import", "tool_tab",
    "--hidden-import", "tool_worker",
    "--hidden-import", "import_ca",
    "--hidden-import", "system_proxy",
    "--hidden-import", "launch_browser",
    "--hidden-import", "burp_bridge",
    "--hidden-import", "app_paths",
    "--hidden-import", "licenses",
    "--hidden-import", "tab_default_content",
    "--hidden-import", "tab_jwt",
    "--hidden-import", "tab_encoder",
    # The other 8 tools are loaded dynamically at runtime (importlib, from
    # tool_registry.TOOLS_ROOT -- personal path or, on a portable/다른 PC
    # run, the bundled copy added via --add-data above), so PyInstaller's
    # static analysis never sees their import statements and never bundles
    # what they need on its own -- anything beyond what proxy_scanner's own
    # code already pulls in has to be listed here by hand. Known needs so
    # far: crawler.py/default_content_scanner.py use urllib.robotparser;
    # infra_vuln_scanner.py uses xml.etree.ElementTree; ssl_tls_scanner/
    # main.py (via analyzers/policy_engine.py) uses PyYAML.
    "--hidden-import", "urllib.robotparser",
    "--hidden-import", "html.parser",
    "--hidden-import", "xml.etree.ElementTree",
    "--hidden-import", "yaml",
    "--collect-all", "yaml",
    "--hidden-import", "ipaddress",
    "--hidden-import", "http.client",
    "--hidden-import", "fnmatch",
    "--hidden-import", "ssl",
    "--hidden-import", "socket",
    "--hidden-import", "hashlib",
    "--hidden-import", "uuid",
    *_add_data_args(),
    str(HERE / "main.py"),
]

if __name__ == "__main__":
    print("Building proxy_scanner.exe ...")
    result = subprocess.run(CMD, cwd=HERE)
    raise SystemExit(result.returncode)
