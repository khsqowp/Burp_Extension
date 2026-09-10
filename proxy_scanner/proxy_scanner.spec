# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('E:/temp/tools/site_depth_crawler', 'site_depth_crawler'), ('E:/temp/tools/default_content_scanner', 'default_content_scanner'), ('E:/temp/tools/infra_vuln_scanner', 'infra_vuln_scanner'), ('E:/temp/tools/ssl_tls_scanner', 'ssl_tls_scanner'), ('E:/temp/tools/xss_reflected_scanner', 'xss_reflected_scanner'), ('E:/temp/tools/xss_stored_scanner', 'xss_stored_scanner'), ('E:/temp/tools/jwt_analyzer', 'jwt_analyzer'), ('E:/temp/tools/crypto_identifier', 'crypto_identifier'), ('E:/temp/tools/ffuf_scanner', 'ffuf_scanner'), ('E:/temp/tools/gobuster_scanner', 'gobuster_scanner'), ('E:/temp/tools/SecLists-master/Discovery/Web-Content/common.txt', 'SecLists-master/Discovery/Web-Content'), ('E:/temp/tools/SecLists-master/Discovery/Web-Content/Web-Servers/Apache-Tomcat.txt', 'SecLists-master/Discovery/Web-Content/Web-Servers'), ('E:/temp/tools/SecLists-master/Discovery/Web-Content/Web-Servers/Apache.txt', 'SecLists-master/Discovery/Web-Content/Web-Servers'), ('E:/temp/tools/SecLists-master/Discovery/Web-Content/Web-Servers/nginx.txt', 'SecLists-master/Discovery/Web-Content/Web-Servers'), ('E:/temp/tools/SecLists-master/Discovery/Web-Content/Web-Servers/IIS.txt', 'SecLists-master/Discovery/Web-Content/Web-Servers'), ('E:/temp/tools/SecLists-master/Discovery/Web-Content/Web-Servers/JBoss.txt', 'SecLists-master/Discovery/Web-Content/Web-Servers'), ('E:/temp/tools/SecLists-master/Discovery/Web-Content/Common-DB-Backups.txt', 'SecLists-master/Discovery/Web-Content'), ('E:/temp/tools/SecLists-master/Passwords/Common-Credentials/10k-most-common.txt', 'SecLists-master/Passwords/Common-Credentials'), ('E:/temp/tools/SecLists-master/Passwords/scraped-JWT-secrets.txt', 'SecLists-master/Passwords'), ('E:/temp/tools/PayloadsAllTheThings-master/Directory Traversal/Intruder/directory_traversal.txt', 'PayloadsAllTheThings-master/Directory Traversal/Intruder'), ('E:/temp/tools/PayloadsAllTheThings-master/Directory Traversal/Intruder/deep_traversal.txt', 'PayloadsAllTheThings-master/Directory Traversal/Intruder'), ('E:/temp/tools/PayloadsAllTheThings-master/Directory Traversal/Intruder/traversals-8-deep-exotic-encoding.txt', 'PayloadsAllTheThings-master/Directory Traversal/Intruder'), ('E:/temp/tools/burp_extension/target/burp-history-bridge.jar', 'burp_extension')]
binaries = [('E:/temp/tools/ffuf/ffuf.exe', 'ffuf'), ('E:/temp/tools/ffuf/LICENSE', 'ffuf'), ('E:/temp/tools/gobuster/gobuster.exe', 'gobuster'), ('E:/temp/tools/gobuster/LICENSE', 'gobuster')]
hiddenimports = ['gui', 'models', 'rules', 'addon', 'proxy_engine', 'tool_registry', 'tool_tab', 'tool_worker', 'import_ca', 'system_proxy', 'launch_browser', 'burp_bridge', 'app_paths', 'licenses', 'tab_default_content', 'tab_jwt', 'tab_encoder', 'urllib.robotparser', 'html.parser', 'xml.etree.ElementTree', 'yaml', 'ipaddress', 'http.client', 'fnmatch', 'ssl', 'socket', 'hashlib', 'uuid']
tmp_ret = collect_all('mitmproxy')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('mitmproxy_rs')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('yaml')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['E:/temp/tools/proxy_scanner/main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='proxy_scanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='E:/temp/tools/proxy_scanner/version_info.txt',
)
