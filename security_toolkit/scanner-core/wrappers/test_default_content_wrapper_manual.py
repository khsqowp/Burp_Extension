import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safety.policy import HttpSafetyPolicy
from storage.models import ScanTarget, Severity
from wrappers.default_content_wrapper import DefaultContentWrapper, PathTraversalWrapper

TESTSERVER = r"C:\Users\user\AppData\Local\Temp\claude\E--temp\cde5e06e-b8b1-45d0-aad9-a3dad83ce944\scratchpad\default_content_testserver.py"
PORT = 8805
VULN_TESTSERVER = r"C:\Users\user\AppData\Local\Temp\claude\E--temp\dcf173e9-7d9a-4773-89f0-d7a723d6ea90\scratchpad\path_traversal_testserver.py"
VULN_PORT = 8899

server = subprocess.Popen([sys.executable, TESTSERVER, str(PORT)])
time.sleep(1)

try:
    target = ScanTarget(value=f"http://127.0.0.1:{PORT}", scope_host="127.0.0.1")

    # -- DefaultContentWrapper: real hits against exposed backup.zip / .git/config
    policy = HttpSafetyPolicy(max_request_count=400, timeout_seconds=5, max_requests_per_second=20)
    dc_wrapper = DefaultContentWrapper(policy)

    # tech="" isolates the built-in generic sensitive/backup-file list (36
    # candidates) instead of also pulling in the huge tomcat/apache/nginx
    # fingerprint wordlists (8700+ combined), which would blow past this
    # test's request budget before ever reaching the two exposed paths.
    argv = dc_wrapper.build_command(target, tech="")
    print("dc argv:", argv)
    assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)

    result, findings = dc_wrapper.run(target, timeout=60, tech="")
    print("dc exit_code:", result.exit_code, "timed_out:", result.timed_out, "duration:", round(result.duration_seconds, 1))
    assert result.exit_code == 0
    assert not result.timed_out
    print("dc findings:", [(f.finding, f.severity.value) for f in findings])
    assert len(findings) >= 2, "expected hits for /backup.zip and /.git/config"
    assert any("backup.zip" in f.finding for f in findings)
    assert any(".git/config" in f.finding for f in findings)
    assert all(f.severity == Severity.MEDIUM for f in findings)
    assert all(f.scanner == "default_content" for f in findings)
    print("DefaultContentWrapper OK")

    # -- PathTraversalWrapper: no vulnerable endpoint, but must run cleanly with 0 hits
    pt_wrapper = PathTraversalWrapper(HttpSafetyPolicy(max_request_count=10, timeout_seconds=5, max_requests_per_second=20))
    argv2 = pt_wrapper.build_command(target, param="file")
    print("pt argv:", argv2)
    assert "--traversal" in argv2 and "--no-fingerprint" in argv2

    try:
        pt_wrapper.build_command(target)
        raise AssertionError("expected ValueError when neither param nor url_template given")
    except ValueError as e:
        print("path_traversal missing-param guard OK:", e)

    result2, findings2 = pt_wrapper.run(target, timeout=30, param="file")
    print("pt exit_code:", result2.exit_code, "findings:", findings2)
    assert result2.exit_code == 0
    assert findings2 == []
    print("PathTraversalWrapper OK (negative path, no vulnerable endpoint)")
finally:
    server.terminate()
    server.wait(timeout=5)

# -- PathTraversalWrapper: true-positive against a naively-vulnerable /download?file= endpoint
vuln_server = subprocess.Popen([sys.executable, VULN_TESTSERVER, str(VULN_PORT)])
time.sleep(1)
try:
    vuln_target = ScanTarget(value=f"http://127.0.0.1:{VULN_PORT}/download", scope_host="127.0.0.1")
    pt_wrapper2 = PathTraversalWrapper(HttpSafetyPolicy(max_request_count=400, timeout_seconds=5, max_requests_per_second=20))
    result3, findings3 = pt_wrapper2.run(vuln_target, timeout=60, param="file", target_os="both")
    print("pt(vuln) exit_code:", result3.exit_code, "hit count:", len(findings3))
    assert result3.exit_code == 0
    assert not result3.timed_out
    assert len(findings3) >= 1, "expected at least one real traversal hit"
    assert all(f.severity == Severity.HIGH for f in findings3)
    assert all(f.scanner == "path_traversal" for f in findings3)
    assert any("etc/passwd" in f.finding for f in findings3) or any("win.ini" in f.finding for f in findings3)
    print("PathTraversalWrapper OK (true-positive: %d hits)" % len(findings3))

    print("\nALL DEFAULT CONTENT / PATH TRAVERSAL WRAPPER TESTS OK")
finally:
    vuln_server.terminate()
    vuln_server.wait(timeout=5)
