import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safety.policy import HttpSafetyPolicy
from storage.models import ScanTarget, Severity
from wrappers.xss_reflected_wrapper import XssReflectedWrapper

TESTSERVER = r"C:\Users\user\AppData\Local\Temp\claude\E--temp\cde5e06e-b8b1-45d0-aad9-a3dad83ce944\scratchpad\xss_reflected_testserver.py"
PORT = 8873

server = subprocess.Popen([sys.executable, TESTSERVER, str(PORT)])
time.sleep(1)

try:
    target = ScanTarget(value=f"http://127.0.0.1:{PORT}/", scope_host="127.0.0.1")
    wrapper = XssReflectedWrapper(HttpSafetyPolicy(timeout_seconds=5, max_requests_per_second=10))

    argv = wrapper.build_command(target, params="name,safe")
    print("argv:", argv)
    assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
    assert "--output-file" not in argv

    try:
        wrapper.build_command(target)
        raise AssertionError("expected ValueError when no param source given")
    except ValueError as e:
        print("missing-params guard OK:", e)

    result, findings = wrapper.run(target, timeout=30, params="name,safe")
    print("exit_code:", result.exit_code, "timed_out:", result.timed_out)
    assert result.exit_code == 0
    assert not result.timed_out
    print("findings:", [(f.finding, f.severity.value, f.evidence) for f in findings])
    # both params reflect (the tool reports escaped reflections too, at lower
    # risk) -- 'name' comes back completely intact (HIGH), 'safe' is
    # HTML-escaped so it's downgraded, not filtered out entirely.
    assert len(findings) == 2
    name_finding = next(f for f in findings if "'name'" in f.finding)
    safe_finding = next(f for f in findings if "'safe'" in f.finding)
    assert name_finding.severity == Severity.HIGH
    assert safe_finding.severity in (Severity.MEDIUM, Severity.LOW)
    assert all(f.scanner == "xss_reflected" for f in findings)

    print("\nALL XSS REFLECTED WRAPPER TESTS OK")
finally:
    server.terminate()
    server.wait(timeout=5)
