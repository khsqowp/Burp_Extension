import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safety.policy import HttpSafetyPolicy
from storage.models import ScanTarget, Severity
from wrappers.xss_stored_wrapper import XssStoredWrapper

TESTSERVER = r"C:\Users\user\AppData\Local\Temp\claude\E--temp\cde5e06e-b8b1-45d0-aad9-a3dad83ce944\scratchpad\xss_stored_testserver.py"
PORT = 8881

server = subprocess.Popen([sys.executable, TESTSERVER, str(PORT)])
time.sleep(1)

try:
    target = ScanTarget(value=f"http://127.0.0.1:{PORT}/", scope_host="127.0.0.1")
    wrapper = XssStoredWrapper(HttpSafetyPolicy(timeout_seconds=5, max_requests_per_second=10))

    check_url = f"http://127.0.0.1:{PORT}/view"
    argv = wrapper.build_command(target, check_url=check_url, params="comment")
    print("argv:", argv)
    assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
    assert "--check-url" in argv and check_url in argv
    assert "--output-file" not in argv

    for bad_kwargs in [{}, {"check_url": check_url}, {"params": "comment"}]:
        try:
            wrapper.build_command(target, **bad_kwargs)
            raise AssertionError(f"expected ValueError for {bad_kwargs}")
        except ValueError as e:
            print("guard OK for", bad_kwargs, "->", e)

    result, findings = wrapper.run(target, timeout=30, check_url=check_url, params="comment")
    print("exit_code:", result.exit_code, "timed_out:", result.timed_out)
    assert result.exit_code == 0
    assert not result.timed_out
    print("findings:", [(f.finding, f.severity.value) for f in findings])
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "comment" in findings[0].finding
    assert findings[0].scanner == "xss_stored"

    print("\nALL XSS STORED WRAPPER TESTS OK")
finally:
    server.terminate()
    server.wait(timeout=5)
