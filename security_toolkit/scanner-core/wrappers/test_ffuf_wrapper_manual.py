import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safety.policy import HttpSafetyPolicy
from storage.models import ScanTarget, Severity
from wrappers.ffuf_wrapper import FfufWrapper

TESTSERVER = r"C:\Users\user\AppData\Local\Temp\claude\E--temp\cde5e06e-b8b1-45d0-aad9-a3dad83ce944\scratchpad\ffuf_testserver.py"
WORDLIST = r"C:\Users\user\AppData\Local\Temp\claude\E--temp\cde5e06e-b8b1-45d0-aad9-a3dad83ce944\scratchpad\ffuf_wordlist.txt"
PORT = 8833

server = subprocess.Popen([sys.executable, TESTSERVER, str(PORT)])
time.sleep(1)

try:
    target = ScanTarget(value=f"http://127.0.0.1:{PORT}/FUZZ", scope_host="127.0.0.1")
    wrapper = FfufWrapper(HttpSafetyPolicy(max_concurrent_requests=5, timeout_seconds=5, max_request_count=100))

    argv = wrapper.build_command(target, wordlist=WORDLIST)
    print("argv:", argv)
    assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
    assert "--output-file" not in argv, "must rely on stdout, same as the real Orchestrator call path"

    # extension-injection guard
    try:
        wrapper.build_command(target, wordlist=WORDLIST, extensions="php; rm -rf /")
        raise AssertionError("expected ValueError for invalid extensions characters")
    except ValueError as e:
        print("extension injection guard OK:", e)

    # spec review finding (2026-09-06): wordlist_limit used to clamp only
    # against a hardcoded 20000 ceiling, not the actual policy.max_request_count
    # (here 100) -- confirm a caller can no longer request more than policy allows.
    argv_over = wrapper.build_command(target, wordlist=WORDLIST, wordlist_limit=15000)
    limit_i = argv_over.index("--wordlist-limit")
    print("wordlist-limit for an over-budget request:", argv_over[limit_i + 1])
    assert argv_over[limit_i + 1] == "100", "wordlist_limit must be clamped to policy.max_request_count"
    print("wordlist_limit policy clamp OK")

    result, findings = wrapper.run(target, timeout=30, wordlist=WORDLIST)
    print("exit_code:", result.exit_code, "timed_out:", result.timed_out, "duration:", round(result.duration_seconds, 1))
    assert result.exit_code == 0
    assert not result.timed_out
    assert result.stdout.strip()
    assert "[진행]" not in result.stdout and "[발견]" not in result.stdout, (
        "live progress commentary must not leak onto stdout -- this is exactly the bug fixed in ffuf_scanner.py"
    )

    print("findings:", [(f.finding, f.severity.value) for f in findings])
    assert len(findings) == 3
    assert {f.severity for f in findings} == {Severity.LOW}
    assert all(f.scanner == "ffuf" for f in findings)
    urls_found = {f.finding for f in findings}
    assert any("/admin" in u for u in urls_found)
    assert any("/secret.txt" in u for u in urls_found)
    assert any("/robots.txt" in u for u in urls_found)

    print("\nALL FFUF WRAPPER TESTS OK")
finally:
    server.terminate()
    server.wait(timeout=5)
