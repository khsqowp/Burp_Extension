import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safety.policy import HttpSafetyPolicy
from storage.models import ScanTarget, Severity
from wrappers.crawler_wrapper import CrawlerWrapper

TESTSERVER = r"C:\Users\user\AppData\Local\Temp\claude\E--temp\cde5e06e-b8b1-45d0-aad9-a3dad83ce944\scratchpad\crawler_testserver.py"
PORT = 8802

server = subprocess.Popen([sys.executable, TESTSERVER, str(PORT)])
time.sleep(1)

try:
    target = ScanTarget(value=f"http://127.0.0.1:{PORT}", scope_host="127.0.0.1")
    wrapper = CrawlerWrapper(HttpSafetyPolicy(max_crawl_depth=3, max_request_count=20, timeout_seconds=2))

    argv = wrapper.build_command(target)
    print("argv:", argv)
    assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
    assert "--depth" in argv and "3" in argv
    assert "--max-pages" in argv and "20" in argv
    assert "--output-file" not in argv, "must rely on stdout, same as the real Orchestrator call path"

    # spec review finding (2026-09-06): a caller-supplied depth/max_pages used
    # to be passed straight through with no clamp at all -- confirm the policy
    # ceiling now applies even when the caller explicitly asks for more.
    argv_over = wrapper.build_command(target, depth=999, max_pages=999999)
    print("argv (over-budget request):", argv_over)
    depth_i = argv_over.index("--depth")
    pages_i = argv_over.index("--max-pages")
    assert argv_over[depth_i + 1] == "3", "depth must be clamped to policy.max_crawl_depth, not passed through as 999"
    assert argv_over[pages_i + 1] == "20", "max_pages must be clamped to policy.max_request_count, not passed through as 999999"
    print("depth/max_pages policy clamp OK")

    # 127.0.0.1:1 (the test page's dead link) is same-host/different-port, so
    # the crawler's same-host scoping still follows it -- this is a real,
    # naturally-occurring fetch error, not a contrived one.
    result, findings = wrapper.run(target, timeout=30)
    print("exit_code:", result.exit_code, "timed_out:", result.timed_out, "duration:", round(result.duration_seconds, 1))
    assert result.exit_code == 0
    assert not result.timed_out
    assert result.stdout.strip(), "real Orchestrator flow depends on JSON landing on stdout, not just a file"

    data = json.loads(result.stdout)
    print("pages discovered:", [p["url"] for p in data["pages"]])
    urls = {p["url"] for p in data["pages"]}
    assert f"http://127.0.0.1:{PORT}/" in urls
    assert f"http://127.0.0.1:{PORT}/about" in urls
    assert f"http://127.0.0.1:{PORT}/admin" in urls
    assert f"http://127.0.0.1:{PORT}/contact" in urls
    assert "http://127.0.0.1:1/dead" in urls

    # This is exactly the case that would have silently vanished if
    # parse_result() were reading from a file the tool never wrote to
    # (--output-file was never passed), instead of stdout.
    print("findings (must be non-empty -- the dead link is a real fetch error):", [(f.finding, f.severity.value, f.evidence) for f in findings])
    assert len(findings) >= 1
    assert all(f.severity == Severity.LOW for f in findings)
    assert all(f.scanner == "crawler" for f in findings)
    assert all(f.target == target.value for f in findings)

    print("\nALL CRAWLER WRAPPER TESTS OK")
finally:
    server.terminate()
    server.wait(timeout=5)
