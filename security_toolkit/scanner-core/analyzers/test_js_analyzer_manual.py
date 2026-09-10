import http.server
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzers.js_analyzer import JsAnalyzer
from analyzers.technology import extract_from_js_analyzer
from safety.policy import HttpSafetyPolicy
from storage.models import ScanTarget, Severity

FIXTURE = b'''/* jQuery v3.4.1 */
fetch("/api/v1/users/list"); fetch("/api/v1/orders/export");
const aws = "AKIA1234567890ABCDEF";
const apiKey = "abcdefghijklmnopqrstuvwx";
'''


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript")
        self.send_header("Content-Length", str(len(FIXTURE)))
        self.end_headers()
        self.wfile.write(FIXTURE)

    def log_message(self, format, *args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
PORT = server.server_address[1]
server_thread = threading.Thread(target=server.serve_forever, daemon=True)
server_thread.start()

try:
    target = ScanTarget(value=f"http://127.0.0.1:{PORT}/", scope_host="127.0.0.1")
    analyzer = JsAnalyzer(HttpSafetyPolicy(timeout_seconds=5))

    # build_command must be explicitly unsupported (this analyzer never spawns a subprocess)
    try:
        analyzer.build_command(target)
        raise AssertionError("expected NotImplementedError")
    except NotImplementedError:
        print("build_command correctly unsupported OK")

    try:
        analyzer.run(target)
        raise AssertionError("expected ValueError when js_url is missing")
    except ValueError as e:
        print("missing js_url guard OK:", e)

    result, findings = analyzer.run(target, js_url=f"http://127.0.0.1:{PORT}/app.js", timeout=10)
    print("exit_code:", result.exit_code, "duration:", round(result.duration_seconds, 2))
    assert result.exit_code == 0
    assert not result.timed_out
    assert result.stdout.strip()

    import json
    payload = json.loads(result.stdout)
    print("path_candidates:", payload["path_candidates"])
    assert any("/api/v1/users/list" in c for c in payload["path_candidates"])
    assert any("/api/v1/orders/export" in c for c in payload["path_candidates"])

    print("technologies:", payload["technologies"])
    assert len(payload["technologies"]) == 1
    assert payload["technologies"][0]["product"] == "jquery"
    assert payload["technologies"][0]["version"] == "3.4.1"

    print("findings:", [(f.finding, f.severity.value) for f in findings])
    assert len(findings) == 2, "expected both the AWS key and the generic apiKey pattern to be flagged"
    assert all(f.severity == Severity.HIGH for f in findings)
    assert any("AWS" in f.finding for f in findings)
    assert any("API key" in f.finding or "api_key" in f.finding.lower() or "토큰" in f.finding for f in findings)

    # -- Technology extraction feeding into CVE/EOL matchers --------------------
    techs = extract_from_js_analyzer(payload, scan_id="scan-x")
    assert len(techs) == 1
    assert techs[0].product == "jquery"
    assert techs[0].version == "3.4.1"
    assert techs[0].scan_id == "scan-x"
    print("Technology extraction for matcher reuse OK")

    # -- unreachable JS URL must fail cleanly, not crash --------------------------
    bad_result, bad_findings = analyzer.run(target, js_url="http://127.0.0.1:1/nope.js", timeout=3)
    print("unreachable url result:", bad_result.exit_code, bad_findings)
    assert bad_result.exit_code != 0
    assert bad_findings == []

    print("\nALL JS ANALYZER TESTS OK")
finally:
    server.shutdown()
    server.server_close()
    server_thread.join(timeout=5)
