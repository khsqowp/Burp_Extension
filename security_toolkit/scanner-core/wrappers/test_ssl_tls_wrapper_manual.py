import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safety.policy import HttpSafetyPolicy
from storage.models import ScanTarget, Severity
from wrappers.base import ToolWrapper, WrapperResult
from wrappers.ssl_tls_wrapper import SSLTLSWrapper

target = ScanTarget(value="https://example.com", scope_host="example.com")

# -- build_command must be a pure list[str] argv, never a shell string -------
wrapper = SSLTLSWrapper(HttpSafetyPolicy(timeout_seconds=5))
argv = wrapper.build_command(target, port=443)
print("argv:", argv)
assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
assert "example.com" in argv
assert "--output" in argv and "json" in argv

# An explicit port in the common target URL must be honored when the caller
# does not supply a TLS-specific override.  Falling back to 443 here caused
# http://host:3000 scans to spend minutes probing the wrong service.
http_target = ScanTarget(value="http://192.168.0.12:3000", scope_host="192.168.0.12")
http_argv = wrapper.build_command(http_target)
http_port_i = http_argv.index("--port")
assert http_argv[http_port_i + 1] == "3000"

# -- interface enforcement: a wrapper returning a bad type must raise --------
class BadWrapper(ToolWrapper):
    module = "bad"
    def build_command(self, target, **kwargs):
        return "not a list -- a shell string"  # deliberately wrong shape
    def parse_result(self, result, target):
        return []

bad = BadWrapper(HttpSafetyPolicy())
try:
    bad.execute(target)
    raise AssertionError("expected TypeError for non-list build_command()")
except TypeError as e:
    print("bad build_command() correctly rejected:", e)

# -- timeout enforcement: a wrapper whose command sleeps past the timeout ----
class SlowWrapper(ToolWrapper):
    module = "slow"
    def build_command(self, target, **kwargs):
        return [sys.executable, "-c", "import time; time.sleep(30)"]
    def parse_result(self, result, target):
        return []

slow = SlowWrapper(HttpSafetyPolicy())
result = slow.execute(target, timeout=1.5)
print("slow wrapper result:", result)
assert result.timed_out is True
assert result.exit_code == -1
assert result.duration_seconds < 10, "process should have been killed near the 1.5s timeout, not run to completion"
print("timeout enforcement OK")

# -- real end-to-end run against a real target (SAFE-classified TLS probe) --
# Uses plain run(), the exact same call Orchestrator.execute_task() makes --
# JSON must arrive on stdout (the real call path never passes --output-file).
result, findings = wrapper.run(target, port=443, timeout=90)
print("real run exit_code:", result.exit_code, "timed_out:", result.timed_out, "duration:", round(result.duration_seconds, 1))
assert result.exit_code == 0
assert not result.timed_out
assert result.stdout.strip(), "JSON must land on stdout -- that's what Orchestrator.execute_task() persists as the raw artifact"
print("parsed findings:", [(f.finding, f.severity.value) for f in findings])
assert len(findings) > 0, "example.com is known to still offer TLSv1.0/1.1 -- expected at least one real Finding"
assert all(f.severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH) for f in findings)
assert all(f.scanner == "ssl_tls" for f in findings)
assert all(f.target == target.value for f in findings)

print("\nALL SSL/TLS WRAPPER TESTS OK")
