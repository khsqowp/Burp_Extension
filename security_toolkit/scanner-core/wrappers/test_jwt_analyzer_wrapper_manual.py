import base64
import hashlib
import hmac
import json
import sys
import tempfile
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safety.policy import HttpSafetyPolicy
from storage.models import ScanTarget, Severity
from wrappers.jwt_analyzer_wrapper import JwtAnalyzerWrapper


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


header = _b64u(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "x"}, separators=(",", ":")).encode())
payload = _b64u(json.dumps({"sub": "1234567890", "name": "test"}, separators=(",", ":")).encode())
sig = hmac.new(b"secret", f"{header}.{payload}".encode(), hashlib.sha256).digest()
token = f"{header}.{payload}.{_b64u(sig)}"

wrapper = JwtAnalyzerWrapper(HttpSafetyPolicy(timeout_seconds=30))
target = ScanTarget(value=token)

# -- structural analysis only --------------------------------------------
argv = wrapper.build_command(target, gen_none=True)
print("argv:", argv)
assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
assert "--gen-none" in argv

try:
    wrapper.build_command(ScanTarget(value=""))
    raise AssertionError("expected ValueError for empty token")
except ValueError as e:
    print("missing-token guard OK:", e)

result, findings = wrapper.run(target, timeout=30, gen_none=True)
print("exit_code:", result.exit_code, "timed_out:", result.timed_out)
assert result.exit_code == 0
assert not result.timed_out
print("findings:", [(f.finding, f.severity.value) for f in findings])
assert any("kid" in f.finding and f.severity == Severity.MEDIUM for f in findings), "expected kid header WARNING->MEDIUM finding"
assert any("exp" in f.finding and f.severity == Severity.MEDIUM for f in findings), "expected missing-exp WARNING->MEDIUM finding"
assert all(f.scanner == "jwt_analyzer" for f in findings)
print("JwtAnalyzerWrapper structural analysis OK")

# -- weak-secret crack (real HMAC brute force against a small wordlist) --
wl = Path(tempfile.mkdtemp(prefix="jwt_wl_")) / "wordlist.txt"
wl.write_text("password\n123456\nsecret\nadmin\n", encoding="utf-8")

result2, findings2 = wrapper.run(target, timeout=30, crack_secret=True, wordlist=str(wl))
print("crack exit_code:", result2.exit_code)
assert result2.exit_code == 0
print("crack findings:", [(f.finding, f.severity.value) for f in findings2])
cracked = [f for f in findings2 if "cracked" in f.finding]
assert len(cracked) == 1
assert cracked[0].severity == Severity.HIGH
assert "'secret'" in cracked[0].finding
print("JwtAnalyzerWrapper crack-secret OK")

print("\nALL JWT ANALYZER WRAPPER TESTS OK")
