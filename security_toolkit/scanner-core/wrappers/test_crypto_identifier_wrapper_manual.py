import base64
import hashlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safety.policy import HttpSafetyPolicy
from storage.models import ScanTarget, Severity
from wrappers.crypto_identifier_wrapper import CryptoIdentifierWrapper

wrapper = CryptoIdentifierWrapper(HttpSafetyPolicy(timeout_seconds=30))

# -- decode-chain path (no crack) ------------------------------------------
b64_value = base64.b64encode(b"hello world").decode()
target = ScanTarget(value=b64_value)

argv = wrapper.build_command(target)
print("argv:", argv)
assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
assert "--crack" not in argv

try:
    wrapper.build_command(ScanTarget(value=""))
    raise AssertionError("expected ValueError for empty value")
except ValueError as e:
    print("missing-value guard OK:", e)

result, findings = wrapper.run(target, timeout=30)
print("exit_code:", result.exit_code, "timed_out:", result.timed_out)
assert result.exit_code == 0
assert not result.timed_out
print("findings:", [(f.finding, f.severity.value, f.evidence) for f in findings])
assert any(f.finding.startswith("Decoded via base64") and "hello world" in f.evidence for f in findings)
assert all(f.scanner == "crypto_identifier" for f in findings)
print("CryptoIdentifierWrapper decode-chain OK")

# -- fast unsalted digest crack (real dictionary attack) -------------------
wl = Path(tempfile.mkdtemp(prefix="crypto_wl_")) / "wordlist.txt"
wl.write_text("password\n123456\nadmin\n", encoding="utf-8")
md5_of_admin = hashlib.md5(b"admin").hexdigest()
hash_target = ScanTarget(value=md5_of_admin)

result2, findings2 = wrapper.run(hash_target, timeout=30, crack=True, wordlist=str(wl))
print("crack exit_code:", result2.exit_code)
assert result2.exit_code == 0
print("crack findings:", [(f.finding, f.severity.value) for f in findings2])
cracked = [f for f in findings2 if "cracked" in f.finding]
assert len(cracked) == 1
assert cracked[0].severity == Severity.HIGH
assert "'admin'" in cracked[0].finding
print("CryptoIdentifierWrapper crack OK")

print("\nALL CRYPTO IDENTIFIER WRAPPER TESTS OK")
