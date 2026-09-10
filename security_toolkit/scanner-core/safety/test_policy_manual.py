import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safety.policy import DEFAULT_POLICY, HttpSafetyPolicy, MODULE_RISK, SafetyPolicyEngine
from storage.models import RiskLevel

# -- conservative defaults ---------------------------------------------------
print("default policy:", DEFAULT_POLICY)
assert DEFAULT_POLICY.allowed_methods == ("GET", "HEAD")
assert DEFAULT_POLICY.max_requests_per_second <= 10
assert DEFAULT_POLICY.max_concurrent_requests <= 10

# -- validation guards --------------------------------------------------------
for bad_kwargs in [
    {"max_requests_per_second": 0},
    {"max_concurrent_requests": -1},
    {"timeout_seconds": 0},
    {"max_request_count": 0},
    {"max_scan_duration_seconds": 0},
    {"allowed_methods": ()},
]:
    try:
        HttpSafetyPolicy(**bad_kwargs)
        raise AssertionError(f"expected ValueError for {bad_kwargs}")
    except ValueError:
        pass
print("validation guards OK")

engine = SafetyPolicyEngine()

# -- classification -----------------------------------------------------------
assert engine.classify("ssl_tls") == RiskLevel.SAFE
assert engine.classify("ffuf") == RiskLevel.CAUTION
assert engine.classify("totally_unknown_module") == RiskLevel.CAUTION  # classify() itself doesn't fail-closed
print("classify() OK")

# -- evaluate: SAFE / CAUTION registered modules pass (with confirm=True) -----
for m in MODULE_RISK:
    d = engine.evaluate(m, confirm=True)
    assert d.allowed, f"{m} unexpectedly blocked: {d.reason}"
print("all v1 registered modules pass evaluate() OK")

# -- evaluate: CAUTION requires explicit confirm (spec review finding 2026-09-06:
# CAUTION used to be auto-allowed exactly like SAFE, no separate confirmation step
# even for data-changing modules like xss_stored) -----------------------------
assert engine.classify("ffuf") == RiskLevel.CAUTION
d_no_confirm = engine.evaluate("ffuf")  # confirm defaults to False
assert not d_no_confirm.allowed
assert "confirm" in d_no_confirm.reason
print("CAUTION without confirm blocked OK:", d_no_confirm.reason)
d_confirmed = engine.evaluate("ffuf", confirm=True)
assert d_confirmed.allowed
print("CAUTION with confirm=True allowed OK")

assert engine.classify("ssl_tls") == RiskLevel.SAFE
assert engine.evaluate("ssl_tls").allowed, "SAFE modules must not require confirm"
print("SAFE module needs no confirm OK")

# -- evaluate: unregistered module fails closed --------------------------------
d = engine.evaluate("totally_unknown_module")
assert not d.allowed
assert "알 수 없는" in d.reason
print("unregistered module fail-closed OK:", d.reason)

# -- evaluate: BLOCKED module is always refused --------------------------------
MODULE_RISK["dos_probe"] = RiskLevel.BLOCKED
d = engine.evaluate("dos_probe")
assert not d.allowed
assert d.risk == RiskLevel.BLOCKED
print("BLOCKED module refused OK:", d.reason)
del MODULE_RISK["dos_probe"]

# -- method policy --------------------------------------------------------------
assert engine.check_method("GET")
assert engine.check_method("head")
assert not engine.check_method("POST")
assert not engine.check_method("DELETE")
print("method policy OK")

# -- per-module method policy (spec review finding 2026-09-06: xss_reflected/
# xss_stored expose a method param that was never checked against anything) ---
d = engine.check_module_method("xss_reflected", "get")
assert d.allowed
d = engine.check_module_method("xss_stored", "post-form")
assert d.allowed, "xss_stored's default post-form must remain allowed -- it's the whole point of that scanner"
d = engine.check_module_method("xss_reflected", "delete")
assert not d.allowed
assert "delete" in d.reason
print("per-module method policy OK:", d.reason)
# a module with no explicit override falls back to the blanket GET/HEAD default
d = engine.check_module_method("crawler", "POST")
assert not d.allowed
d = engine.check_module_method("crawler", "GET")
assert d.allowed
print("per-module method fallback to default policy OK")

# -- request budget -------------------------------------------------------------
ok = engine.check_request_budget(100)
assert ok.allowed
over = engine.check_request_budget(10_000)
assert not over.allowed
assert "초과" in over.reason
print("request budget OK:", over.reason)

print("\nALL SAFETY POLICY TESTS OK")
