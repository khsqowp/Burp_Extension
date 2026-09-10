import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safety.policy import HttpSafetyPolicy
from storage.models import ScanTarget, Severity
from wrappers.base import WrapperResult
from wrappers.infra_vuln_wrapper import InfraVulnWrapper

target = ScanTarget(value="127.0.0.1", scope_host="127.0.0.1")
wrapper = InfraVulnWrapper(HttpSafetyPolicy(max_scan_duration_seconds=60))

# -- build_command shape ------------------------------------------------------
argv = wrapper.build_command(target, ports="80,443", no_vuln_scripts=True)
print("argv:", argv)
assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
assert "--ports" in argv and "80,443" in argv
assert "--no-vuln-scripts" in argv
assert "--nmap-timeout" in argv and "60" in argv

argv2 = wrapper.build_command(target, top_ports=50)
assert "--top-ports" in argv2 and "50" in argv2
assert "--ports" not in argv2

# -- parse_result: synthetic JSON matching the real schema (script_findings +
# version_rule_hits) -- exercised as a unit test since safely reproducing a
# genuinely vulnerable live service isn't practical here.
fake_json = json.dumps([
    {
        "port": 8080, "protocol": "tcp", "state": "open", "service_name": "http",
        "product": "Apache httpd", "version": "2.4.49", "extrainfo": "", "cpe": [],
        "script_findings": [{"script_id": "http-vuln-cve2021-41773", "state": "VULNERABLE", "output": "proof of concept exploit succeeded"}],
        "version_rule_hits": [{"product_substr": "apache httpd", "max_safe_version": "2.4.51", "note": "2.4.49/2.4.50 경로 순회+RCE", "cve_refs": ["CVE-2021-41773", "CVE-2021-42013"]}],
    },
    {
        "port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh",
        "product": "OpenSSH", "version": "9.6", "extrainfo": "", "cpe": [],
        "script_findings": [], "version_rule_hits": [],
    },
])
fake_result = WrapperResult(exit_code=0, stdout=fake_json, stderr="", timed_out=False, duration_seconds=1.0)
findings = wrapper.parse_result(fake_result, target)
print("synthetic findings:", [(f.finding, f.severity.value, f.port, f.evidence) for f in findings])
assert len(findings) == 2, "expected 1 script_finding + 1 version_rule_hit, and NOTHING from the clean port 22"
assert all(f.severity == Severity.HIGH for f in findings)
assert any("http-vuln-cve2021-41773" in f.finding for f in findings)
assert any("CVE-2021-41773" in f.evidence for f in findings)
assert all(f.port == 8080 for f in findings), "port 22 (no hits) must not produce any Finding"
print("parse_result unit test OK")

# -- real end-to-end run (fast: --no-vuln-scripts, tiny port range) ----------
# Note: nmap's XML collapses a long run of same-state ports into a single
# <extraports> summary (no individual <port> elements), which the underlying
# tool's XML parser doesn't expand -- a wide, all-closed range like 1-100
# legitimately parses to an empty list. A short, non-contiguous selector
# avoids that collapse and gives a real per-port listing to check against.
result, real_findings = wrapper.run(target, timeout=60, ports="80,443,8821-8825", no_vuln_scripts=True)
print("real run exit_code:", result.exit_code, "timed_out:", result.timed_out, "duration:", round(result.duration_seconds, 1))
assert result.exit_code == 0
assert not result.timed_out
assert result.stdout.strip()
raw = json.loads(result.stdout)
print("real scan ports checked:", len(raw))
assert len(raw) > 0
assert all("port" in p and "state" in p for p in raw)
print("real findings (likely empty -- no NSE scripts ran):", real_findings)

print("\nALL INFRA_VULN (nmap) WRAPPER TESTS OK")
