import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safety.policy import HttpSafetyPolicy
from storage.models import ScanTarget
from wrappers.base import WrapperResult
from wrappers.ffuf_wrapper import FfufWrapper
from wrappers.gobuster_wrapper import GobusterWrapper

target = ScanTarget(value="http://192.168.0.12:3000", scope_host="192.168.0.12")
redirect = {"url": target.value + "/admin", "status": 307, "size": 28, "length": 28,
            "redirect": "/login?callbackUrl=%2Fadmin"}
ok = {"url": target.value + "/exposed.txt", "status": 200, "size": 12, "length": 12}

gobuster_result = WrapperResult(0, json.dumps({"hits": [redirect, ok]}), "", False, 0.1)
gobuster_findings = GobusterWrapper(HttpSafetyPolicy()).parse_result(gobuster_result, target)
assert len(gobuster_findings) == 1 and "exposed.txt" in gobuster_findings[0].finding

ffuf_result = WrapperResult(0, json.dumps({"actionable_results": [redirect, ok]}), "", False, 0.1)
ffuf_findings = FfufWrapper(HttpSafetyPolicy()).parse_result(ffuf_result, target)
assert len(ffuf_findings) == 1 and "exposed.txt" in ffuf_findings[0].finding

print("redirect observations are not promoted to vulnerabilities: PASS")
