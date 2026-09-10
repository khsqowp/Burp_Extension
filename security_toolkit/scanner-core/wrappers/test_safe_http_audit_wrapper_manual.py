from __future__ import annotations

import json

from storage.models import ScanTarget
from wrappers.base import WrapperResult
from wrappers.safe_http_audit_wrapper import SAFE_AUDIT_WRAPPERS


target = ScanTarget("http://example.test:3000", "example.test")
expected = {
    "error_page_disclosure", "http_methods", "directory_listing",
    "server_header", "security_headers", "subdomain_discovery",
    "virtual_host_isolation",
}
assert {wrapper.module for wrapper in SAFE_AUDIT_WRAPPERS} == expected

for wrapper_cls in SAFE_AUDIT_WRAPPERS:
    wrapper = wrapper_cls()
    command = wrapper.build_command(target)
    assert command[-2:] == ["--check", wrapper.module]
    assert isinstance(command, list)

payload = {
    "findings": [{
        "severity": "medium", "message": "가상 호스트 분리가 미흡합니다.",
        "evidence": "status=200",
    }]
}
wrapper = next(item() for item in SAFE_AUDIT_WRAPPERS if item.module == "virtual_host_isolation")
findings = wrapper.parse_result(WrapperResult(0, json.dumps(payload), "", False, 0.1), target)
assert len(findings) == 1
assert findings[0].scanner == "virtual_host_isolation"
assert findings[0].severity.value == "medium"

print("SAFE HTTP AUDIT WRAPPER TESTS OK")
