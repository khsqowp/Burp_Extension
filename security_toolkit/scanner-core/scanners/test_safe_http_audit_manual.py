from __future__ import annotations

from scanners.safe_http_audit import (
    ResponseEvidence,
    analyze_rule,
    discover_subdomains,
    evaluate_virtual_host_isolation,
)


error_rule = {
    "detections": [{
        "id": "tomcat-default-error",
        "severity": "low",
        "status": [404],
        "body_contains_all_ci": ["type status report", "apache tomcat"],
        "message_ko": "Tomcat 기본 오류 페이지 노출",
    }]
}
response = ResponseEvidence(
    request_method="GET", request_url="http://target/nope", status=404,
    headers={"content-type": "text/html"},
    body="<h1>Type Status Report</h1><p>Apache Tomcat/9.0</p>", error="",
)
assert analyze_rule(error_rule, response)[0]["id"] == "tomcat-default-error"

header_rule = {"detections": [{
    "id": "product-header", "headers_ci": ["server", "x-powered-by"],
    "value_regex_ci": ["next\\.js"], "message_ko": "제품 노출",
}]}
header_response = ResponseEvidence(
    request_method="HEAD", request_url="http://target/", status=200,
    headers={"x-powered-by": "Next.js", "x-padding": "x" * 1000}, body="", error="",
)
assert analyze_rule(header_rule, header_response)[0]["evidence"] == "x-powered-by: Next.js"


resolved = {
    "example.test": ["10.0.0.1"],
    "admin.example.test": ["10.0.0.1"],
    "dev.example.test": ["10.0.0.2"],
}
dns_rows = discover_subdomains(
    "example.test", ["admin", "dev", "missing"],
    resolver=lambda host: resolved.get(host, []), max_candidates=3,
)
assert [row["hostname"] for row in dns_rows] == ["admin.example.test", "dev.example.test"]


assessment = evaluate_virtual_host_isolation(
    base_ips={"10.0.0.1"},
    candidates=dns_rows,
    probes={
        "admin.example.test": {"status": 200, "fingerprint": "admin-a"},
        "__random__.example.test": {"status": 404, "fingerprint": "fallback"},
    },
)
assert assessment[0]["classification"] == "same_ip_admin_exposure"
assert assessment[0]["severity"] == "info"


print("SAFE HTTP AUDIT TESTS OK")
