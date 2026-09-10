import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzers.technology import extract_from_infra_vuln
from storage.models import Technology

raw_ports = [
    {
        "port": 8080, "protocol": "tcp", "state": "open", "service_name": "http",
        "product": "Apache httpd", "version": "2.4.49", "extrainfo": "", "cpe": ["cpe:/a:apache:http_server:2.4.49"],
        "script_findings": [], "version_rule_hits": [],
    },
    {
        "port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh",
        "product": "OpenSSH", "version": "9.6", "extrainfo": "", "cpe": [],
        "script_findings": [], "version_rule_hits": [],
    },
    {
        "port": 9999, "protocol": "tcp", "state": "closed", "service_name": "",
        "product": "", "version": "", "extrainfo": "", "cpe": [],
        "script_findings": [], "version_rule_hits": [],
    },
]

techs = extract_from_infra_vuln(raw_ports, host="example.com", scan_id="scan-1")
print("extracted:", [(t.product, t.version, t.port, t.cpe) for t in techs])
assert len(techs) == 2, "closed port with no product must not become a Technology"
assert all(isinstance(t, Technology) for t in techs)
apache = next(t for t in techs if t.product == "Apache httpd")
assert apache.version == "2.4.49"
assert apache.port == 8080
assert apache.category == "service"
assert apache.source_scanner == "infra_vuln"
assert apache.scan_id == "scan-1"
assert apache.cpe == ["cpe:/a:apache:http_server:2.4.49"]

d = apache.to_dict()
apache2 = Technology.from_dict(d)
assert apache2 == apache
print("round-trip OK")

print("\nALL TECHNOLOGY DETECTION TESTS OK")
