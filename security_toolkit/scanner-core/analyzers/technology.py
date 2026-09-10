"""Technology Detection (spec §16) -- normalizes each wrapper's own raw
product/version signals into a shared Technology list that the CVE/EOS-EOL
Matchers (Phase 3, spec §19/§21) can consume uniformly.

Only extracts from signals a wrapper's raw output already contains --
never guesses or invents a product/version that wasn't actually observed.
"""

from __future__ import annotations


def extract_from_infra_vuln(raw_ports: list[dict], host: str, scan_id: str = "") -> list["Technology"]:  # noqa: F821
    from storage.models import Technology

    techs: list[Technology] = []
    for port_result in raw_ports:
        product = (port_result.get("product") or "").strip()
        if not product:
            continue
        techs.append(
            Technology(
                product=product, version=(port_result.get("version") or "").strip(),
                category="service", host=host, port=port_result.get("port"),
                evidence=f"{port_result.get('service_name', '')} on port {port_result.get('port')}/"
                         f"{port_result.get('protocol', 'tcp')}",
                source_scanner="infra_vuln", cpe=list(port_result.get("cpe", [])), scan_id=scan_id,
            )
        )
    return techs


def extract_from_js_analyzer(raw_payload: dict, scan_id: str = "") -> list["Technology"]:  # noqa: F821
    from storage.models import Technology

    techs = []
    for t in raw_payload.get("technologies", []):
        tech = Technology.from_dict(t)
        tech.scan_id = scan_id
        techs.append(tech)
    return techs
