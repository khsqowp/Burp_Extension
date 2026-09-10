"""Read-only HTTP configuration, subdomain, and virtual-host checks.

The module deliberately has no passive-OSINT providers, browser session,
cookie jar, redirect support, or state-changing HTTP methods.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import random
import re
import socket
import string
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from safety.safe_rule_bundle import load_verified_bundle


BUNDLE_DIR = Path(__file__).resolve().parents[2] / "safe_http_checks"
SAFE_CHECKS = {
    "error_page_disclosure": "error-page-signatures",
    "http_methods": "allowed-methods",
    "directory_listing": "directory-listing",
    "server_header": "server-header-disclosure",
    "security_headers": "security-headers",
}
DEFAULT_SUBDOMAIN_LABELS = (
    "admin", "administrator", "manage", "management", "console", "portal",
    "internal", "intranet", "dev", "development", "stage", "staging",
    "test", "qa", "api", "auth", "sso", "vpn", "monitor", "status",
)
ADMIN_LABELS = {"admin", "administrator", "manage", "management", "console", "portal", "internal", "intranet"}
MAX_BODY_BYTES = 256 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


@dataclass
class ResponseEvidence:
    request_method: str
    request_url: str
    status: int | None
    headers: dict[str, str]
    body: str
    error: str

    def to_dict(self) -> dict:
        return asdict(self)


def _contains_all(text: str, values: list[str]) -> bool:
    lowered = text.lower()
    return all(value.lower() in lowered for value in values)


def _contains_any(text: str, values: list[str]) -> bool:
    lowered = text.lower()
    return any(value.lower() in lowered for value in values)


def analyze_rule(rule: dict, response: ResponseEvidence) -> list[dict]:
    """Apply the small local matcher vocabulary to one preserved response."""
    findings: list[dict] = []
    headers = {key.lower(): value for key, value in response.headers.items()}
    header_blob = "\n".join(f"{key}: {value}" for key, value in headers.items())
    for detection in rule.get("detections", []):
        matched_headers: dict[str, str] = {}
        statuses = detection.get("status")
        if statuses and response.status not in statuses:
            continue
        if detection.get("content_type_contains_ci", "").lower() not in headers.get("content-type", "").lower():
            if detection.get("content_type_contains_ci"):
                continue
        if detection.get("body_contains_all_ci") and not _contains_all(response.body, detection["body_contains_all_ci"]):
            continue
        if detection.get("body_contains_any_ci") and not _contains_any(response.body, detection["body_contains_any_ci"]):
            continue
        if detection.get("body_regex_ci") and not any(re.search(pattern, response.body, re.I) for pattern in detection["body_regex_ci"]):
            continue
        if detection.get("when_scheme") and not response.request_url.lower().startswith(detection["when_scheme"] + "://"):
            continue
        if detection.get("missing_header_ci") and detection["missing_header_ci"].lower() in headers:
            continue
        if detection.get("missing_headers_all_ci") and any(name.lower() in headers for name in detection["missing_headers_all_ci"]):
            continue
        if detection.get("header_ci"):
            value = headers.get(detection["header_ci"].lower())
            if value is None:
                continue
            if detection.get("value_contains_any_ci") and not _contains_any(value, detection["value_contains_any_ci"]):
                continue
        if detection.get("headers_ci"):
            matching = {name: headers[name.lower()] for name in detection["headers_ci"] if name.lower() in headers}
            if not matching:
                continue
            if detection.get("value_regex_ci"):
                matching = {
                    name: value for name, value in matching.items()
                    if any(re.search(pattern, value, re.I) for pattern in detection["value_regex_ci"])
                }
                if not matching:
                    continue
            matched_headers = matching
        if detection.get("inspect_headers_ci"):
            inspected = " ".join(headers.get(name.lower(), "") for name in detection["inspect_headers_ci"])
            risky = [value for value in detection.get("risky_values_ci", []) if re.search(rf"\b{re.escape(value)}\b", inspected, re.I)]
            if not risky:
                continue
            matched_headers = {
                name: headers[name.lower()] for name in detection["inspect_headers_ci"]
                if name.lower() in headers
            }
        evidence = response.body[:500] if response.body else header_blob[:500]
        if matched_headers:
            evidence = "\n".join(f"{name}: {value}" for name, value in matched_headers.items())[:500]
        findings.append({
            "id": detection["id"], "severity": detection.get("severity", "info"),
            "message": detection.get("message_ko", detection["id"]), "evidence": evidence,
        })
    return findings


def _target_url(raw: str) -> str:
    value = raw.strip()
    if "://" not in value:
        value = "http://" + value
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("target must be an http(s) URL without credentials")
    _ = parsed.port
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _fetch(method: str, url: str, timeout: int) -> ResponseEvidence:
    if method not in {"GET", "HEAD", "OPTIONS"}:
        raise ValueError("state-changing HTTP method rejected")
    request = urllib.request.Request(
        url, method=method,
        headers={"User-Agent": "security-toolkit-safe-audit/1.0", "Accept": "text/html,*/*;q=0.1"},
    )
    # Ignore HTTP(S)_PROXY environment variables.  A diagnostic request must
    # go only to the explicitly selected target, never through an unrelated
    # corporate/developer proxy that could receive the URL or response.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_BODY_BYTES).decode("utf-8", errors="replace") if method == "GET" else ""
            return ResponseEvidence(method, url, response.status, dict(response.headers.items()), body, "")
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY_BYTES).decode("utf-8", errors="replace") if method == "GET" else ""
        return ResponseEvidence(method, url, exc.code, dict(exc.headers.items()), body, "")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return ResponseEvidence(method, url, None, {}, "", str(exc))


def discover_subdomains(
    domain: str, labels: list[str] | tuple[str, ...], *,
    resolver: Callable[[str], list[str]] | None = None, max_candidates: int = 20,
) -> list[dict]:
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain.lower()):
        raise ValueError("subdomain discovery requires a DNS domain, not an IP or single-label host")
    if not 1 <= max_candidates <= 25:
        raise ValueError("max_candidates must be 1..25")

    def system_resolver(host: str) -> list[str]:
        return sorted({row[4][0] for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})

    resolve = resolver or system_resolver
    results: list[dict] = []
    seen: set[str] = set()
    for label in list(labels)[:max_candidates]:
        normalized = label.strip().lower()
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", normalized):
            continue
        hostname = f"{normalized}.{domain.lower()}"
        try:
            addresses = resolve(hostname)
        except OSError:
            addresses = []
        if addresses and hostname not in seen:
            seen.add(hostname)
            results.append({"hostname": hostname, "label": normalized, "addresses": addresses})
    return results


def evaluate_virtual_host_isolation(base_ips: set[str], candidates: list[dict], probes: dict[str, dict]) -> list[dict]:
    assessments: list[dict] = []
    fallback = next((value for key, value in probes.items() if key.startswith("__random__.")), None)
    for candidate in candidates:
        hostname = candidate["hostname"]
        probe = probes.get(hostname)
        if not probe or not base_ips.intersection(candidate.get("addresses", [])):
            continue
        if candidate.get("label") in ADMIN_LABELS and probe.get("status") and probe["status"] < 500:
            assessments.append({
                "classification": "same_ip_admin_exposure", "severity": "info", "hostname": hostname,
                "message": "관리자 기능으로 추정되는 서브도메인이 기준 도메인과 같은 IP에서 외부 요청에 응답합니다. 동일 IP 자체는 취약점이 아니므로 인증과 네트워크 접근통제를 추가 확인해야 합니다.",
            })
        if fallback and probe.get("fingerprint") and probe.get("fingerprint") == fallback.get("fingerprint"):
            assessments.append({
                "classification": "arbitrary_host_fallback", "severity": "medium", "hostname": hostname,
                "message": "등록되지 않은 Host 값에도 관리자 후보와 동일한 응답이 반환되어 기본 가상 호스트 분리가 미흡할 수 있습니다.",
            })
    return assessments


def _resolve(host: str) -> list[str]:
    return sorted({row[4][0] for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})


def _head_with_host(ip: str, port: int, host_header: str, timeout: int) -> dict:
    connection = http.client.HTTPConnection(ip, port, timeout=timeout)
    try:
        connection.request("HEAD", "/", headers={"Host": host_header, "User-Agent": "security-toolkit-safe-audit/1.0"})
        response = connection.getresponse()
        headers = {key.lower(): value for key, value in response.getheaders()}
        material = json.dumps({"status": response.status, "headers": headers}, sort_keys=True).encode()
        return {"status": response.status, "headers": headers, "fingerprint": hashlib.sha256(material).hexdigest()}
    except OSError as exc:
        return {"status": None, "headers": {}, "fingerprint": "", "error": str(exc)}
    finally:
        connection.close()


def run_check(target: str, check: str, max_candidates: int = 20) -> dict:
    started = time.time()
    normalized = _target_url(target)
    parsed = urlsplit(normalized)
    raw: list[dict] = []
    findings: list[dict] = []
    observations: list[dict] = []

    if check in SAFE_CHECKS:
        rule = load_verified_bundle(BUNDLE_DIR)[SAFE_CHECKS[check]]
        token = "".join(random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(12))
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for index, request in enumerate(rule["requests"]):
            if index:
                time.sleep(1.0 / rule["limits"]["requests_per_second"])
            path = request["path"].replace("{random_token}", token)
            response = _fetch(request["method"], origin + path, rule["limits"]["timeout_seconds"])
            raw.append(response.to_dict())
            findings.extend(analyze_rule(rule, response))
            if response.error:
                observations.append({"type": "request_error", "message": response.error, "url": response.request_url})
    else:
        if parsed.hostname is None or re.fullmatch(r"\d+(?:\.\d+){3}", parsed.hostname):
            raise ValueError("subdomain checks require a domain-name target")
        domain = parsed.hostname.lower()
        base_ips = set(_resolve(domain))
        candidates = discover_subdomains(domain, DEFAULT_SUBDOMAIN_LABELS, max_candidates=max_candidates)
        raw.append({"type": "dns", "domain": domain, "base_addresses": sorted(base_ips), "candidates": candidates})
        if check == "subdomain_discovery":
            observations.extend(candidates)
        elif check == "virtual_host_isolation":
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if parsed.scheme != "http":
                observations.append({"type": "not_applicable", "message": "HTTPS Host/SNI 혼합 검사는 안전한 기본 모드에서 수행하지 않습니다."})
            else:
                same_ip = [row for row in candidates if base_ips.intersection(row["addresses"])]
                probes: dict[str, dict] = {}
                for row in same_ip[:5]:
                    probes[row["hostname"]] = _head_with_host(next(iter(base_ips)), port, row["hostname"], 10)
                    time.sleep(1.0)
                random_host = f"__random__.{domain}"
                probes[random_host] = _head_with_host(next(iter(base_ips)), port, random_host, 10)
                raw.append({"type": "http_head_host_checks", "probes": probes})
                assessments = evaluate_virtual_host_isolation(base_ips, same_ip, probes)
                findings.extend(row for row in assessments if row.get("severity") != "info")
                observations.extend(row for row in assessments if row.get("severity") == "info")
        else:
            raise ValueError(f"unknown check: {check}")

    return {
        "check": check, "target": normalized, "status": "completed",
        "summary": {"finding_count": len(findings), "observation_count": len(observations)},
        "findings": findings, "observations": observations, "raw": raw,
        "duration_seconds": round(time.time() - started, 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only safe HTTP configuration audit")
    parser.add_argument("target")
    parser.add_argument("--check", required=True, choices=[*SAFE_CHECKS, "subdomain_discovery", "virtual_host_isolation"])
    parser.add_argument("--max-candidates", type=int, default=20)
    args = parser.parse_args()
    try:
        print(json.dumps(run_check(args.target, args.check, args.max_candidates), ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(str(exc), file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
