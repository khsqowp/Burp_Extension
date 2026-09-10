"""Fail-closed loader for the locally curated, read-only HTTP rule bundle."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}
ALLOWED_RULE_IDS = {
    "allowed-methods",
    "directory-listing",
    "error-page-signatures",
    "security-headers",
    "server-header-disclosure",
}
FORBIDDEN_TEXT = re.compile(
    r"(?i)(?:https?://|interactsh|(?:^|[^a-z])oast\.(?:fun|pro|me|online)|"
    r"burp\s*collaborator|callback|webhook|telemetry|(?:^|[^a-z])(?:put|delete|patch|connect)\s+/|"
    r"\b(?:dos|race_count|reverse.shell|command.protocol)\b)"
)


class BundleValidationError(ValueError):
    """Raised when a bundle cannot be proven to satisfy the local safety contract."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_rule(rule: dict[str, Any], source: Path) -> None:
    rule_id = rule.get("id")
    if rule.get("schema_version") != 1 or rule_id not in ALLOWED_RULE_IDS:
        raise BundleValidationError(f"{source.name}: unsupported schema or rule id")
    if rule.get("external_network") is not False:
        raise BundleValidationError(f"{source.name}: external_network must be false")

    limits = rule.get("limits") or {}
    if not 1 <= limits.get("max_requests", 0) <= 10:
        raise BundleValidationError(f"{source.name}: max_requests must be 1..10")
    if not 0 < limits.get("requests_per_second", 0) <= 2:
        raise BundleValidationError(f"{source.name}: requests_per_second must be <= 2")
    if limits.get("max_concurrency") != 1:
        raise BundleValidationError(f"{source.name}: max_concurrency must be 1")
    if not 1 <= limits.get("timeout_seconds", 0) <= 15:
        raise BundleValidationError(f"{source.name}: timeout_seconds must be 1..15")
    if limits.get("max_redirects") != 0:
        raise BundleValidationError(f"{source.name}: redirects must be disabled")

    requests = rule.get("requests")
    if not isinstance(requests, list) or not requests or len(requests) > limits["max_requests"]:
        raise BundleValidationError(f"{source.name}: invalid request list")
    for request in requests:
        method = str(request.get("method", "")).upper()
        path = request.get("path")
        if method not in ALLOWED_METHODS:
            raise BundleValidationError(f"{source.name}: forbidden method {method!r}")
        if not isinstance(path, str) or not path.startswith("/") or "://" in path or "\\" in path:
            raise BundleValidationError(f"{source.name}: request path must be target-relative")
        if request.get("send_credentials") is not False:
            raise BundleValidationError(f"{source.name}: credentials must never be sent")

    serialized = json.dumps(rule, ensure_ascii=False, sort_keys=True)
    if FORBIDDEN_TEXT.search(serialized):
        raise BundleValidationError(f"{source.name}: forbidden external or active content")


def load_verified_bundle(bundle_dir: Path) -> dict[str, dict[str, Any]]:
    """Load only files named and hashed by manifest.json, rejecting all drift."""
    bundle_dir = Path(bundle_dir).resolve()
    manifest_path = bundle_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleValidationError("manifest.json is missing or invalid") from exc
    if manifest.get("schema_version") != 1 or manifest.get("auto_update") is not False:
        raise BundleValidationError("manifest must disable automatic updates")

    expected = manifest.get("files")
    if not isinstance(expected, dict) or set(expected) != {f"{item}.json" for item in ALLOWED_RULE_IDS}:
        raise BundleValidationError("manifest file allowlist is incomplete or unexpected")

    actual_json = {path.name for path in bundle_dir.glob("*.json")} - {"manifest.json"}
    if actual_json != set(expected):
        raise BundleValidationError("bundle contains an unregistered or missing rule file")

    loaded: dict[str, dict[str, Any]] = {}
    for filename, expected_hash in sorted(expected.items()):
        path = bundle_dir / filename
        if not re.fullmatch(r"[0-9a-f]{64}", str(expected_hash)):
            raise BundleValidationError(f"{filename}: invalid manifest hash")
        if _sha256(path) != expected_hash:
            raise BundleValidationError(f"{filename}: SHA-256 mismatch")
        try:
            rule = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BundleValidationError(f"{filename}: invalid JSON") from exc
        _validate_rule(rule, path)
        loaded[rule["id"]] = rule
    return loaded
