"""Executable acceptance tests for the locally curated safe HTTP rule bundle."""

from __future__ import annotations

import json
import hashlib
import tempfile
from pathlib import Path

from safety.safe_rule_bundle import BundleValidationError, load_verified_bundle


BUNDLE_DIR = Path(__file__).resolve().parents[2] / "safe_http_checks"


bundle = load_verified_bundle(BUNDLE_DIR)
assert set(bundle) == {
    "allowed-methods",
    "directory-listing",
    "error-page-signatures",
    "security-headers",
    "server-header-disclosure",
}

for rule in bundle.values():
    assert 1 <= rule["limits"]["max_requests"] <= 10
    assert 0 < rule["limits"]["requests_per_second"] <= 2
    for request in rule["requests"]:
        assert request["method"] in {"GET", "HEAD", "OPTIONS"}
        assert request["path"].startswith("/")
        assert "://" not in request["path"]


with tempfile.TemporaryDirectory() as tmp:
    copied = Path(tmp)
    for source in BUNDLE_DIR.iterdir():
        if source.is_file():
            (copied / source.name).write_bytes(source.read_bytes())
    target = copied / "allowed-methods.json"
    data = json.loads(target.read_text(encoding="utf-8"))
    data["requests"].append({"method": "DELETE", "path": "/"})
    target.write_text(json.dumps(data), encoding="utf-8")
    manifest_path = copied / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][target.name] = hashlib.sha256(target.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    try:
        load_verified_bundle(copied)
    except BundleValidationError:
        pass
    else:
        raise AssertionError("modified or state-changing rules must be rejected")


with tempfile.TemporaryDirectory() as tmp:
    copied = Path(tmp)
    for source in BUNDLE_DIR.iterdir():
        if source.is_file():
            (copied / source.name).write_bytes(source.read_bytes())
    target = copied / "directory-listing.json"
    data = json.loads(target.read_text(encoding="utf-8"))
    data["requests"][0]["path"] = "https://collector.invalid/result"
    target.write_text(json.dumps(data), encoding="utf-8")
    manifest_path = copied / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][target.name] = hashlib.sha256(target.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    try:
        load_verified_bundle(copied)
    except BundleValidationError:
        pass
    else:
        raise AssertionError("external destination rules must be rejected")


print("SAFE RULE BUNDLE TESTS OK")
