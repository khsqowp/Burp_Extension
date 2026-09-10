"""Standardized data models shared across the Scanner Core (spec §23-§24,
§39-§40, §61-§62). Every wrapper/scanner converts its own tool-specific
output into a Finding list here, so the API/Web UI/Burp Extension never need
to understand ffuf/gobuster/nmap's individual raw formats -- only the raw
artifact is kept alongside (raw_ref) for later re-analysis.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskLevel(str, Enum):
    """Spec §12 risk classification -- every Scanner/Payload/module is
    tagged with exactly one of these; Safety Policy Engine decides which
    levels run automatically."""

    SAFE = "safe"
    CAUTION = "caution"
    BLOCKED = "blocked"


@dataclass
class Finding:
    """Spec §61 standardized scan result -- the common shape every tool
    wrapper's raw output gets normalized into."""

    target: str
    scanner: str
    finding: str
    severity: Severity = Severity.INFO
    host: str = ""
    port: int | None = None
    protocol: str = ""
    service: str = ""
    technology: str = ""
    evidence: str = ""
    timestamp: str = ""
    scan_id: str = ""
    task_id: str = ""
    raw_ref: str = ""  # spec §62: path to the raw tool output this was derived from
    id: str = field(default_factory=lambda: new_id("finding"))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value if isinstance(self.severity, Severity) else self.severity
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = dict(d)
        if "severity" in d:
            d["severity"] = Severity(d["severity"])
        return cls(**d)


@dataclass
class Technology:
    """Spec §16/§34 Technology Detection -- a normalized product/version
    signal, regardless of which module originally observed it (nmap
    version-detection, JS bundle fingerprint, HTTP header, ...). CVE/EOS-EOL
    Matchers (spec §19/§21) consume these instead of each knowing how to
    read every wrapper's raw format."""

    product: str
    version: str = ""
    category: str = ""  # e.g. "service", "web_framework", "js_library", "os"
    host: str = ""
    port: int | None = None
    evidence: str = ""
    source_scanner: str = ""
    cpe: list[str] = field(default_factory=list)
    scan_id: str = ""
    id: str = field(default_factory=lambda: new_id("tech"))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Technology":
        return cls(**d)


@dataclass
class ScanTarget:
    """Spec §56 Scope Control -- every Scan is bound to exactly one target;
    wrappers/scanners must never expand past it (redirects, discovered
    links, etc. to a different host are out of scope by default)."""

    value: str  # host, host:port, or URL depending on module
    scope_host: str = ""
    id: str = field(default_factory=lambda: new_id("target"))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ScanTarget":
        return cls(**d)


@dataclass
class TaskRecord:
    """Spec §24 Task -- one module execution (e.g. one ffuf run) within a
    Scan. Every Task has a unique id and one of the 5 defined states."""

    scan_id: str
    module: str
    status: TaskStatus = TaskStatus.PENDING
    start_time: str = ""
    end_time: str = ""
    error: str = ""
    result_file: str = ""
    id: str = field(default_factory=lambda: new_id("task"))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, TaskStatus) else self.status
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "TaskRecord":
        d = dict(d)
        if "status" in d:
            d["status"] = TaskStatus(d["status"])
        return cls(**d)


@dataclass
class ScanRecord:
    """Spec §40 Scan Database entry -- one diagnostic run against one
    Target, made up of one or more Tasks (modules)."""

    target: ScanTarget
    status: TaskStatus = TaskStatus.PENDING
    start_time: str = ""
    end_time: str = ""
    result_dir: str = ""
    id: str = field(default_factory=lambda: new_id("scan"))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, TaskStatus) else self.status
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ScanRecord":
        d = dict(d)
        if "status" in d:
            d["status"] = TaskStatus(d["status"])
        d["target"] = ScanTarget.from_dict(d["target"]) if isinstance(d.get("target"), dict) else d.get("target")
        return cls(**d)
