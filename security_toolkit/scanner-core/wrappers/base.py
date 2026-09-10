"""Tool Wrapper Interface (spec §6, §55, §59-§60).

Scanner Core -> Safety Policy -> Tool Wrapper -> Open Source Tool

A wrapper never accepts a raw shell string (spec §55: "Raw Command 제한") --
`build_command()` must return an argv list[str], which `execute()` enforces
before ever calling subprocess. Every external tool run gets Process
Isolation (spec §60): its own subprocess, a mandatory timeout (spec §59:
"무한 실행되는 subprocess를 허용하지 않는다"), and stdout/stderr/exit-code
collection -- the caller never talks to the underlying process directly.
"""

from __future__ import annotations

import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable

from safety.policy import HttpSafetyPolicy
from storage.models import Finding, ScanTarget


@dataclass
class WrapperResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float


class WrapperParseError(RuntimeError):
    """Parsing failed after stdout/stderr had already been captured."""

    def __init__(self, result: WrapperResult, cause: Exception) -> None:
        super().__init__(f"result parse failed: {cause}")
        self.result = result


class ToolWrapper(ABC):
    """`module` must match a key registered in safety.policy.MODULE_RISK --
    the Orchestrator looks the wrapper's risk classification up by this
    name before ever calling execute()."""

    module: str

    def __init__(self, policy: HttpSafetyPolicy | None = None) -> None:
        self.policy = policy or HttpSafetyPolicy()

    @abstractmethod
    def build_command(self, target: ScanTarget, **kwargs) -> list[str]:
        """Must return a list[str] argv. Never build or accept a shell
        string -- the caller only ever supplies structured, already-
        validated arguments (spec §55)."""

    @abstractmethod
    def parse_result(self, result: WrapperResult, target: ScanTarget) -> list[Finding]:
        """Normalize this tool's raw output into standardized Findings
        (spec §61). Raw output itself is preserved separately by the
        Orchestrator (spec §62), not discarded here."""

    def execute(
        self, target: ScanTarget, *, timeout: float | None = None,
        on_start: Callable[[subprocess.Popen], None] | None = None, **kwargs
    ) -> WrapperResult:
        argv = self.build_command(target, **kwargs)
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
            raise TypeError(
                f"{type(self).__name__}.build_command() must return list[str] argv, got {argv!r}"
            )
        effective_timeout = timeout if timeout is not None else self.policy.max_scan_duration_seconds
        start = time.monotonic()
        # encoding="utf-8" is required, not just nice-to-have: several wrapped
        # tools (crawler.py, ...) log Korean text to stderr, and Python's
        # subprocess text-mode otherwise decodes with the OS codepage (cp949
        # on this Windows install), which crashes the reader thread on
        # legitimate UTF-8 multi-byte sequences it can't represent.
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace"
        )
        # spec §60 Process Termination: hands the live Popen to the caller
        # (Orchestrator's ProcessRegistry) the instant it exists, so a
        # cancel_task() on a different thread can actually kill it instead of
        # only being able to cancel Tasks that haven't started yet.
        if on_start is not None:
            on_start(proc)
        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=effective_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            timed_out = True
        duration = time.monotonic() - start
        return WrapperResult(
            exit_code=(-1 if timed_out else proc.returncode),
            stdout=stdout or "", stderr=stderr or "",
            timed_out=timed_out, duration_seconds=duration,
        )

    def run(
        self, target: ScanTarget, *, timeout: float | None = None,
        on_start: Callable[[subprocess.Popen], None] | None = None, **kwargs
    ) -> tuple[WrapperResult, list[Finding]]:
        """execute() + parse_result() in one call -- what the Orchestrator
        actually invokes per Task."""
        result = self.execute(target, timeout=timeout, on_start=on_start, **kwargs)
        try:
            findings = [] if result.timed_out else self.parse_result(result, target)
        except Exception as exc:
            raise WrapperParseError(result, exc) from exc
        return result, findings
