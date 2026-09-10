"""Wraps E:\\temp\\tools\\site_depth_crawler\\crawler.py (spec §25).

Crawler is a discovery module, not a vulnerability scanner (spec §25 lists
its output as HTML/Link/Form/Script/Resource URL/Endpoint data feeding
*other* modules) -- parse_result() intentionally does not invent "findings"
for every discovered page. It only surfaces real crawl errors as
informational Findings; the full page list is preserved as the raw
artifact (spec §62) for downstream modules/Web UI to consume directly.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from storage.models import Finding, ScanTarget, Severity
from wrappers.base import ToolWrapper, WrapperResult

EXTERNAL_TOOLS_ROOT = Path(__file__).resolve().parents[3]
CRAWLER_SCRIPT = EXTERNAL_TOOLS_ROOT / "site_depth_crawler" / "crawler.py"


class CrawlerWrapper(ToolWrapper):
    module = "crawler"

    def build_command(
        self, target: ScanTarget, *, depth: int | None = None, max_pages: int | None = None
    ) -> list[str]:
        if not CRAWLER_SCRIPT.exists():
            raise FileNotFoundError(f"crawler.py not found at {CRAWLER_SCRIPT}")
        # spec review finding (2026-09-06): a caller-supplied depth/max_pages
        # used to be passed through completely unclamped ("정책 상한보다 큰
        # 값도 그대로 전달"), bypassing spec §10's Maximum Crawl Depth /
        # Maximum Request Count entirely -- only the *default* (omitted)
        # case respected policy. min() with policy now applies either way.
        effective_depth = min(depth, self.policy.max_crawl_depth) if depth is not None else self.policy.max_crawl_depth
        effective_max_pages = (
            min(max_pages, self.policy.max_request_count) if max_pages is not None else self.policy.max_request_count
        )
        return [
            sys.executable, str(CRAWLER_SCRIPT), target.value,
            "--depth", str(effective_depth),
            "--max-pages", str(effective_max_pages),
            "--min-interval", str(1.0 / self.policy.max_requests_per_second),
            "--timeout", str(int(self.policy.timeout_seconds)),
            "--retries", str(self.policy.retry_count),
            "--output", "json",
        ]

    def parse_result(self, result: WrapperResult, target: ScanTarget) -> list[Finding]:
        if result.exit_code != 0 or not result.stdout.strip():
            return []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []
        for page in data.get("pages", []):
            if page.get("error"):
                findings.append(
                    Finding(
                        target=target.value, scanner=self.module, finding="Crawl error",
                        severity=Severity.LOW, host=target.scope_host, evidence=str(page.get("error")),
                        raw_ref="",
                    )
                )
        return findings
