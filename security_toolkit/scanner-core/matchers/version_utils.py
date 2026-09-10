"""Minimal dotted-version comparison shared by the CVE and EOS/EOL matchers.
No external dependency (packaging isn't in requirements.txt) -- this only
needs to compare simple numeric dotted versions like "2.4.49", which is all
the seeded rule tables ever contain.
"""

from __future__ import annotations

import re

_NUM_RE = re.compile(r"\d+")


def parse_version(version: str) -> tuple[int, ...]:
    """'2.4.49' -> (2, 4, 49). Non-numeric segments/suffixes (e.g. '9.6p1',
    'RELEASE') are ignored via extracting leading digit runs only -- good
    enough for the coarse "older than X" comparisons these rule tables do."""
    return tuple(int(n) for n in _NUM_RE.findall(version)) or (0,)


def version_less_than(a: str, b: str) -> bool:
    va, vb = parse_version(a), parse_version(b)
    max_len = max(len(va), len(vb))
    va = va + (0,) * (max_len - len(va))
    vb = vb + (0,) * (max_len - len(vb))
    return va < vb
