import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.main import normalize_http_target

assert normalize_http_target("192.168.0.12") == ("http://192.168.0.12", "192.168.0.12")
assert normalize_http_target("192.168.0.12:3000") == ("http://192.168.0.12:3000", "192.168.0.12")
assert normalize_http_target("https://example.com/a") == ("https://example.com/a", "example.com")

for invalid in ("http://http:192.168.0,12:3000", "http://", "ftp://192.168.0.12", "http://user:pass@host/"):
    try:
        normalize_http_target(invalid)
        raise AssertionError(f"invalid target accepted: {invalid}")
    except ValueError:
        pass

print("API target normalization and rejection: PASS")
