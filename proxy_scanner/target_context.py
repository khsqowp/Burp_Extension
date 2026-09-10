"""Common target model shared by every URL/host-based diagnostic tab.

The user sets one URL (and, optionally, a port that overrides whatever the
URL itself implies) once at the top of the window; each scanning tab reads
its starting values from here instead of asking the user to re-type
scheme/host/port separately in every tab."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

_DEFAULT_PORTS = {"http": 80, "https": 443}


class TargetError(ValueError):
    """Raised with an already-Korean, user-facing message -- callers can show
    str(exc) directly in the GUI without translating anything."""


@dataclass(frozen=True)
class TargetContext:
    raw: str            # exactly what the user typed
    scheme: str          # "http" | "https"
    host: str            # hostname or IP, no port
    port: int             # resolved port: explicit override > URL's own port > scheme default
    port_explicit: bool    # True if the port came from the user (override field or in the URL itself),
                             # False if it was silently defaulted from the scheme (matters for tools like
                             # the infra scanner where "no port given" means "scan a port range", not "scan 80/443")
    url: str               # URL reconstructed with the resolved port, path/query preserved
    origin: str             # f"{scheme}://{host}:{port}"


def parse_target(url_text: str, port_text: str = "") -> TargetContext:
    url_text = (url_text or "").strip()
    port_text = (port_text or "").strip()

    if not url_text:
        raise TargetError("진단 대상 URL을 입력하세요.")
    if "://" not in url_text:
        raise TargetError("URL에 http:// 또는 https:// 를 포함해야 합니다. 예: https://example.com")

    parsed = urlparse(url_text)
    if parsed.scheme not in ("http", "https"):
        raise TargetError(f"지원하지 않는 스킴입니다: '{parsed.scheme}' (http 또는 https만 가능)")
    if not parsed.hostname:
        raise TargetError("URL에서 호스트를 찾을 수 없습니다.")

    if port_text:
        try:
            port = int(port_text)
        except ValueError:
            raise TargetError("포트는 숫자여야 합니다.") from None
        if not (1 <= port <= 65535):
            raise TargetError("포트는 1~65535 범위여야 합니다.")
        port_explicit = True
        netloc = f"{parsed.hostname}:{port}"
    elif parsed.port is not None:
        port = parsed.port
        port_explicit = True
        netloc = parsed.netloc
    else:
        port = _DEFAULT_PORTS[parsed.scheme]
        port_explicit = False
        netloc = parsed.hostname

    host = parsed.hostname
    url = parsed._replace(netloc=netloc).geturl()
    origin = f"{parsed.scheme}://{host}:{port}"
    return TargetContext(
        raw=url_text, scheme=parsed.scheme, host=host, port=port,
        port_explicit=port_explicit, url=url, origin=origin,
    )
