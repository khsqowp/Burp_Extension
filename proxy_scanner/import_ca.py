"""One-time setup utility: import an existing CA (private key + cert, e.g.
exported from Burp Suite as PKCS#12) so proxy_scanner signs traffic with it
instead of auto-generating its own mitmproxy CA.

Burp's plain "Certificate" export (DER/PEM, e.g. burpsuiteca.crt) is cert-only
and CANNOT be used here -- there's no private key in it, so nothing could sign
per-domain leaf certs with it. You need Burp's other export option:
    Burp -> Proxy -> Options -> Import / export CA certificate ->
    "Certificate and private key in PKCS#12 keystore format"
(pick a password when exporting -- you'll be asked for it again below).

Usage:
    python import_ca.py                          (uses default path, prompts for password)
    python import_ca.py path\to\exported.p12
    python import_ca.py path\to\exported.p12 --password mypassword

What it does: writes ~/.mitmproxy/mitmproxy-ca.pem (the exact filename/format
mitmproxy's CertStore looks for: private key PEM + certificate PEM,
concatenated). Any existing file there is backed up first, never silently
overwritten.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

import app_paths

DEFAULT_CONFDIR = Path(os.path.expanduser("~/.mitmproxy"))
DEFAULT_P12 = DEFAULT_CONFDIR / "pkcs.p12"


@dataclass
class ImportedCertInfo:
    """Shown to the user after a successful import (spec: 단일 EXE 휴대용
    배포 §6.2 "성공하면 인증서 주체, 발급자, 만료일, 지문을 표시한다")."""
    subject: str
    issuer: str
    not_valid_after: datetime
    fingerprint_sha256: str

    @property
    def not_valid_after_display(self) -> str:
        return self.not_valid_after.strftime("%Y-%m-%d")


def _is_explicitly_not_a_ca(cert: x509.Certificate) -> bool:
    """True only when the certificate's BasicConstraints extension is
    present AND explicitly says ca=False -- a real end-entity leaf cert
    someone mistakenly exported instead of the CA. Certs that simply omit
    the extension (common in loosely-generated self-signed CAs) are not
    treated as a hard failure -- spec's "CA 용도... 검증" is about catching
    an obviously-wrong file, not rejecting anything that isn't textbook-strict."""
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        return bc.ca is False
    except x509.ExtensionNotFound:
        return False


def import_pkcs12(p12_path: Path, password: str, confdir: Path) -> ImportedCertInfo:
    """Convert a PKCS#12 (cert + private key) into the mitmproxy-ca.pem
    format mitmproxy's CertStore expects, writing it into `confdir`.
    Returns info about the imported CA for display. Raises ValueError on
    any problem (bad password, cert-only file with no key, expired,
    obviously-not-a-CA, etc.) with a message meant to be shown directly to
    the user -- and never touches `confdir` until every check has passed,
    so a failed import always leaves an existing valid CA untouched
    (spec 6.2: "실패하면 기존 정상 인증서를 덮어쓰거나 삭제하지 않는다")."""
    if not p12_path.exists():
        raise ValueError(f"파일을 찾을 수 없음: {p12_path}")

    try:
        raw = p12_path.read_bytes()
    except OSError as exc:
        raise ValueError(f"파일을 읽을 수 없습니다: {exc}") from exc

    try:
        key, cert, additional_certs = pkcs12.load_key_and_certificates(raw, password.encode("utf-8") or None)
    except Exception as exc:  # noqa: BLE001
        # cryptography's pkcs12 loader doesn't reliably distinguish "wrong
        # password" from "corrupt file" in its exception text across
        # versions/backends -- a password was actually supplied is the one
        # case common enough to name with confidence; otherwise stay honest
        # instead of guessing.
        if password:
            raise ValueError("인증서 비밀번호가 올바르지 않습니다.") from exc
        raise ValueError(f"PKCS#12 파일을 열 수 없습니다 (손상되었을 수 있음): {exc}") from exc

    if key is None or cert is None:
        raise ValueError(
            "이 파일에는 개인키가 없습니다. 개인키 포함 PKCS#12(.p12/.pfx) 파일을 선택하세요."
        )

    if _is_explicitly_not_a_ca(cert):
        raise ValueError(
            "이 인증서는 CA(인증기관) 용도가 아닙니다 -- 일반 서버/클라이언트 인증서로 보입니다. "
            "CA 인증서와 개인키가 포함된 PKCS#12 파일을 선택하세요."
        )

    not_valid_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    if not_valid_after < datetime.now(timezone.utc):
        raise ValueError(f"인증서가 만료되었습니다. 만료일: {not_valid_after.strftime('%Y-%m-%d')}")

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    chain_pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (additional_certs or []))

    confdir.mkdir(parents=True, exist_ok=True)
    target = confdir / "mitmproxy-ca.pem"
    if target.exists():
        backup = confdir / "mitmproxy-ca.pem.bak"
        target.replace(backup)

    target.write_bytes(key_pem + cert_pem + chain_pem)
    try:
        target.chmod(0o600)  # no-op on Windows (flips the read-only attribute bit only) -- real ACL restriction below
    except OSError:
        pass
    app_paths.restrict_to_current_user(target)

    fingerprint_bytes = cert.fingerprint(hashes.SHA256())
    fingerprint_display = ":".join(f"{b:02X}" for b in fingerprint_bytes)

    return ImportedCertInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_valid_after=not_valid_after,
        fingerprint_sha256=fingerprint_display,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="import_ca", description="Import an existing CA (PKCS#12) for proxy_scanner to sign traffic with.")
    parser.add_argument("p12_path", nargs="?", default=str(DEFAULT_P12), help=f"Path to the .p12/.pfx file (default: {DEFAULT_P12})")
    parser.add_argument("--password", default=None, help="PKCS#12 password (omit to be prompted securely)")
    parser.add_argument("--confdir", default=str(DEFAULT_CONFDIR), help=f"mitmproxy confdir to write into (default: {DEFAULT_CONFDIR})")
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    parser = build_arg_parser()
    args = parser.parse_args(argv)

    password = args.password
    if password is None:
        password = getpass.getpass("PKCS#12 비밀번호: ")

    try:
        info = import_pkcs12(Path(args.p12_path), password, Path(args.confdir))
    except ValueError as exc:
        print(str(exc))
        return 2

    print(f"작성됨: {Path(args.confdir) / 'mitmproxy-ca.pem'}")
    print(f"주체: {info.subject}")
    print(f"발급자: {info.issuer}")
    print(f"만료일: {info.not_valid_after_display}")
    print(f"지문(SHA-256): {info.fingerprint_sha256}")
    print("proxy_scanner를 시작하면 이제 이 CA로 서명함. 이 CA가 브라우저/OS에 이미 "
          "신뢰된 상태가 아니라면 (예: 새로 만든 키라면) 인증서를 따로 설치해야 함.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
