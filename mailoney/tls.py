"""
TLS certificate handling for Mailoney.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import secrets
import ssl
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from .config import TlsConfig

logger = logging.getLogger(__name__)

# As the snakeoil certificate of a Debian mail server: ten years, made some
# time ago, not minutes before the first connection
CERT_VALIDITY_DAYS = 3650
CERT_MAX_AGE_DAYS = 90


@dataclass(frozen=True)
class TlsMaterial:
    cert_file: str
    key_file: str


def _subject_alt_name(server_name: str) -> x509.SubjectAlternativeName:
    try:
        ip_address = ipaddress.ip_address(server_name)
    except ValueError:
        return x509.SubjectAlternativeName([x509.DNSName(server_name)])
    return x509.SubjectAlternativeName([x509.IPAddress(ip_address)])


def _server_name_ip(server_name: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(server_name)
    except ValueError:
        return None


def _certificate_matches_server_name(
    certificate: x509.Certificate,
    server_name: str,
) -> bool:
    server_ip = _server_name_ip(server_name)
    try:
        san = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound:
        san = None

    if san is not None:
        if server_ip is not None:
            return server_ip in san.get_values_for_type(x509.IPAddress)
        dns_names = san.get_values_for_type(x509.DNSName)
        return server_name.lower() in (name.lower() for name in dns_names)

    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return any(name.value.lower() == server_name.lower() for name in common_names)


def _existing_certificate_matches(cert_file: Path, server_name: str) -> bool:
    certificate = x509.load_pem_x509_certificate(cert_file.read_bytes())
    return _certificate_matches_server_name(certificate, server_name)


def _generate_self_signed_certificate(
    cert_file: Path,
    key_file: Path,
    server_name: str,
) -> None:
    cert_file.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    key_file.parent.mkdir(parents=True, exist_ok=True, mode=0o750)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, server_name)]
    )
    not_before = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(
        days=1 + secrets.randbelow(CERT_MAX_AGE_DAYS),
        seconds=secrets.randbelow(86400),
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(_subject_alt_name(server_name), critical=False)
        .sign(key, hashes.SHA256())
    )

    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)

    _write_atomic(key_file, key_bytes, 0o600)
    _write_atomic(cert_file, cert_bytes, 0o640)


def _write_atomic(path: Path, data: bytes, mode: int) -> None:
    """Write through a temp file that has its final mode from the start."""
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def _restrict_key(key_file: Path) -> None:
    try:
        if key_file.stat().st_mode & 0o077:
            os.chmod(key_file, 0o600)
    except OSError as exc:
        logger.warning("Could not restrict TLS key %s: %s", key_file, exc)


def ensure_tls_material(
    config: TlsConfig,
    server_name: str,
) -> Optional[TlsMaterial]:
    if not config.enabled:
        return None

    cert_file = Path(config.cert_file)
    key_file = Path(config.key_file)
    if cert_file.exists() and key_file.exists():
        try:
            if _existing_certificate_matches(cert_file, server_name):
                _restrict_key(key_file)
                return TlsMaterial(cert_file=str(cert_file), key_file=str(key_file))
        except Exception as exc:
            if not config.auto_generate:
                raise ValueError(
                    f"TLS certificate could not be read: {cert_file}: {exc}"
                ) from exc
            logger.warning(
                "TLS certificate %s could not be read; regenerating it: %s",
                cert_file,
                exc,
            )
        else:
            if not config.auto_generate:
                raise ValueError(
                    "TLS certificate does not match server_name "
                    f"{server_name!r}: {cert_file}"
                )
            logger.info(
                "TLS certificate %s does not match server_name %r; regenerating it",
                cert_file,
                server_name,
            )
        _generate_self_signed_certificate(cert_file, key_file, server_name)
        return TlsMaterial(cert_file=str(cert_file), key_file=str(key_file))

    if not config.auto_generate:
        raise FileNotFoundError(
            f"TLS certificate/key missing: {cert_file} / {key_file}"
        )

    _generate_self_signed_certificate(cert_file, key_file, server_name)
    return TlsMaterial(cert_file=str(cert_file), key_file=str(key_file))


def build_server_context(material: TlsMaterial) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(material.cert_file, material.key_file)
    return context
