#!/usr/bin/env python3
"""
Generate the lab CA plus per-service cert bundles for mTLS.

Writes the following PEM files under ``certs/`` at the repo root:

    ca.crt / ca.key                            - lab CA root
    gateway.crt / gateway.key                  - gateway service identity
    internal-admin.crt / internal-admin.key    - internal-admin service identity
    token-service.crt / token-service.key      - token-service service identity

Each service cert is issued with BOTH serverAuth and clientAuth Extended
Key Usage flags, so a single cert can be used as a TLS server (when a
peer calls this service) and as a TLS client (when this service calls
a peer). This is the simplest cert scheme that models a real service
mesh without needing per-direction cert bundles.

LAB ONLY. The generated keys are intentionally committable material.
Never reuse them in production; rotate by running this script again.
"""

from __future__ import annotations

import pathlib
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CERTS_DIR = REPO_ROOT / "certs"

SERVICES = ("gateway", "internal-admin", "token-service")


def _save(path: pathlib.Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o644)


def _ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _dump_key(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _dump_cert(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _build_ca():
    key = _ec_key()
    now = datetime.now(timezone.utc)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSRF Ring Dojo"),
            x509.NameAttribute(NameOID.COMMON_NAME, "dojo-lab-ca"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365 * 5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _build_service_cert(ca_key, ca_cert, name: str):
    key = _ec_key()
    now = datetime.now(timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSRF Ring Dojo"),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365 * 5))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(name),
                    x509.DNSName("localhost"),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def main() -> None:
    CERTS_DIR.mkdir(exist_ok=True)

    ca_key, ca_cert = _build_ca()
    _save(CERTS_DIR / "ca.crt", _dump_cert(ca_cert))
    _save(CERTS_DIR / "ca.key", _dump_key(ca_key))
    print(f"wrote {CERTS_DIR}/ca.crt")
    print(f"wrote {CERTS_DIR}/ca.key")

    for svc in SERVICES:
        key, cert = _build_service_cert(ca_key, ca_cert, svc)
        _save(CERTS_DIR / f"{svc}.crt", _dump_cert(cert))
        _save(CERTS_DIR / f"{svc}.key", _dump_key(key))
        print(f"wrote {CERTS_DIR}/{svc}.crt")
        print(f"wrote {CERTS_DIR}/{svc}.key")


if __name__ == "__main__":
    main()
