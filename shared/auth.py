import base64
import binascii
import json
import secrets
import time
from functools import lru_cache
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class AuthError(ValueError):
    pass


def now_epoch() -> int:
    return int(time.time())


def new_jti() -> str:
    return secrets.token_urlsafe(16)


def normalize_scope(value: str) -> str:
    scope = value.strip()
    if not scope or any(char.isspace() for char in scope) or "," in scope:
        raise AuthError("bad scope")
    return scope


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _split_token(token: str) -> tuple[str, str]:
    parts = token.split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise AuthError("bad token")
    return parts[0], parts[1]


@lru_cache(maxsize=None)
def _load_private_key(path: str) -> Ed25519PrivateKey:
    try:
        raw_key = Path(path).read_bytes()
        key = serialization.load_pem_private_key(raw_key, password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise AuthError("bad private key") from exc

    if not isinstance(key, Ed25519PrivateKey):
        raise AuthError("unsupported private key")

    return key


@lru_cache(maxsize=None)
def _load_public_key(path: str) -> Ed25519PublicKey:
    try:
        raw_key = Path(path).read_bytes()
        key = serialization.load_pem_public_key(raw_key)
    except (OSError, ValueError, TypeError) as exc:
        raise AuthError("bad public key") from exc

    if not isinstance(key, Ed25519PublicKey):
        raise AuthError("unsupported public key")

    return key


def _coerce_private_key(signing_key) -> Ed25519PrivateKey:
    if isinstance(signing_key, Ed25519PrivateKey):
        return signing_key
    return _load_private_key(str(signing_key))


def _coerce_public_key(verification_key) -> Ed25519PublicKey:
    if isinstance(verification_key, Ed25519PublicKey):
        return verification_key
    return _load_public_key(str(verification_key))


def peek_signed_payload(token: str) -> dict:
    payload_b64, _ = _split_token(token)

    try:
        return json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
        binascii.Error,
    ) as exc:
        raise AuthError("bad token") from exc


def issue_signed_payload(payload: dict, signing_key) -> str:
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    payload_b64 = _b64url_encode(payload_json)
    signature = _coerce_private_key(signing_key).sign(payload_b64.encode("ascii"))
    return f"{payload_b64}.{_b64url_encode(signature)}"


def verify_signed_payload(token: str, verification_key) -> dict:
    payload_b64, signature_b64 = _split_token(token)

    try:
        signature = _b64url_decode(signature_b64)
    except binascii.Error as exc:
        raise AuthError("bad signature") from exc

    try:
        _coerce_public_key(verification_key).verify(
            signature, payload_b64.encode("ascii")
        )
    except InvalidSignature as exc:
        raise AuthError("bad signature") from exc

    try:
        return json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, binascii.Error) as exc:
        raise AuthError("bad payload") from exc
