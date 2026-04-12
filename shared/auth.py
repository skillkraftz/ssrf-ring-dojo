import base64
import binascii
import hashlib
import hmac
import json
import secrets
import time


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


def peek_signed_payload(token: str) -> dict:
    try:
        payload_b64, _ = token.split(".", 1)
        return json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except (
        ValueError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        binascii.Error,
    ) as exc:
        raise AuthError("bad token") from exc


def issue_signed_payload(payload: dict, signing_secret: str) -> str:
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    payload_b64 = _b64url_encode(payload_json)
    signature = hmac.new(
        signing_secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256
    ).digest()
    return f"{payload_b64}.{_b64url_encode(signature)}"


def verify_signed_payload(token: str, signing_secret: str) -> dict:
    try:
        payload_b64, signature_b64 = token.split(".", 1)
    except ValueError as exc:
        raise AuthError("bad token") from exc

    expected_signature = _b64url_encode(
        hmac.new(
            signing_secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256
        ).digest()
    )
    if not hmac.compare_digest(signature_b64, expected_signature):
        raise AuthError("bad signature")

    try:
        return json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, binascii.Error) as exc:
        raise AuthError("bad payload") from exc
