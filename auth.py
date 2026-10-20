"""Password hashing, verification, and signed session-cookie helpers.

Password hashing uses PBKDF2-HMAC-SHA256 (hashlib, stdlib) with a random
per-user salt, stored in the format:

    pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
"""
import hashlib
import hmac
import secrets
import time

from fastapi import Response
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from config import PBKDF2_ITERATIONS, SESSION_SECRET

_serializer = URLSafeTimedSerializer(SESSION_SECRET)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PBKDF2_ITERATIONS
    )
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS, salt.hex(), digest.hex()
    )


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        scheme, iterations, salt_hex, hash_hex = hashed_password.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", plain_password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def create_session_token(username: str) -> str:
    """Create a signed, time-limited session cookie value."""
    return _serializer.dumps({"username": username, "created": time.time()})


def verify_session_token(token: str, max_age: int = 3600) -> str | None:
    """Verify a session token and return the username, or None."""
    try:
        data = _serializer.loads(token, max_age=max_age)
        return data.get("username")
    except (BadSignature, SignatureExpired):
        return None


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=3600,
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie("session")
