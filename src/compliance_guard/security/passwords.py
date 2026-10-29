"""Password hashing and the shared authentication failure."""

from __future__ import annotations

import hashlib
import hmac
import secrets

# scrypt parameters. n=2^14 keeps an interactive login responsive while making a
# large offline guessing run expensive.
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SALT_BYTES = 16

# Deliberately identical for every authentication failure.
_AUTH_FAILED = "用户名或密码不正确"


class SessionError(RuntimeError):
    """Authentication or credential change refused."""


def hash_password(password: str) -> str:
    """Derive a storable representation of ``password``.

    Format: ``scrypt$n$r$p$salt_hex$key_hex``. Self-describing so the parameters
    can be raised later without invalidating existing records.
    """
    if password is None:
        raise SessionError("password is required")
    salt = secrets.token_bytes(_SALT_BYTES)
    key = hashlib.scrypt(
        str(password).encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${key.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Whether ``password`` matches ``stored``.

    A malformed record returns False rather than raising: a corrupted user file
    should deny access, not crash the login route into a 500 that leaks a stack
    trace.
    """
    try:
        scheme, n_text, r_text, p_text, salt_hex, key_hex = str(stored).split("$")
        if scheme != "scrypt":
            return False
        key = hashlib.scrypt(
            str(password).encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n_text),
            r=int(r_text),
            p=int(p_text),
            dklen=len(bytes.fromhex(key_hex)),
        )
    except (AttributeError, TypeError, ValueError):
        return False
    # Constant-time: a length-or-prefix comparison leaks information through timing.
    return hmac.compare_digest(key, bytes.fromhex(key_hex))


def auth_failed() -> str:
    """The single public failure message for unknown users and wrong passwords."""
    return _AUTH_FAILED
