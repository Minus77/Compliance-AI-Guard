"""Minimal local sessions: the server decides who you are.

``x-demo-role`` let a caller name their own role, so changing one request header
was enough to publish model policy or read the audit trail (defect P-3). Every
route checked permissions faithfully — against an identity the caller had simply
asserted.

**Scope, stated plainly.** This is a minimal local session store, not enterprise
SSO. There is no identity provider, no second factor, no user management. It exists
so the trust boundary sits in the right *place*, with a seam an OIDC integration can
replace. Claiming more would repeat the overstatement the audit-trail work was
careful to avoid, and a reviewer would rightly stop believing the rest.

Choices worth the words:

**scrypt with a per-password salt.** A memory-hard KDF, because the threat is an
offline attempt against a stolen file, and identical passwords must not produce
identical records.

**One error for every failure.** Unknown user and wrong password return the same
message. Distinguishing them turns the endpoint into a way to enumerate accounts.

**The default credential expires on first use.** A shipped password that keeps
working is a backdoor with documentation. The bootstrap password is generated per
installation, shown once, and never written to disk.

**Changing a password ends existing sessions.** Otherwise a credential rotation —
usually done precisely because something leaked — leaves the leaked session alive.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import json
import secrets
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import Field

from compliance_guard.domain.enums import Role
from compliance_guard.domain.models import Actor, DomainModel
from compliance_guard.runtime_paths import writable_data_dir

# scrypt parameters. n=2^14 keeps an interactive login responsive while making a
# large offline guessing run expensive.
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SALT_BYTES = 16

_MIN_PASSWORD_CHARS = 12
_DEFAULT_TTL_SECONDS = 8 * 60 * 60      # one working day
_BOOTSTRAP_USERNAME = "admin"

# Deliberately identical for every authentication failure.
_AUTH_FAILED = "用户名或密码不正确"


def announce_bootstrap_credential(username: str, password: str | None) -> None:
    """Show a freshly generated bootstrap password to the operator, once.

    Lives here rather than in an entry point because *every* way of starting the app
    has to do it. It was originally called only from the desktop launcher, so the
    documented ``uvicorn apps.api.main:app`` command generated a password and printed
    nothing -- with ``DEMO_MODE`` off that is a first-run lockout: the account exists,
    the password is unknowable, and the sign-in form cannot be cleared.

    Where the value may appear is the rest of the design. **Not** the log: it lives in
    the per-user data directory, is appended to on every run, and is the first thing
    attached to a bug report. A working password there would put a plaintext
    credential on disk beside its own hash, defeating the point of hashing it. So the
    value goes to stdout, and the log records only that an announcement happened.

    ``password is None`` means an established account is being reused, and silence is
    correct: printing a reassurance on every start trains the reader to skip the one
    line that matters.
    """
    if not password:
        return

    logging.info(
        "bootstrap credential generated for %r; printed to console only", username
    )
    lines = [
        "",
        "=" * 68,
        "  首次启动：已生成初始管理员密码 / Initial admin password generated",
        "=" * 68,
        f"  用户名 / username : {username}",
        f"  密码   / password : {password}",
        "",
        "  · 该密码仅显示一次，不会写入日志或磁盘。",
        "    Shown only once. It is not written to the log or to disk.",
        "  · 首次登录后必须修改密码才能继续使用。",
        "    You must change it after signing in before you can continue.",
        "=" * 68,
        "",
    ]
    print("\n".join(lines), flush=True)


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


class User(DomainModel):
    """A local account. Never carries a plaintext password."""

    username: str
    role: Role
    password_hash: str
    must_change_password: bool = False
    tenant_id: str = "TENANT-CN"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # Whether this account has ever been signed into. The bootstrap recovery below
    # turns on this single fact, so it is recorded rather than inferred.
    last_login_at: datetime | None = None

    @property
    def never_used(self) -> bool:
        """True when no one has ever signed in with this account.

        An account with no history has nothing to protect, which is what makes it
        safe to re-key. Once it has been used it is a real identity and re-keying
        would be a way in rather than a recovery.
        """
        return self.last_login_at is None and self.must_change_password

    def actor(self) -> Actor:
        return Actor(actor_id=f"user-{self.username}", role=self.role, tenant_id=self.tenant_id)


class Session(DomainModel):
    """An authenticated session. The token is the only credential presented."""

    token: str
    username: str
    role: Role
    tenant_id: str = "TENANT-CN"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    must_change_password: bool = False

    @property
    def actor(self) -> Actor:
        return Actor(actor_id=f"user-{self.username}", role=self.role, tenant_id=self.tenant_id)

    def expired(self, now: datetime | None = None) -> bool:
        return (now or datetime.now(UTC)) >= self.expires_at


class SessionStore:
    """File-backed users and sessions for a single local installation."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path is not None else writable_data_dir() / "users.json"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._users: dict[str, User] = {}
        self._sessions: dict[str, Session] = {}
        # Held in memory only, and only for the run that created the account.
        self._bootstrap_password: str | None = None
        self._load()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def bootstrap_password(self) -> str | None:
        """The generated default password, available only on the run that made it.

        Not persisted: a plaintext credential on disk would defeat the hashing
        above. An operator who loses it re-provisions the file.
        """
        return self._bootstrap_password

    # -- persistence ---------------------------------------------------------

    def _load(self) -> None:
        if not self._path.is_file():
            self._provision()
            return
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            # Unreadable user file: provision a fresh one rather than serving with
            # no accounts at all, which would make every protected route a 403.
            self._provision()
            return

        for record in (payload.get("users") or {}).values():
            try:
                user = User(**record)
            except (TypeError, ValueError):
                continue
            self._users[user.username] = user
        for record in (payload.get("sessions") or {}).values():
            try:
                session = Session(**record)
            except (TypeError, ValueError):
                continue
            if not session.expired():
                self._sessions[session.token] = session
        if not self._users:
            self._provision()
            return
        self._rekey_unused_bootstrap()

    def _rekey_unused_bootstrap(self) -> None:
        """Re-issue the password for a bootstrap account nobody has used.

        The generated password is never written to disk, which is right -- storing a
        plaintext credential beside its own hash would defeat the hashing. But on the
        second start the file exists, so nothing could reveal the password and the
        account became a permanent lockout whose only remedy was deleting an
        undocumented file.

        Re-keying is confined to accounts that have never been signed into. A used
        account keeps its credential: silently replacing a working identity's password
        would be an entry point, not a recovery.
        """
        user = self._users.get(_BOOTSTRAP_USERNAME)
        if user is None or not user.never_used:
            return
        password = secrets.token_urlsafe(18)
        self._bootstrap_password = password
        self._users[user.username] = user.model_copy(
            update={"password_hash": hash_password(password)}
        )
        # Any session opened against the previous password is void.
        self._sessions = {
            token: session
            for token, session in self._sessions.items()
            if session.username != user.username
        }
        self._flush()

    def _provision(self) -> None:
        """Create the single bootstrap account with a generated password."""
        password = secrets.token_urlsafe(18)
        self._bootstrap_password = password
        self._users = {
            _BOOTSTRAP_USERNAME: User(
                username=_BOOTSTRAP_USERNAME,
                role=Role.COMPLIANCE_ADMIN,
                password_hash=hash_password(password),
                # Forced on purpose: a default credential that keeps working is a
                # backdoor with documentation.
                must_change_password=True,
            )
        }
        self._sessions = {}
        self._flush()

    def _flush(self) -> None:
        payload = {
            "version": 1,
            "users": {
                name: user.model_dump(mode="json") for name, user in self._users.items()
            },
            "sessions": {
                token: session.model_dump(mode="json")
                for token, session in self._sessions.items()
            },
        }
        self._path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    # -- accounts ------------------------------------------------------------

    def user(self, username: str) -> User | None:
        return self._users.get(str(username))

    def change_password(self, username: str, current: str, replacement: str) -> User:
        """Replace a password and end every session for that account."""
        with self._lock:
            user = self._users.get(str(username))
            if user is None or not verify_password(current, user.password_hash):
                raise SessionError(_AUTH_FAILED)
            candidate = str(replacement or "")
            if len(candidate) < _MIN_PASSWORD_CHARS:
                raise SessionError(
                    f"密码至少需要 {_MIN_PASSWORD_CHARS} 个字符"
                )
            if verify_password(candidate, user.password_hash):
                raise SessionError("新密码不能与当前密码相同")

            updated = user.model_copy(
                update={
                    "password_hash": hash_password(candidate),
                    "must_change_password": False,
                }
            )
            self._users[updated.username] = updated
            # A rotation is usually done because something leaked, so leaving the
            # older sessions alive would defeat the point of rotating.
            self._sessions = {
                token: session
                for token, session in self._sessions.items()
                if session.username != updated.username
            }
            self._flush()
            return updated

    # -- sessions ------------------------------------------------------------

    def login(
        self,
        username: str,
        password: str,
        *,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> Session:
        """Authenticate and open a session.

        Every failure raises the same message: distinguishing "no such user" from
        "wrong password" turns this into an account-enumeration endpoint.
        """
        with self._lock:
            user = self._users.get(str(username))
            if user is None or not verify_password(password, user.password_hash):
                raise SessionError(_AUTH_FAILED)

            now = datetime.now(UTC)
            # Mark the account used, so it is never re-keyed on a later start.
            if user.last_login_at is None:
                user = user.model_copy(update={"last_login_at": now})
                self._users[user.username] = user
            session = Session(
                token=secrets.token_urlsafe(32),
                username=user.username,
                role=user.role,
                tenant_id=user.tenant_id,
                created_at=now,
                expires_at=now + timedelta(seconds=max(0, int(ttl_seconds))),
                must_change_password=user.must_change_password,
            )
            self._sessions[session.token] = session
            self._prune()
            self._flush()
            return session

    def resolve(self, token: str | None) -> Session | None:
        """The session for ``token``, or None when absent or expired."""
        if not token:
            return None
        with self._lock:
            session = self._sessions.get(str(token))
            if session is None:
                return None
            if session.expired():
                self._sessions.pop(session.token, None)
                self._flush()
                return None
            return session

    def logout(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            if self._sessions.pop(str(token), None) is not None:
                self._flush()

    def _prune(self) -> None:
        """Drop expired sessions so the file cannot grow without bound."""
        live = {
            token: session
            for token, session in self._sessions.items()
            if not session.expired()
        }
        self._sessions = live

    def summary(self) -> dict[str, Any]:
        """Non-sensitive view for a readiness probe."""
        return {
            "users": len(self._users),
            "active_sessions": len(self._sessions),
            "password_change_required": any(
                user.must_change_password for user in self._users.values()
            ),
            # A bootstrap credential is waiting to be used. Reported as a flag only:
            # the value itself is shown once, on the console, and never in an API
            # response an unauthenticated caller could read.
            "bootstrap_pending": any(user.never_used for user in self._users.values()),
            "path": str(self._path),
        }


__all__ = [
    "Session",
    "announce_bootstrap_credential",
    "SessionError",
    "SessionStore",
    "User",
    "hash_password",
    "verify_password",
]
