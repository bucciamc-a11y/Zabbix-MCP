"""Admin authentication: PBKDF2 password hashes, signed expiring session cookies, and a
login throttle. No external dependencies."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

PBKDF2_ITERATIONS = 600_000
SESSION_TTL = 8 * 3600
MIN_PASSWORD_LEN = 12


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters, salt_b64, dk_b64 = stored.split("$")
        if scheme != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt_b64), int(iters))
        return hmac.compare_digest(dk, base64.b64decode(dk_b64))
    except (ValueError, TypeError):
        return False


def check_password_strength(password: str) -> str | None:
    if len(password) < MIN_PASSWORD_LEN:
        return f"Password must be at least {MIN_PASSWORD_LEN} characters."
    return None


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Sessions:
    """Stateless signed sessions: payload {exp, csrf} + HMAC. The key lives in the data dir (0600)
    so sessions survive restarts; deleting the file logs everyone out."""

    def __init__(self, data_dir: str | Path):
        self._path = Path(data_dir) / ".session_secret"
        self._key: bytes | None = None

    def _secret(self) -> bytes:
        if self._key is None:
            try:
                self._key = self._path.read_bytes()
            except FileNotFoundError:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                key = secrets.token_bytes(32)
                fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(key)
                self._key = key
        return self._key

    def rotate(self) -> None:
        """Replace the signing key: every previously issued cookie becomes invalid."""
        self._key = secrets.token_bytes(32)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".new")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(self._key)
        os.replace(tmp, self._path)

    def issue(self, ttl: int = SESSION_TTL, now: float | None = None) -> tuple[str, str]:
        """Returns (cookie_value, csrf_token)."""
        csrf = secrets.token_urlsafe(16)
        body = _b64(json.dumps({"exp": int((now or time.time()) + ttl), "csrf": csrf}).encode())
        sig = _b64(hmac.new(self._secret(), body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}", csrf

    def verify(self, cookie: str | None, now: float | None = None) -> dict | None:
        if not cookie or "." not in cookie:
            return None
        body, _, sig = cookie.partition(".")
        good = _b64(hmac.new(self._secret(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, good):
            return None
        try:
            data = json.loads(_unb64(body))
        except (ValueError, TypeError):
            return None
        return data if data.get("exp", 0) >= (now or time.time()) else None


class LoginLimiter:
    """Lock a client out for `lockout` seconds after `max_fails` failures within `window`."""

    def __init__(self, max_fails: int = 5, window: int = 300, lockout: int = 300, clock=time.monotonic):
        self.max_fails, self.window, self.lockout, self._clock = max_fails, window, lockout, clock
        self._fails: dict[str, list[float]] = {}
        self._locked: dict[str, float] = {}

    def blocked(self, key: str) -> int:
        """Seconds remaining of lockout (0 = allowed)."""
        until = self._locked.get(key, 0)
        left = int(until - self._clock())
        if left <= 0:
            self._locked.pop(key, None)
            return 0
        return left

    def fail(self, key: str) -> None:
        now = self._clock()
        recent = [t for t in self._fails.get(key, []) if now - t < self.window] + [now]
        self._fails[key] = recent
        if len(recent) >= self.max_fails:
            self._locked[key] = now + self.lockout
            self._fails.pop(key, None)
        if len(self._fails) > 1000:
            self._fails.clear()

    def success(self, key: str) -> None:
        self._fails.pop(key, None)
