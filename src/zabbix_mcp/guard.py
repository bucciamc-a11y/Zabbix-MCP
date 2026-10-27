"""Safety layer: read-only mode, method allow/deny, and two-step confirmation."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from .config import Settings
from .registry import get_method

CONFIRM_TTL = 300
_MAX_PENDING = 500
_DESTRUCTIVE_ACTIONS = {"delete", "deleteglobal", "clear", "massremove", "replacehostinterfaces",
                        "execute", "import", "resettotp", "unblock"}


@dataclass
class Decision:
    allowed: bool
    reason: str = ""
    needs_confirm: bool = False
    mutating: bool = False


def _matches(method: str, patterns: list[str]) -> bool:
    return any(fnmatchcase(method, p) for p in patterns)


def evaluate(settings: Settings, method: str) -> Decision:
    if method == "apiinfo.version":
        return Decision(True)
    info = get_method(method)
    if info is None:
        return Decision(False, f"'{method}' is not a Zabbix 7.4 API method. "
                               "Use zabbix_search_methods to find the right name.")
    if _matches(method, settings.deny_methods):
        return Decision(False, f"'{method}' is denied by the deny list.", mutating=info.mutating)
    if info.mutating and settings.read_only:
        return Decision(False, "Server is in read-only mode; change requests are blocked. "
                               "An administrator can disable read-only mode in the settings.",
                        mutating=True)
    if info.blocked_by_default and not _matches(method, settings.allow_methods):
        return Decision(False, f"'{method}' is blocked by default for safety. An administrator "
                               "can allow it via the allow list.", mutating=info.mutating)
    if not info.mutating:
        return Decision(True)
    mode = settings.confirm_writes
    needs = mode == "all" or (mode == "destructive" and info.action in _DESTRUCTIVE_ACTIONS)
    return Decision(True, needs_confirm=needs, mutating=True)


def _fingerprint(method: str, params: Any) -> str:
    raw = json.dumps([method, params], sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


class ConfirmStore:
    """Single-use confirmation tokens bound to the exact method + params."""

    def __init__(self, ttl: int = CONFIRM_TTL, clock=time.monotonic):
        self._ttl, self._clock = ttl, clock
        self._pending: dict[str, tuple[str, float]] = {}

    def issue(self, method: str, params: Any) -> str:
        self._purge()
        if len(self._pending) >= _MAX_PENDING:
            oldest = min(self._pending, key=lambda k: self._pending[k][1])
            del self._pending[oldest]
        token = secrets.token_urlsafe(9)
        self._pending[token] = (_fingerprint(method, params), self._clock() + self._ttl)
        return token

    def consume(self, token: str, method: str, params: Any) -> bool:
        entry = self._pending.pop(token, None)
        return bool(entry and entry[1] >= self._clock() and entry[0] == _fingerprint(method, params))

    def _purge(self) -> None:
        now = self._clock()
        for k in [k for k, (_, exp) in self._pending.items() if exp < now]:
            del self._pending[k]
