"""ZabbixService: the one place every tool goes through (guard -> confirm -> client -> trim -> audit).
Settings are re-read per call so admin-UI changes apply without a restart."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from . import guard
from .client import ZabbixClient
from .config import ConfigStore, Settings
from .errors import BlockedError, ZabbixMCPError
from .logging_setup import Audit
from .trim import prepare_params, shrink

log = logging.getLogger(__name__)

# Connection-affecting settings: a change rebuilds the HTTP client.
_CLIENT_KEYS = ("zabbix_url", "zabbix_api_token", "zabbix_user", "zabbix_password",
                "verify_tls", "ca_bundle", "request_timeout")


class ZabbixService:
    def __init__(self, store: ConfigStore, transport: httpx.AsyncBaseTransport | None = None):
        self.store = store
        self._transport = transport
        self._client: ZabbixClient | None = None
        self._client_sig: tuple | None = None
        self._confirms = guard.ConfirmStore()
        self._audit: Audit | None = None
        self._audit_path: str | None = None
        self._bg: set = set()

    # -- plumbing ---------------------------------------------------------
    @property
    def settings(self) -> Settings:
        return self.store.settings

    def client(self) -> ZabbixClient:
        s = self.settings
        sig = tuple(getattr(s, k) for k in _CLIENT_KEYS)
        if self._client is None or sig != self._client_sig:
            if self._client is not None:
                old = self._client
                import asyncio
                try:
                    t = asyncio.get_running_loop().create_task(old.aclose())
                    self._bg.add(t)  # keep a reference so the task is not garbage-collected mid-close
                    t.add_done_callback(self._bg.discard)
                except RuntimeError:
                    pass
            self._client = ZabbixClient(s, self._transport)
            self._client_sig = sig
        return self._client

    def audit(self) -> Audit:
        path = self.settings.audit_log
        if self._audit is None or path != self._audit_path:
            self._audit, self._audit_path = Audit(path), path
        return self._audit

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    # -- execution ---------------------------------------------------------
    async def execute(self, method: str, params: dict[str, Any] | None = None, *,
                      confirm_token: str | None = None, trim: bool = True) -> Any:
        """Run a Zabbix method with all safeguards. Returns the (possibly trimmed) result, or a
        confirmation-required dict for writes. Raises ZabbixMCPError subclasses on failure."""
        s = self.settings
        params = dict(params or {}) if not isinstance(params, list) else params
        decision = guard.evaluate(s, method)
        if not decision.allowed:
            self.audit().record(method=method, params=params, outcome="blocked", ms=0,
                                mutating=decision.mutating, detail=decision.reason)
            raise BlockedError(decision.reason)

        if decision.needs_confirm:
            if not confirm_token:
                token = self._confirms.issue(method, params)
                return {"status": "confirmation_required", "method": method, "params": params,
                        "confirm_token": token, "expires_in_seconds": guard.CONFIRM_TTL,
                        "message": "Nothing was changed. Show this to the user; if they approve, "
                                   "call again with the same arguments plus confirm_token."}
            if not self._confirms.consume(confirm_token, method, params):
                raise BlockedError("Invalid, expired, or mismatched confirm_token.",
                                   hint="Repeat the call without confirm_token to get a new preview. "
                                        "Parameters must be identical to the previewed ones.")

        send = prepare_params(method, params, s.default_limit) if trim and isinstance(params, dict) \
            else params
        t0 = time.perf_counter()
        try:
            result = await self.client().call(method, send)
        except ZabbixMCPError as e:
            self.audit().record(method=method, params=send, outcome=e.kind,
                                ms=(time.perf_counter() - t0) * 1000, mutating=decision.mutating,
                                detail=e.message)
            raise
        self.audit().record(method=method, params=send, outcome="ok",
                            ms=(time.perf_counter() - t0) * 1000, mutating=decision.mutating)
        if not trim:
            return result
        value, info = shrink(result, s.max_response_chars)
        if info:
            return {"result": value, **info}
        return value
