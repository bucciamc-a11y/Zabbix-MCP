"""Async Zabbix JSON-RPC client (7.4): pooled httpx, Bearer auth, retries for reads,
and error mapping to typed exceptions."""

from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Any

import httpx

from .config import Settings
from .errors import (
    ConfigError,
    ZabbixAPIError,
    ZabbixAuthError,
    ZabbixConnectionError,
    ZabbixHTTPError,
    ZabbixTimeoutError,
)

log = logging.getLogger(__name__)

ENDPOINT = "/api_jsonrpc.php"
_AUTH_MARKERS = ("not authorized", "not authorised", "session terminated",
                 "incorrect user name or password", "re-login", "no permissions",
                 "api token expired", "api token disabled")
NO_AUTH_METHODS = {"apiinfo.version", "user.login", "user.checkAuthentication"}


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ConfigError("ZABBIX_URL is not set", hint="Set the Zabbix frontend URL in settings.")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    url = url.rstrip("/")
    return url if url.endswith(".php") else url + ENDPOINT


def map_api_error(method: str, err: dict) -> ZabbixAPIError | ZabbixAuthError:
    code = int(err.get("code", 0))
    msg = str(err.get("message", "")).strip()
    data = err.get("data")
    low = f"{msg} {data}".lower()
    if any(m in low for m in _AUTH_MARKERS):
        return ZabbixAuthError(
            f"Zabbix rejected the credentials or permissions for {method}: {data or msg}",
            hint="Check the API token, that it has not expired, and that the API user's role "
                 "allows API access and this method.")
    hint = None
    if code == -32602:
        hint = "Invalid params. Use zabbix_describe_method to check the parameters for this method."
    elif code == -32500:
        hint = "Application error from Zabbix; the 'data' field explains why (often permissions or a missing object)."
    elif code == -32601:
        hint = "Method not found in this Zabbix version (server supports 7.4 methods)."
    return ZabbixAPIError(f"{msg}: {data}" if data else msg, code=code,
                          data=None if data is None else str(data), method=method, hint=hint)


class ZabbixClient:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self._s = settings
        self.url = normalize_url(settings.zabbix_url)
        verify: ssl.SSLContext | bool | str = settings.verify_tls
        if settings.verify_tls and settings.ca_bundle:
            verify = ssl.create_default_context(cafile=settings.ca_bundle)
        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.request_timeout, connect=min(10.0, settings.request_timeout)),
            verify=verify,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            headers={"Content-Type": "application/json-rpc", "Accept": "application/json"},
            transport=transport,
        )
        self._token = settings.zabbix_api_token
        self._login_lock = asyncio.Lock()
        self._id = 0
        self._version: str | None = None

    async def aclose(self) -> None:
        await self._http.aclose()

    @property
    def configured_auth(self) -> bool:
        return bool(self._token or (self._s.zabbix_user and self._s.zabbix_password))

    async def version(self) -> str:
        if self._version is None:
            self._version = str(await self.call("apiinfo.version", {}, retry=True))
            if not self._version.startswith("7.4"):
                log.warning("Connected Zabbix is %s; this server targets 7.4", self._version)
        return self._version

    async def _ensure_token(self) -> str:
        if self._token:
            return self._token
        if not (self._s.zabbix_user and self._s.zabbix_password):
            raise ConfigError("No Zabbix credentials configured",
                              hint="Set an API token (preferred) in settings.")
        async with self._login_lock:
            if not self._token:
                self._token = await self.call(
                    "user.login", {"username": self._s.zabbix_user, "password": self._s.zabbix_password},
                    retry=False)
        return self._token

    async def call(self, method: str, params: Any = None, *, retry: bool | None = None) -> Any:
        """Execute a JSON-RPC call. Reads are retried on transient network errors."""
        if retry is None:
            retry = method.endswith(".get") or method in NO_AUTH_METHODS
        headers: dict[str, str] = {}
        if method not in NO_AUTH_METHODS:
            headers["Authorization"] = f"Bearer {await self._ensure_token()}"
        self._id += 1
        body = {"jsonrpc": "2.0", "method": method, "params": params if params is not None else {},
                "id": self._id}
        attempts = 3 if retry else 1
        for attempt in range(attempts):
            try:
                resp = await self._http.post(self.url, json=body, headers=headers)
                break
            except httpx.TimeoutException as e:
                if attempt + 1 == attempts:
                    raise ZabbixTimeoutError(
                        f"Zabbix did not answer within {self._s.request_timeout:.0f}s ({method})",
                        hint="Narrow the query (filters, limit) or raise the request timeout.") from e
            except httpx.TransportError as e:
                if attempt + 1 == attempts:
                    raise ZabbixConnectionError(
                        f"Cannot reach Zabbix at {self.url}: {type(e).__name__}",
                        hint="Check the URL, DNS, firewall and TLS settings (verify_tls / CA bundle).") from e
            await asyncio.sleep(0.25 * 2 ** attempt)
        return await self._parse(method, params, resp)

    async def _parse(self, method: str, params: Any, resp: httpx.Response) -> Any:
        if resp.status_code in (401, 403):
            raise ZabbixAuthError(f"HTTP {resp.status_code} from Zabbix",
                                  hint="Check the API token and any reverse proxy in front of Zabbix.")
        if resp.status_code == 404:
            raise ZabbixHTTPError("HTTP 404: API endpoint not found",
                                  hint=f"The URL should be the Zabbix frontend; tried {self.url}")
        if resp.status_code >= 400:
            raise ZabbixHTTPError(f"HTTP {resp.status_code} from Zabbix")
        try:
            payload = resp.json()
        except ValueError as e:
            raise ZabbixHTTPError("Response was not JSON",
                                  hint="The URL probably does not point to a Zabbix API endpoint.") from e
        if "error" in payload:
            err = map_api_error(method, payload["error"])
            if isinstance(err, ZabbixAuthError) and method not in NO_AUTH_METHODS \
                    and self._s.zabbix_user and not self._s.zabbix_api_token:
                # session token from legacy login expired: re-login once
                self._token = ""
                return await self.call(method, params, retry=False)
            raise err
        return payload.get("result")
