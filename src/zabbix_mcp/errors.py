"""Exception hierarchy. Messages are safe to show to an LLM: never contain secrets."""

from __future__ import annotations


class ZabbixMCPError(Exception):
    """Base error. `hint` tells the caller what to do next."""

    kind = "error"

    def __init__(self, message: str, *, hint: str | None = None, **extra):
        super().__init__(message)
        self.message = message
        self.hint = hint
        self.extra = extra

    def to_dict(self) -> dict:
        d = {"error": self.kind, "message": self.message}
        if self.hint:
            d["hint"] = self.hint
        d.update(self.extra)
        return d


class ConfigError(ZabbixMCPError):
    kind = "config_error"


class ZabbixConnectionError(ZabbixMCPError):
    kind = "connection_error"


class ZabbixTimeoutError(ZabbixMCPError):
    kind = "timeout"


class ZabbixHTTPError(ZabbixMCPError):
    kind = "http_error"


class ZabbixAuthError(ZabbixMCPError):
    kind = "auth_error"


class ZabbixAPIError(ZabbixMCPError):
    """JSON-RPC error returned by Zabbix."""

    kind = "zabbix_api_error"

    def __init__(self, message: str, *, code: int, data: str | None = None, method: str = "",
                 hint: str | None = None):
        super().__init__(message, hint=hint, code=code, data=data, method=method)
        self.code = code
        self.data = data
        self.method = method


class BlockedError(ZabbixMCPError):
    kind = "blocked"
