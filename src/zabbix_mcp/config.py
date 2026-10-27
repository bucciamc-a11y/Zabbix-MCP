"""Configuration: environment variables seed defaults; a JSON file on the data volume
(editable from the admin UI) overrides them. Secrets live only in that 0600 file/env."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .registry import DEFAULT_TOOLSETS, TOOLSETS

CONFIRM_MODES = ("all", "destructive", "none")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _bool(v: Any, default: bool) -> bool:
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _list(v: Any) -> list[str]:
    if v is None or v == "":
        return []
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in str(v).split(",") if x.strip()]


@dataclass
class Settings:
    zabbix_url: str = ""
    zabbix_api_token: str = ""
    zabbix_user: str = ""
    zabbix_password: str = ""
    verify_tls: bool = True
    ca_bundle: str = ""
    read_only: bool = True
    confirm_writes: str = "all"
    toolsets: list[str] = field(default_factory=lambda: list(DEFAULT_TOOLSETS))
    allow_methods: list[str] = field(default_factory=list)
    deny_methods: list[str] = field(default_factory=list)
    transport: str = "stdio"
    host: str = "0.0.0.0"
    port: int = 8000
    public_url: str = ""  # e.g. https://example.com/zabbix-mcp (informational + host allowlist)
    mcp_token_hashes: list[str] = field(default_factory=list)  # sha256 hex of bearer tokens
    request_timeout: float = 30.0
    default_limit: int = 50
    max_response_chars: int = 20000
    log_level: str = "INFO"
    audit_log: str = ""  # path; empty = stderr
    data_dir: str = "/data"
    admin_enabled: bool = False
    admin_password_hash: str = ""  # pbkdf2 string, see admin.auth

    SECRET_FIELDS = ("zabbix_api_token", "zabbix_password", "admin_password_hash")

    def validate(self) -> None:
        if self.transport not in ("stdio", "http"):
            raise ConfigError(f"transport must be 'stdio' or 'http', got {self.transport!r}")
        if self.confirm_writes not in CONFIRM_MODES:
            raise ConfigError(f"confirm_writes must be one of {CONFIRM_MODES}")
        bad = [t for t in self.toolsets if t not in TOOLSETS]
        if bad:
            raise ConfigError(f"unknown toolsets {bad}; valid: {sorted(TOOLSETS)}")
        if not 1 <= self.port <= 65535:
            raise ConfigError("port out of range")
        if self.request_timeout <= 0:
            raise ConfigError("request_timeout must be greater than 0")
        if self.default_limit < 1 or self.max_response_chars < 1000:
            raise ConfigError("default_limit must be >=1 and max_response_chars >=1000")

    def public_dict(self) -> dict:
        """Settings safe to display: secrets replaced by a set/unset flag."""
        d = asdict(self)
        for k in self.SECRET_FIELDS:
            d[k] = bool(d[k])
        d["mcp_token_count"] = len(d.pop("mcp_token_hashes"))
        return d


_ENV = {
    "ZABBIX_URL": "zabbix_url", "ZABBIX_API_TOKEN": "zabbix_api_token",
    "ZABBIX_USER": "zabbix_user", "ZABBIX_PASSWORD": "zabbix_password",
    "ZABBIX_VERIFY_TLS": "verify_tls", "ZABBIX_CA_BUNDLE": "ca_bundle",
    "READ_ONLY": "read_only", "CONFIRM_WRITES": "confirm_writes",
    "ZABBIX_TOOLSETS": "toolsets", "ZABBIX_ALLOW_METHODS": "allow_methods",
    "ZABBIX_DENY_METHODS": "deny_methods", "MCP_TRANSPORT": "transport",
    "MCP_HOST": "host", "MCP_PORT": "port", "MCP_PUBLIC_URL": "public_url",
    "REQUEST_TIMEOUT": "request_timeout", "DEFAULT_LIMIT": "default_limit",
    "MAX_RESPONSE_CHARS": "max_response_chars", "LOG_LEVEL": "log_level",
    "AUDIT_LOG": "audit_log", "DATA_DIR": "data_dir", "ADMIN_ENABLED": "admin_enabled",
}
_TYPES = {f.name: f.type for f in fields(Settings)}


def _coerce(name: str, value: Any) -> Any:
    t = str(_TYPES.get(name, "str"))
    try:
        if t.startswith("bool"):
            return _bool(value, getattr(Settings(), name))
        if t.startswith("int"):
            return int(value)
        if t.startswith("float"):
            return float(value)
        if t.startswith("list"):
            return _list(value)
    except (TypeError, ValueError) as e:
        raise ConfigError(f"invalid value for {name}: {value!r}") from e
    return "" if value is None else str(value)


def settings_from_env(env: dict[str, str] | None = None) -> Settings:
    env = os.environ if env is None else env
    s = Settings()
    for var, name in _ENV.items():
        if env.get(var) not in (None, ""):
            setattr(s, name, _coerce(name, env[var]))
    if env.get("MCP_AUTH_TOKEN"):
        s.mcp_token_hashes = [hash_token(env["MCP_AUTH_TOKEN"])]
    return s


def env_changes(env: dict[str, str] | None = None) -> dict[str, Any]:
    """Settings explicitly present in the environment (used by `zabbix-mcp init`)."""
    env = os.environ if env is None else env
    return {name: _coerce(name, env[var]) for var, name in _ENV.items() if env.get(var) not in (None, "")}


class ConfigStore:
    """Thread-safe settings holder with cheap hot reload (stat on mtime) and atomic save."""

    def __init__(self, path: str | Path | None = None, env: dict[str, str] | None = None):
        self._env = env
        base = settings_from_env(env)
        self.path = Path(path) if path else Path(base.data_dir) / "config.json"
        self._lock = threading.RLock()
        self._mtime = 0.0
        self._settings = base
        self.reload(force=True)

    @property
    def settings(self) -> Settings:
        self.reload()
        return self._settings

    def reload(self, force: bool = False) -> bool:
        with self._lock:
            try:
                mtime = self.path.stat().st_mtime
            except FileNotFoundError:
                if force:
                    self._settings.validate()
                return False
            if not force and mtime == self._mtime:
                return False
            try:
                data = json.loads(self.path.read_text())
            except (OSError, json.JSONDecodeError) as e:
                raise ConfigError(f"cannot read {self.path}: {e}") from e
            s = settings_from_env(self._env)
            for k, v in data.items():
                if k in _TYPES:
                    setattr(s, k, _coerce(k, v))
            s.validate()
            self._settings, self._mtime = s, mtime
            return True

    def update(self, changes: dict[str, Any]) -> Settings:
        """Validate and persist changes (only known keys). Blank secret values are ignored
        so the UI can leave them untouched."""
        with self._lock:
            self.reload()  # never overwrite changes another process (CLI, installer) saved meanwhile
            current = asdict(self._settings)
            for k, v in changes.items():
                if k not in _TYPES:
                    raise ConfigError(f"unknown setting {k!r}")
                if k in Settings.SECRET_FIELDS and v in (None, ""):
                    continue
                current[k] = _coerce(k, v)
            new = Settings(**current)
            new.validate()
            self._write(current)
            self._settings = new
            return new

    def add_mcp_token(self) -> str:
        """Create a bearer token; only its hash is stored. Returns the plaintext once."""
        token = "zmcp_" + secrets.token_urlsafe(32)
        with self._lock:
            hashes = [*self._settings.mcp_token_hashes, hash_token(token)]
            self.update({"mcp_token_hashes": hashes})
        return token

    def revoke_mcp_tokens(self, hashes: list[str] | None = None) -> None:
        with self._lock:
            keep = [] if hashes is None else [
                h for h in self._settings.mcp_token_hashes if h not in hashes]
            self.update({"mcp_token_hashes": keep})

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, self.path)
        self._mtime = self.path.stat().st_mtime
