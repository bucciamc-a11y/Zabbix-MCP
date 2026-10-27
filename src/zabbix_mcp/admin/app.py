"""Admin UI backend: JSON API + static single-page app, mounted at /admin on the HTTP app.
All URLs are relative-safe so it works under a reverse-proxy path prefix."""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import re
import signal
from importlib import resources
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from .. import __version__
from ..client import ZabbixClient, normalize_url
from ..config import ConfigStore, Settings, hash_token
from ..errors import ConfigError, ZabbixMCPError
from ..registry import DEFAULT_BLOCKED_PATTERNS, DEFAULT_TOOLSETS, TOOLSETS, all_methods
from ..service import ZabbixService
from .auth import (
    LoginLimiter,
    Sessions,
    check_password_strength,
    hash_password,
    verify_password,
)

log = logging.getLogger(__name__)

EDITABLE = {
    "zabbix_url", "zabbix_api_token", "zabbix_user", "zabbix_password", "verify_tls", "ca_bundle",
    "read_only", "confirm_writes", "toolsets", "allow_methods", "deny_methods", "public_url",
    "request_timeout", "default_limit", "max_response_chars", "log_level", "audit_log",
}
RESTART_KEYS = {"toolsets", "log_level", "audit_log"}
CSRF_HEADER = "x-csrf-token"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
       "img-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
_PREFIX_OK = re.compile(r"^(/[A-Za-z0-9._~-]+)*$")
_STATIC = {"app.js": "text/javascript", "app.css": "text/css"}


def _tail_json_lines(p: Path, max_bytes: int = 65536, max_lines: int = 200) -> list[str]:
    try:
        size = p.stat().st_size
        with p.open("rb") as fh:
            fh.seek(max(size - max_bytes, 0))
            data = fh.read().decode(errors="replace")
    except OSError:
        return []
    return [ln for ln in data.splitlines() if ln.startswith("{")][-max_lines:]


def _read_static(name: str) -> bytes:
    return (resources.files("zabbix_mcp.admin") / "static" / name).read_bytes()


class Admin:
    def __init__(self, store: ConfigStore, svc: ZabbixService):
        self.store, self.svc = store, svc
        self.sessions = Sessions(store.settings.data_dir)
        self.limiter = LoginLimiter()
        self._static = {n: _read_static(n) for n in (*_STATIC, "index.html")}

    # -- helpers ------------------------------------------------------------
    def _json(self, data: Any, status: int = 200, **kw) -> JSONResponse:
        return JSONResponse(data, status_code=status, headers={"Cache-Control": "no-store"}, **kw)

    def _page(self, name: str) -> Response:
        ctype = "text/html; charset=utf-8" if name == "index.html" else _STATIC[name] + "; charset=utf-8"
        return Response(self._static[name], media_type=ctype.split(";")[0], headers={
            "Content-Security-Policy": CSP, "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store" if name == "index.html" else "public, max-age=300"})

    def _session(self, request: Request) -> dict | None:
        return self.sessions.verify(request.cookies.get("zmcp_admin"))

    async def _in(self, request: Request, mutate: bool = True) -> tuple[dict, JSONResponse | None]:
        """Authenticate; for mutating calls also check CSRF and parse the JSON object body.
        Returns (body, None) or ({}, error_response)."""
        sess = self._session(request)
        if not sess:
            return {}, self._json({"error": "unauthorized"}, 401)
        if not mutate:
            return {}, None
        if not (hmac.compare_digest(request.headers.get(CSRF_HEADER, ""), str(sess["csrf"]))
                and request.headers.get("content-type", "").startswith("application/json")):
            return {}, self._json({"error": "csrf", "message": "Missing or invalid CSRF token."}, 403)
        return await self._json_body(request)

    async def _json_body(self, request: Request) -> tuple[dict, JSONResponse | None]:
        try:
            body = await request.json()
        except Exception:
            body = None
        if not isinstance(body, dict):
            return {}, self._json({"error": "bad_request", "message": "Request body must be a JSON object."}, 400)
        return body, None

    @staticmethod
    def _client_key(request: Request) -> str:
        """Throttle key. Behind Traefik every peer is the proxy, so use the right-most
        X-Forwarded-For entry (the one the proxy appended; earlier entries are client-supplied
        and spoofable)."""
        xff = request.headers.get("x-forwarded-for", "")
        if xff and (last := xff.split(",")[-1].strip()):
            return last[:64]
        return request.client.host if request.client else "?"

    # -- routes ------------------------------------------------------------
    async def index(self, request: Request) -> Response:
        # <base> makes the relative asset/API URLs work at /admin and /admin/, with or without a
        # reverse-proxy prefix (Traefik's stripPrefix sets X-Forwarded-Prefix).
        prefix = request.headers.get("x-forwarded-prefix", "").rstrip("/")
        if not _PREFIX_OK.match(prefix):
            prefix = ""
        resp = self._page("index.html")
        resp.body = self._static["index.html"].replace(b"__BASE__", f"{prefix}/admin/".encode())
        resp.headers["content-length"] = str(len(resp.body))
        return resp

    async def static(self, request: Request) -> Response:
        name = request.path_params["name"]
        return self._page(name) if name in _STATIC else Response(status_code=404)

    async def login(self, request: Request) -> JSONResponse:
        key = self._client_key(request)
        if wait := self.limiter.blocked(key):
            return self._json({"error": "locked", "message": f"Too many attempts. Try again in {wait}s."}, 429)
        body, bad = await self._json_body(request)
        if bad:
            return bad
        pw = str(body.get("password", ""))
        stored = self.store.settings.admin_password_hash
        if not stored:
            return self._json({"error": "not_configured",
                               "message": "No admin password set. Run: zabbix-mcp set-admin-password"}, 409)
        if not await asyncio.to_thread(verify_password, pw, stored):
            self.limiter.fail(key)
            log.warning("admin login failed from %s", key)
            return self._json({"error": "invalid", "message": "Wrong password."}, 401)
        self.limiter.success(key)
        cookie, csrf = self.sessions.issue()
        secure = request.headers.get("x-forwarded-proto", request.url.scheme) == "https"
        prefix = request.headers.get("x-forwarded-prefix", "").rstrip("/")
        resp = self._json({"ok": True, "csrf": csrf})
        resp.set_cookie("zmcp_admin", cookie, max_age=8 * 3600, httponly=True, samesite="strict",
                        secure=secure, path=(prefix + "/admin") or "/admin")
        return resp

    async def logout(self, request: Request) -> JSONResponse:
        resp = self._json({"ok": True})
        prefix = request.headers.get("x-forwarded-prefix", "").rstrip("/")
        resp.delete_cookie("zmcp_admin", path=(prefix + "/admin") or "/admin")
        return resp

    async def session(self, request: Request) -> JSONResponse:
        sess = self._session(request)
        if not sess:
            return self._json({"authenticated": False,
                               "configured": bool(self.store.settings.admin_password_hash)})
        return self._json({"authenticated": True, "csrf": sess["csrf"]})

    async def state(self, request: Request) -> JSONResponse:
        if bad := (await self._in(request, False))[1]:
            return bad
        s = self.store.settings
        tokens = [h[:10] for h in s.mcp_token_hashes]
        return self._json({
            "version": __version__, "settings": s.public_dict(), "tokens": tokens,
            "toolsets": {k: list(v) for k, v in TOOLSETS.items()}, "default_toolsets": list(DEFAULT_TOOLSETS),
            "default_blocked": list(DEFAULT_BLOCKED_PATTERNS),
            "method_count": len(all_methods()),
            "endpoint": (s.public_url.rstrip("/") + "/mcp") if s.public_url else ""})

    async def save_settings(self, request: Request) -> JSONResponse:
        body, bad = await self._in(request)
        if bad:
            return bad
        changes = body.get("changes", {})
        if not isinstance(changes, dict):
            return self._json({"error": "bad_request", "message": "'changes' must be an object."}, 400)
        bad = set(changes) - EDITABLE
        if bad:
            return self._json({"error": "forbidden_keys", "message": f"Cannot edit: {sorted(bad)}"}, 400)
        before = self.store.settings
        try:
            after = self.store.update(changes)
        except ConfigError as e:
            return self._json(e.to_dict(), 400)
        restart = any(getattr(before, k) != getattr(after, k) for k in RESTART_KEYS if k in changes)
        log.info("admin changed settings: %s", sorted(k for k in changes if k not in Settings.SECRET_FIELDS))
        return self._json({"ok": True, "restart_required": restart, "settings": after.public_dict()})

    async def test_connection(self, request: Request) -> JSONResponse:
        body, bad = await self._in(request)
        if bad:
            return bad
        cand = body.get("candidate", {})
        if not isinstance(cand, dict):
            return self._json({"error": "bad_request", "message": "'candidate' must be an object."}, 400)
        cur = self.store.settings
        data = {k: getattr(cur, k) for k in ("zabbix_url", "zabbix_api_token", "zabbix_user",
                                             "zabbix_password", "verify_tls", "ca_bundle", "request_timeout")}
        for k, v in cand.items():
            if k in data and v not in (None, ""):
                data[k] = v
        # Never send the stored credentials to a different server than the one they belong to.
        try:
            moved = normalize_url(str(data["zabbix_url"])) != normalize_url(cur.zabbix_url)
        except ConfigError:
            moved = False
        if moved and not any(cand.get(k) for k in ("zabbix_api_token", "zabbix_password")):
            return self._json({"ok": False, "error": "credentials_required",
                               "message": "The URL changed: enter the API token (or password) for the new "
                                          "server; stored credentials are not sent to a different host."})
        probe = Settings(**{**cur.__dict__, **data})
        client = None
        try:
            probe.validate()
            client = ZabbixClient(probe)
            ver = await client.version()
            rows = await client.call("host.get", {"limit": 1, "output": ["hostid"]})
            return self._json({"ok": True, "version": ver, "supported": ver.startswith("7.4"),
                               "can_read_hosts": isinstance(rows, list)})
        except ZabbixMCPError as e:
            return self._json({"ok": False, **e.to_dict()})
        finally:
            if client:
                await client.aclose()

    async def tokens(self, request: Request) -> JSONResponse:
        body, bad = await self._in(request)
        if bad:
            return bad
        action = body.get("action")
        if action == "create":
            token = self.store.add_mcp_token()
            return self._json({"ok": True, "token": token, "fingerprint": hash_token(token)[:10]})
        if action == "revoke":
            fp = str(body.get("fingerprint", ""))
            full = [h for h in self.store.settings.mcp_token_hashes if len(fp) >= 8 and h.startswith(fp)]
            if not full:
                return self._json({"error": "not_found"}, 404)
            self.store.revoke_mcp_tokens(full)
            return self._json({"ok": True})
        return self._json({"error": "bad_action"}, 400)

    async def password(self, request: Request) -> JSONResponse:
        body, bad = await self._in(request)
        if bad:
            return bad
        key = self._client_key(request)
        if wait := self.limiter.blocked(key):
            return self._json({"error": "locked", "message": f"Too many attempts. Try again in {wait}s."}, 429)
        if not await asyncio.to_thread(verify_password, str(body.get("current", "")),
                                       self.store.settings.admin_password_hash):
            self.limiter.fail(key)
            return self._json({"error": "invalid", "message": "Current password is wrong."}, 401)
        self.limiter.success(key)
        new = str(body.get("new", ""))
        if msg := check_password_strength(new):
            return self._json({"error": "weak", "message": msg}, 400)
        self.store.update({"admin_password_hash": await asyncio.to_thread(hash_password, new)})
        # A password change must invalidate every other session (cookies are stateless).
        self.sessions.rotate()
        cookie, csrf = self.sessions.issue()
        resp = self._json({"ok": True, "csrf": csrf})
        prefix = request.headers.get("x-forwarded-prefix", "").rstrip("/")
        if not _PREFIX_OK.match(prefix):
            prefix = ""
        resp.set_cookie("zmcp_admin", cookie, max_age=8 * 3600, httponly=True, samesite="strict",
                        secure=request.headers.get("x-forwarded-proto", request.url.scheme) == "https",
                        path=(prefix + "/admin") or "/admin")
        return resp

    async def audit(self, request: Request) -> JSONResponse:
        if bad := (await self._in(request, False))[1]:
            return bad
        path = self.store.settings.audit_log
        if not path:
            return self._json({"configured": False, "lines": []})
        lines = await asyncio.to_thread(_tail_json_lines, Path(path))
        return self._json({"configured": True, "lines": lines})

    async def restart(self, request: Request) -> JSONResponse:
        if bad := (await self._in(request))[1]:
            return bad
        loop = asyncio.get_running_loop()
        loop.call_later(1.0, lambda: os.kill(os.getpid(), signal.SIGTERM))
        return self._json({"ok": True, "message": "Restarting; the container supervisor brings it back."})


def build_admin_app(store: ConfigStore, svc: ZabbixService) -> tuple[Starlette, Admin]:
    a = Admin(store, svc)
    app = Starlette(routes=[
        Route("/", a.index), Route("/static/{name}", a.static),
        Route("/api/login", a.login, methods=["POST"]), Route("/api/logout", a.logout, methods=["POST"]),
        Route("/api/session", a.session), Route("/api/state", a.state),
        Route("/api/settings", a.save_settings, methods=["POST"]),
        Route("/api/test-connection", a.test_connection, methods=["POST"]),
        Route("/api/tokens", a.tokens, methods=["POST"]), Route("/api/password", a.password, methods=["POST"]),
        Route("/api/audit", a.audit), Route("/api/restart", a.restart, methods=["POST"]),
    ])
    return app, a


def mount_admin(app: Starlette, store: ConfigStore, svc: ZabbixService) -> None:
    sub, admin = build_admin_app(store, svc)
    # "/admin" without a trailing slash serves the page directly (a redirect would drop any
    # reverse-proxy path prefix).
    app.router.routes.append(Route("/admin", admin.index))
    app.router.routes.append(Mount("/admin", app=sub))
