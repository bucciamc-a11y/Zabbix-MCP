"""Server assembly and entry point (stdio or streamable HTTP)."""

from __future__ import annotations

import argparse
import hmac
import logging
import sys

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from . import __version__, prompts
from .config import ConfigStore, env_changes, hash_token
from .errors import ConfigError
from .logging_setup import setup_logging
from .service import ZabbixService
from .tools import curated, dashboards, registry_tools

log = logging.getLogger("zabbix_mcp")

INSTRUCTIONS = (
    "Zabbix 7.4 monitoring tools. Prefer the curated tools (get_active_problems, get_host_details, "
    "query_metrics_history, ...). For anything else use zabbix_search_methods / zabbix_describe_method "
    "and the zabbix_<domain> tools or zabbix_raw_api. Writes are two-step: the first call returns a "
    "preview and confirm_token; show the preview to the user and only repeat the call with the token "
    "after they approve. If the server is read-only, writes are refused.")


def build_server(store: ConfigStore, svc: ZabbixService | None = None) -> tuple[FastMCP, ZabbixService]:
    s = store.settings
    svc = svc or ZabbixService(store)
    http = s.transport == "http"
    mcp = FastMCP(
        "zabbix", instructions=INSTRUCTIONS, host=s.host, port=s.port,
        stateless_http=http, json_response=http, log_level=s.log_level,  # type: ignore[arg-type]
        # Behind a TLS reverse proxy the Host header is the public name; bearer auth protects access.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))
    curated.register(mcp, svc)
    dashboards.register(mcp, svc)
    registry_tools.register(mcp, svc, s.toolsets)
    prompts.register(mcp)
    return mcp, svc


class BearerAuth:
    """ASGI middleware: require 'Authorization: Bearer <token>' on protected paths. Token hashes are
    read from the live config so tokens can be added/revoked without a restart."""

    def __init__(self, app: ASGIApp, store: ConfigStore, open_prefixes: tuple[str, ...] = ("/healthz", "/admin")):
        self.app, self.store, self.open = app, store, open_prefixes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"].startswith(self.open):
            return await self.app(scope, receive, send)
        auth = Request(scope).headers.get("authorization", "")
        presented = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
        ok = False
        if presented:
            h = hash_token(presented)
            ok = any(hmac.compare_digest(h, known) for known in self.store.settings.mcp_token_hashes)
        if not ok:
            resp = JSONResponse({"error": "unauthorized"}, status_code=401,
                                headers={"WWW-Authenticate": 'Bearer realm="zabbix-mcp"'})
            return await resp(scope, receive, send)
        await self.app(scope, receive, send)


def build_http_app(store: ConfigStore, mcp: FastMCP, svc: ZabbixService):
    """Streamable-HTTP ASGI app: /mcp (bearer-protected), /healthz, optional /admin."""
    s = store.settings
    if not s.mcp_token_hashes:
        raise ConfigError("HTTP transport requires at least one MCP bearer token",
                          hint="Set MCP_AUTH_TOKEN or create a token in the admin UI / installer.")
    app = mcp.streamable_http_app()

    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "version": __version__})

    app.add_route("/healthz", healthz, methods=["GET"])
    if s.admin_enabled:
        from .admin.app import mount_admin
        mount_admin(app, store, svc)
    app.add_middleware(BearerAuth, store=store)
    return app


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="zabbix-mcp", description="Zabbix 7.4 MCP server")
    ap.add_argument("command", nargs="?", default="serve",
                    choices=["serve", "check", "init", "set-admin-password", "create-token", "show-config"],
                    help="serve (default) | check Zabbix connection | init (write config from environment) | "
                         "set-admin-password (reads stdin) | create-token | show-config")
    ap.add_argument("--new-token", action="store_true", help="init: always create an MCP access token")
    ap.add_argument("--admin-password-stdin", action="store_true", help="init: read admin password from stdin")
    ap.add_argument("--transport", choices=["stdio", "http"], help="override MCP_TRANSPORT")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--config", help="config file (default: $DATA_DIR/config.json)")
    ap.add_argument("--check", action="store_true", help="same as the 'check' command")
    return ap.parse_args(argv)


def _admin_password(store: ConfigStore) -> int:
    import getpass

    from .admin.auth import check_password_strength, hash_password
    pw = getpass.getpass("New admin password: ") if sys.stdin.isatty() else sys.stdin.readline().rstrip("\n")
    if msg := check_password_strength(pw):
        print(msg, file=sys.stderr)
        return 2
    store.update({"admin_password_hash": hash_password(pw)})
    print("Admin password updated.", file=sys.stderr)
    return 0


def _init(store: ConfigStore, args: argparse.Namespace) -> int:
    """Persist environment-provided settings to the config file (idempotent). Prints a new MCP
    token on stdout when one is created; everything else goes to stderr."""
    store.update(env_changes())
    if args.admin_password_stdin and _admin_password(store) != 0:
        return 2
    if args.new_token or not store.settings.mcp_token_hashes:
        print(store.add_mcp_token())
    print(f"Configuration written to {store.path}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    import asyncio
    import json
    import os

    args = _parse_args(argv)
    cmd = "check" if args.check else args.command
    if args.transport:
        os.environ["MCP_TRANSPORT"] = args.transport
    if args.host:
        os.environ["MCP_HOST"] = args.host
    if args.port:
        os.environ["MCP_PORT"] = str(args.port)
    try:
        store = ConfigStore(args.config)
        setup_logging(store.settings.log_level)
        s = store.settings
        if cmd == "check":
            return asyncio.run(_check(store))
        if cmd == "init":
            return _init(store, args)
        if cmd == "set-admin-password":
            return _admin_password(store)
        if cmd == "create-token":
            print(store.add_mcp_token())  # the only intended stdout output: the token itself
            return 0
        if cmd == "show-config":
            print(json.dumps(s.public_dict(), indent=2))
            return 0
        mcp, svc = build_server(store)
        log.info("zabbix-mcp %s starting (%s, read_only=%s, toolsets=%s)", __version__, s.transport,
                 s.read_only, ",".join(s.toolsets))
        if s.transport == "stdio":
            mcp.run("stdio")
        else:
            import uvicorn
            app = build_http_app(store, mcp, svc)
            uvicorn.run(app, host=s.host, port=s.port, log_level=s.log_level.lower(),
                        proxy_headers=True, forwarded_allow_ips="*", access_log=False)
        return 0
    except ConfigError as e:
        print(f"configuration error: {e.message}" + (f"\n  hint: {e.hint}" if e.hint else ""), file=sys.stderr)
        return 2


async def _check(store: ConfigStore) -> int:
    svc = ZabbixService(store)
    try:
        ver = await svc.client().version()
        print(f"OK: connected to Zabbix {ver}", file=sys.stderr)
        await svc.execute("host.get", {"limit": 1, "output": ["hostid"]})
        print("OK: API token can read hosts", file=sys.stderr)
        return 0
    except Exception as e:  # noqa: BLE001 - CLI diagnostic
        msg = getattr(e, "message", str(e))
        hint = getattr(e, "hint", None)
        print(f"FAILED: {msg}" + (f"\n  hint: {hint}" if hint else ""), file=sys.stderr)
        return 1
    finally:
        await svc.aclose()



if __name__ == "__main__":
    raise SystemExit(main())
