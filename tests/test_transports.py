import json
import os
import sys

import pytest
from starlette.testclient import TestClient

from zabbix_mcp.config import hash_token
from zabbix_mcp.errors import ConfigError
from zabbix_mcp.server import build_http_app, build_server

TOKEN = "zmcp_test_token_value"
H = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}


@pytest.fixture
def http_app(make_store):
    store = make_store(MCP_TRANSPORT="http", MCP_AUTH_TOKEN=TOKEN)
    mcp, svc = build_server(store)
    return build_http_app(store, mcp, svc), store


def test_requires_token_in_http_mode(make_store):
    store = make_store(MCP_TRANSPORT="http")
    mcp, svc = build_server(store)
    with pytest.raises(ConfigError):
        build_http_app(store, mcp, svc)


def test_auth_and_health(http_app):
    app, _ = http_app
    with TestClient(app) as c:
        assert c.get("/healthz").json()["status"] == "ok"
        r = c.post("/mcp", headers=H, json=INIT)
        assert r.status_code == 401 and "www-authenticate" in r.headers
        r = c.post("/mcp", headers={**H, "Authorization": "Bearer wrong"}, json=INIT)
        assert r.status_code == 401
        r = c.post("/mcp", headers={**H, "Authorization": f"Bearer {TOKEN}"}, json=INIT)
        assert r.status_code == 200
        assert r.json()["result"]["serverInfo"]["name"] == "zabbix"


def test_stateless_tools_list_without_session(http_app):
    app, _ = http_app
    h = {**H, "Authorization": f"Bearer {TOKEN}"}
    with TestClient(app) as c:
        r = c.post("/mcp", headers=h, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in r.json()["result"]["tools"]}
        assert "get_active_problems" in names and "zabbix_raw_api" in names


def test_token_revocation_is_live(http_app):
    app, store = http_app
    new = store.add_mcp_token()
    h = {**H, "Authorization": f"Bearer {new}"}
    with TestClient(app) as c:
        assert c.post("/mcp", headers=h, json=INIT).status_code == 200
        store.revoke_mcp_tokens([hash_token(new)])
        assert c.post("/mcp", headers=h, json=INIT).status_code == 401


async def test_stdio_stdout_is_clean_protocol(tmp_path):
    """A real stdio subprocess must emit only protocol frames on stdout (no log noise)."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    env = {**os.environ, "ZABBIX_URL": "https://zbx.example.com", "ZABBIX_API_TOKEN": "tok-secret-123",
           "DATA_DIR": str(tmp_path), "LOG_LEVEL": "DEBUG", "MCP_TRANSPORT": "stdio"}
    params = StdioServerParameters(command=sys.executable, args=["-m", "zabbix_mcp.server"], env=env)
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        tools = await s.list_tools()
        assert any(t.name == "get_server_status" for t in tools.tools)
        res = await s.call_tool("zabbix_describe_method", {"method": "host.get"})
        assert json.loads(res.content[0].text)["method"] == "host.get"
