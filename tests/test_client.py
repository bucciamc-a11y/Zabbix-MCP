import httpx
import pytest
import respx

from tests.conftest import API, err, ok
from zabbix_mcp.client import ZabbixClient, normalize_url
from zabbix_mcp.errors import (
    ConfigError,
    ZabbixAPIError,
    ZabbixAuthError,
    ZabbixConnectionError,
    ZabbixHTTPError,
    ZabbixTimeoutError,
)


def test_normalize_url():
    assert normalize_url("zbx.example.com") == "https://zbx.example.com/api_jsonrpc.php"
    assert normalize_url("http://h/zabbix/") == "http://h/zabbix/api_jsonrpc.php"
    assert normalize_url("https://h/api_jsonrpc.php") == "https://h/api_jsonrpc.php"
    with pytest.raises(ConfigError):
        normalize_url("")


@pytest.fixture
def client(make_store):
    return ZabbixClient(make_store().settings)


@respx.mock
async def test_bearer_header_and_result(client):
    route = respx.post(API).mock(return_value=httpx.Response(200, json=ok([{"hostid": "1"}])))
    assert await client.call("host.get", {"limit": 1}) == [{"hostid": "1"}]
    req = route.calls[0].request
    assert req.headers["authorization"] == "Bearer tok-secret-123"
    assert req.headers["content-type"] == "application/json-rpc"
    assert b'"jsonrpc":"2.0"' in req.content.replace(b" ", b"")


@respx.mock
async def test_apiinfo_version_has_no_auth_and_is_cached(client):
    route = respx.post(API).mock(return_value=httpx.Response(200, json=ok("7.4.1")))
    assert await client.version() == "7.4.1"
    assert await client.version() == "7.4.1"
    assert route.call_count == 1
    assert "authorization" not in route.calls[0].request.headers


@respx.mock
async def test_invalid_params_mapped(client):
    respx.post(API).mock(return_value=httpx.Response(
        200, json=err(-32602, "Invalid params.", "Invalid parameter \"/\": unexpected parameter \"x\".")))
    with pytest.raises(ZabbixAPIError) as ei:
        await client.call("host.get", {"x": 1})
    assert ei.value.code == -32602 and "zabbix_describe_method" in ei.value.hint


@respx.mock
async def test_app_error_mapped(client):
    respx.post(API).mock(return_value=httpx.Response(
        200, json=err(-32500, "Application error.", "No permissions to referred object or it does not exist!")))
    with pytest.raises(ZabbixAuthError):
        await client.call("host.get", {})


@respx.mock
async def test_not_authorised_is_auth_error_without_leaking_token(client):
    respx.post(API).mock(return_value=httpx.Response(
        200, json=err(-32602, "Invalid params.", "Not authorized.")))
    with pytest.raises(ZabbixAuthError) as ei:
        await client.call("host.get", {})
    assert "tok-secret-123" not in str(ei.value.to_dict())


@respx.mock
@pytest.mark.parametrize("status,exc", [(401, ZabbixAuthError), (403, ZabbixAuthError),
                                        (404, ZabbixHTTPError), (502, ZabbixHTTPError)])
async def test_http_errors(client, status, exc):
    respx.post(API).mock(return_value=httpx.Response(status))
    with pytest.raises(exc):
        await client.call("host.get", {})


@respx.mock
async def test_non_json(client):
    respx.post(API).mock(return_value=httpx.Response(200, text="<html>login</html>"))
    with pytest.raises(ZabbixHTTPError):
        await client.call("host.get", {})


@respx.mock
async def test_reads_retry_then_succeed(client, monkeypatch):
    async def nosleep(_):
        return None
    monkeypatch.setattr("zabbix_mcp.client.asyncio.sleep", nosleep)
    route = respx.post(API).mock(side_effect=[httpx.ConnectError("x"),
                                              httpx.Response(200, json=ok([]))])
    assert await client.call("host.get", {}) == []
    assert route.call_count == 2


@respx.mock
async def test_writes_not_retried(client):
    route = respx.post(API).mock(side_effect=httpx.ConnectError("x"))
    with pytest.raises(ZabbixConnectionError):
        await client.call("host.update", {"hostid": "1"})
    assert route.call_count == 1


@respx.mock
async def test_timeout_mapped(client, monkeypatch):
    async def nosleep(_):
        return None
    monkeypatch.setattr("zabbix_mcp.client.asyncio.sleep", nosleep)
    respx.post(API).mock(side_effect=httpx.ReadTimeout("t"))
    with pytest.raises(ZabbixTimeoutError):
        await client.call("host.get", {})


@respx.mock
async def test_login_fallback_and_relogin(make_store):
    s = make_store(ZABBIX_API_TOKEN="", ZABBIX_USER="u", ZABBIX_PASSWORD="pw")
    c = ZabbixClient(s.settings)
    seen = []

    def handler(request):
        import json
        body = json.loads(request.content)
        seen.append((body["method"], request.headers.get("authorization")))
        if body["method"] == "user.login":
            return httpx.Response(200, json=ok(f"sess{sum(1 for m, _ in seen if m == 'user.login')}"))
        if request.headers.get("authorization") == "Bearer sess1":
            return httpx.Response(200, json=err(-32602, "Invalid params.", "Session terminated, re-login, please."))
        return httpx.Response(200, json=ok([{"hostid": "9"}]))

    respx.post(API).mock(side_effect=handler)
    assert await c.call("host.get", {}) == [{"hostid": "9"}]
    assert [m for m, _ in seen].count("user.login") == 2


async def test_no_credentials(make_store):
    c = ZabbixClient(make_store(ZABBIX_API_TOKEN="").settings)
    with pytest.raises(ConfigError):
        await c.call("host.get", {})
