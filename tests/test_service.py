import json

import httpx
import pytest
import respx

from tests.conftest import API, ok
from zabbix_mcp.errors import BlockedError
from zabbix_mcp.service import ZabbixService


def sent(route):
    return [json.loads(c.request.content) for c in route.calls]


@respx.mock
async def test_get_gets_defaults_and_trimming(make_store):
    svc = ZabbixService(make_store())
    route = respx.post(API).mock(return_value=httpx.Response(200, json=ok(
        [{"hostid": str(i), "pad": "x" * 500} for i in range(100)])))
    out = await svc.execute("host.get", {})
    body = sent(route)[0]["params"]
    assert body["limit"] == 50 and "hostid" in body["output"]
    assert out["truncated"] is True and out["total"] == 100 and len(out["result"]) < 100


@respx.mock
async def test_write_flow_preview_then_execute(make_store):
    svc = ZabbixService(make_store(READ_ONLY="false"))
    route = respx.post(API).mock(return_value=httpx.Response(200, json=ok({"hostids": ["1"]})))
    prev = await svc.execute("host.update", {"hostid": "1", "status": 1})
    assert prev["status"] == "confirmation_required" and route.call_count == 0
    with pytest.raises(BlockedError):
        await svc.execute("host.update", {"hostid": "1", "status": 0}, confirm_token=prev["confirm_token"])
    prev = await svc.execute("host.update", {"hostid": "1", "status": 1})
    res = await svc.execute("host.update", {"hostid": "1", "status": 1}, confirm_token=prev["confirm_token"])
    assert res == {"hostids": ["1"]} and route.call_count == 1
    with pytest.raises(BlockedError):  # token is single use
        await svc.execute("host.update", {"hostid": "1", "status": 1}, confirm_token=prev["confirm_token"])


@respx.mock
async def test_read_only_never_hits_network(make_store):
    svc = ZabbixService(make_store())
    route = respx.post(API).mock(return_value=httpx.Response(200, json=ok({})))
    with pytest.raises(BlockedError):
        await svc.execute("host.delete", ["1"])
    assert route.call_count == 0


@respx.mock
async def test_settings_hot_reload_rebuilds_client(make_store):
    store = make_store()
    svc = ZabbixService(store)
    c1 = svc.client()
    store.update({"zabbix_url": "https://other.example.com"})
    c2 = svc.client()
    assert c1 is not c2 and "other.example.com" in c2.url
    assert svc.client() is c2
