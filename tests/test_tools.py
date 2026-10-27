import json
import time

import pytest
import respx
from mcp.shared.memory import create_connected_server_and_client_session as connect

from tests.fake import FakeZabbix
from zabbix_mcp.server import build_server

NOW = int(time.time())


async def run(store_, tool, args=None):
    """Call a tool through a real in-memory MCP session."""
    mcp, svc = build_server(store_)
    async with connect(mcp._mcp_server) as client:
        res = await client.call_tool(tool, args or {})
    text = res.content[0].text
    return res.isError, json.loads(text[text.index('{'):] if text.startswith('Error') else text)


@pytest.fixture
def zbx():
    with respx.mock(assert_all_called=False) as router:
        yield FakeZabbix(router)


async def test_tool_inventory(make_store):
    mcp, _ = build_server(make_store())
    async with connect(mcp._mcp_server) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    for name in ("get_active_problems", "get_host_details", "query_metrics_history",
                 "acknowledge_problem", "manage_maintenance_window", "manage_dashboard",
                 "zabbix_raw_api", "zabbix_search_methods", "zabbix_describe_method",
                 "zabbix_monitoring", "zabbix_hosts", "zabbix_visualization"):
        assert name in tools, name
    assert "zabbix_admin" not in tools  # admin toolset is opt-in
    assert tools["get_active_problems"].annotations.readOnlyHint is True
    assert tools["acknowledge_problem"].annotations.destructiveHint is True
    # token budget guard: all tool definitions together stay modest
    size = sum(len(json.dumps(t.model_dump(mode="json"))) for t in tools.values())
    assert size < 40000, size


async def test_active_problems(make_store, zbx):
    zbx.on("problem.get", [
        {"eventid": "9", "objectid": "55", "name": "CPU high", "severity": "4",
         "clock": str(NOW - 7500), "acknowledged": "0", "opdata": "load 9.1"}])
    zbx.on("trigger.get", {"55": {"triggerid": "55", "hosts": [{"name": "web-01"}]}})
    err, out = await run(make_store(), "get_active_problems", {})
    assert not err and out["count"] == 1
    p = out["problems"][0]
    assert p["host"] == "web-01" and p["severity"] == "high" and p["age"] == "2h5m" and p["ack"] is False
    sent = zbx.params("problem.get")
    assert sent["acknowledged"] is False and sent["severities"] == [3, 4, 5] and sent["limit"] == 25


async def test_active_problems_unknown_host(make_store, zbx):
    zbx.on("host.get", [])
    err, out = await run(make_store(), "get_active_problems", {"host": "nope"})
    assert not err and out["count"] == 0 and zbx.count("problem.get") == 0


async def test_host_details_fallback_when_field_rejected(make_store, zbx):
    calls = []

    def host_get(p):
        calls.append(p)
        if "active_available" in p["output"]:
            raise_ = {"code": -32602}
            return raise_
        return [{"hostid": "1", "host": "web-01", "name": "Web 01", "status": "0",
                 "description": "", "maintenance_status": "0",
                 "interfaces": [{"ip": "10.0.0.1", "dns": "", "port": "10050", "type": "1",
                                 "main": "1", "available": "1", "useip": "1"}],
                 "hostgroups": [{"name": "Linux"}], "parentTemplates": [{"name": "Linux by Zabbix agent"}],
                 "tags": [], "items": "120"}]

    # first call rejected via error response, second succeeds
    import httpx
    state = {"n": 0}

    def handler(request):
        body = json.loads(request.content)
        if body["method"] == "host.get":
            state["n"] += 1
            if state["n"] == 1:
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": {
                    "code": -32602, "message": "Invalid params.", "data": "unexpected parameter active_available"}})
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": host_get(
                {"output": body["params"]["output"]})})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "3"})

    zbx.route.mock(side_effect=handler)
    err, out = await run(make_store(), "get_host_details", {"host": "web-01"})
    assert not err and out["host"] == "web-01" and out["enabled"] is True
    assert out["interfaces"][0]["addr"] == "10.0.0.1" and out["groups"] == ["Linux"]
    assert out["open_problems"] == 3 and state["n"] == 2


async def test_metrics_history_downsample(make_store, zbx):
    zbx.on("host.get", [{"hostid": "1"}])
    zbx.on("item.get", [{"itemid": "7", "name": "CPU load", "key_": "system.cpu.load",
                         "value_type": "0", "units": ""}])
    zbx.on("history.get", [{"clock": str(NOW - i * 30), "value": str(i % 10)} for i in range(200)])
    err, out = await run(make_store(), "query_metrics_history",
                         {"host": "web-01", "item": "cpu", "minutes": 120, "max_points": 10})
    assert not err
    it = out["items"][0]
    assert it["source"] == "history" and len(it["series"]) <= 10 and it["summary"]["max"] == 9.0
    assert zbx.params("history.get")["history"] == 0


async def test_metrics_history_uses_trends_for_long_windows(make_store, zbx):
    zbx.on("host.get", [{"hostid": "1"}])
    zbx.on("item.get", [{"itemid": "7", "name": "x", "key_": "k", "value_type": "3", "units": "B"}])
    zbx.on("trend.get", [{"clock": str(NOW - i * 3600), "num": "60", "value_min": "1",
                          "value_avg": "2", "value_max": "3"} for i in range(100)])
    err, out = await run(make_store(), "query_metrics_history", {"host": "h", "item": "k", "minutes": 10080})
    assert not err and out["items"][0]["source"] == "trends(hourly)" and zbx.count("history.get") == 0


async def test_acknowledge_preview_then_execute(make_store, zbx):
    zbx.on("event.acknowledge", {"eventids": ["9"]})
    st = make_store(READ_ONLY="false")
    args = {"eventid": "9", "message": "looking", "actions": ["acknowledge"]}
    err, prev = await run(st, "acknowledge_problem", args)
    assert not err and prev["status"] == "confirmation_required" and zbx.count("event.acknowledge") == 0
    assert prev["params"]["action"] == 6  # ack(2) + message(4)
    err, done = await run(st, "acknowledge_problem", {**args, "confirm_token": prev["confirm_token"]})
    # new in-memory server has a fresh confirm store, so the token is rejected
    assert err and done["error"] == "blocked"


async def test_acknowledge_full_flow_same_server(make_store, zbx):
    zbx.on("event.acknowledge", {"eventids": ["9"]})
    mcp, _ = build_server(make_store(READ_ONLY="false"))
    async with connect(mcp._mcp_server) as c:
        r1 = json.loads((await c.call_tool("acknowledge_problem", {"eventid": "9"})).content[0].text)
        r2 = await c.call_tool("acknowledge_problem", {"eventid": "9", "confirm_token": r1["confirm_token"]})
    assert not r2.isError and json.loads(r2.content[0].text) == {"eventids": ["9"]}
    assert zbx.params("event.acknowledge") == {"eventids": ["9"], "action": 2}


async def test_read_only_blocks_acknowledge(make_store, zbx):
    err, out = await run(make_store(), "acknowledge_problem", {"eventid": "9"})
    assert err and out["error"] == "blocked" and "read-only" in out["message"]
    assert zbx.count("event.acknowledge") == 0


async def test_maintenance_create_params(make_store, zbx):
    zbx.on("host.get", [{"hostid": "10"}])
    zbx.on("hostgroup.get", [{"groupid": "4"}])
    st = make_store(READ_ONLY="false", CONFIRM_WRITES="none")
    zbx.on("maintenance.create", {"maintenanceids": ["3"]})
    err, out = await run(st, "manage_maintenance_window", {
        "operation": "create", "name": "patching", "hosts": ["web-01"], "groups": ["Linux"],
        "duration_minutes": 30})
    assert not err and out == {"maintenanceids": ["3"]}
    p = zbx.params("maintenance.create")
    assert p["hosts"] == [{"hostid": "10"}] and p["groups"] == [{"groupid": "4"}]
    assert p["active_till"] - p["active_since"] == 1800 and p["active_since"] % 60 == 0
    assert p["timeperiods"][0]["period"] == 1800 and p["maintenance_type"] == 0


async def test_server_status_survives_partial_failure(make_store, zbx):
    zbx.on("apiinfo.version", "7.4.2")
    zbx.on("host.get", lambda p: "5")
    zbx.on("problem.get", "2")
    zbx.on("proxy.get", [{"name": "p1", "operating_mode": "0", "state": "2", "lastaccess": str(NOW - 5)}])
    # hanode.get has no fake -> returns an API error that must not sink the whole report
    err, out = await run(make_store(), "get_server_status")
    assert not err and out["version"] == "7.4.2" and out["open_problems"] == "2"
    assert out["proxies"][0]["state"] == "online" and "error" in out["ha_nodes"]


async def test_raw_api_and_toolset_routing(make_store, zbx):
    zbx.on("item.get", [{"itemid": "1"}])
    st = make_store()
    err, out = await run(st, "zabbix_raw_api", {"method": "item.get", "params": {"hostids": ["1"]}})
    assert not err and out == [{"itemid": "1"}]
    assert zbx.params("item.get")["limit"] == 50  # default limit applied
    err, out = await run(st, "zabbix_hosts", {"method": "item.get"})
    assert err and "zabbix_monitoring" in out["message"]
    err, out = await run(st, "zabbix_raw_api", {"method": "user.create", "params": {}})
    assert err and out["error"] == "blocked"


async def test_describe_and_search(make_store):
    st = make_store()
    err, out = await run(st, "zabbix_describe_method", {"method": "host.create"})
    assert out["docs"].endswith("/host/create") and out["write"] and not out["allowed"]
    err, out = await run(st, "zabbix_search_methods", {"query": "maintenance"})
    assert {m["method"] for m in out["methods"]} >= {"maintenance.get", "maintenance.create"}


async def test_no_secret_in_any_error(make_store, zbx):
    zbx.on("host.get", None)
    zbx.route.mock(side_effect=__import__("httpx").ConnectError("boom"))
    err, out = await run(make_store(), "search_hosts", {"query": "web"})
    assert err and out["error"] == "connection_error" and "tok-secret-123" not in json.dumps(out)
