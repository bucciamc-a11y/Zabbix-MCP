import json

import respx
from mcp.shared.memory import create_connected_server_and_client_session as connect

from tests.fake import FakeZabbix
from zabbix_mcp.server import build_server

DASH = {"dashboardid": "7", "name": "NOC", "private": "1", "pages": [
    {"dashboard_pageid": "11", "name": "", "widgets": [
        {"widgetid": "100", "type": "clock", "name": "Clock", "x": "0", "y": "0", "width": "18",
         "height": "5", "view_mode": "0", "fields": []},
        {"widgetid": "101", "type": "problems", "name": "Probs", "x": "18", "y": "0", "width": "36",
         "height": "5", "view_mode": "0", "fields": [{"type": 1, "name": "reference", "value": "AAAAA"}]}]}]}


async def call(mcp, tool, args):
    async with connect(mcp._mcp_server) as c:
        r = await c.call_tool(tool, args)
    t = r.content[0].text
    return r.isError, json.loads(t[t.index('{'):] if t.startswith('Error') else t)


async def test_add_widget_preserves_existing_and_places_new(make_store):
    with respx.mock(assert_all_called=False) as router:
        z = FakeZabbix(router).on("dashboard.get", [DASH]).on("dashboard.update", {"dashboardids": ["7"]})
        mcp, _ = build_server(make_store(READ_ONLY="false", CONFIRM_WRITES="none"))
        err, out = await call(mcp, "manage_dashboard", {
            "operation": "add_widget", "dashboard": "NOC",
            "widgets": [{"type": "item", "name": "Load", "fields": {"itemid": 5, "show": [1, 2]}}]})
        assert not err and out == {"dashboardids": ["7"]}
        sent = z.params("dashboard.update")
        ws = sent["pages"][0]["widgets"]
        assert sent["dashboardid"] == "7" and sent["pages"][0]["dashboard_pageid"] == "11"
        assert [w.get("widgetid") for w in ws] == ["100", "101", None]  # existing ids retained
        new = ws[2]
        assert (new["x"], new["y"]) == (54, 0)  # first free slot to the right
        assert {"type": 4, "name": "itemid", "value": 5} in new["fields"]


async def test_dashboard_write_needs_confirmation_by_default(make_store):
    with respx.mock(assert_all_called=False) as router:
        z = FakeZabbix(router).on("dashboard.get", [DASH]).on("dashboard.update", {})
        mcp, _ = build_server(make_store(READ_ONLY="false"))
        err, out = await call(mcp, "manage_dashboard", {"operation": "rename", "dashboard": "7", "name": "X"})
        assert not err and out["status"] == "confirmation_required" and z.count("dashboard.update") == 0


async def test_remove_widget_and_missing(make_store):
    with respx.mock(assert_all_called=False) as router:
        z = FakeZabbix(router).on("dashboard.get", [DASH]).on("dashboard.update", {})
        mcp, _ = build_server(make_store(READ_ONLY="false", CONFIRM_WRITES="none"))
        err, _ = await call(mcp, "manage_dashboard", {"operation": "remove_widget", "dashboard": "7",
                                                      "widget_name": "Clock"})
        assert not err and [w["widgetid"] for w in z.params("dashboard.update")["pages"][0]["widgets"]] == ["101"]
        err, out = await call(mcp, "manage_dashboard", {"operation": "remove_widget", "dashboard": "7",
                                                        "widget_name": "Nope"})
        assert err and "No widget named" in out["message"]


async def test_create_validates_before_sending(make_store):
    with respx.mock(assert_all_called=False) as router:
        z = FakeZabbix(router).on("dashboard.create", {"dashboardids": ["9"]})
        mcp, _ = build_server(make_store(READ_ONLY="false", CONFIRM_WRITES="none"))
        err, out = await call(mcp, "manage_dashboard", {
            "operation": "create", "name": "Bad",
            "widgets": [{"type": "nonsense", "name": "x", "x": 0, "y": 0, "width": 5, "height": 5}]})
        assert err and "unknown widget type" in out["message"] and z.count("dashboard.create") == 0
        err, out = await call(mcp, "manage_dashboard", {
            "operation": "create", "name": "Good", "private": False,
            "widgets": [{"type": "clock", "name": "c"}, {"type": "systeminfo", "name": "s"}]})
        assert not err
        p = z.params("dashboard.create")
        assert p["private"] == 0 and len(p["pages"][0]["widgets"]) == 2
        a, b = p["pages"][0]["widgets"]
        assert (a["x"], b["x"]) == (0, 18)


async def test_catalog_and_read_only_list(make_store):
    with respx.mock(assert_all_called=False) as router:
        FakeZabbix(router).on("dashboard.get", [{"dashboardid": "7", "name": "NOC", "private": "0"}])
        mcp, _ = build_server(make_store())  # read-only default: list still works
        err, out = await call(mcp, "manage_dashboard", {"operation": "list"})
        assert not err and out == [{"dashboardid": "7", "name": "NOC", "private": False}]
        err, cat = await call(mcp, "dashboard_widget_catalog", {})
        assert "problems" in cat["widgets"] and cat["grid"].startswith("72")
        err, out = await call(mcp, "manage_dashboard", {"operation": "delete", "dashboard": "7"})
        assert err and "read-only" in out["message"]
