"""Regression tests for the issues found in the code review (see FIXES.md)."""

import json
import logging
import time

import respx
from mcp.shared.memory import create_connected_server_and_client_session as connect
from starlette.testclient import TestClient

from tests.fake import FakeZabbix
from zabbix_mcp.config import ConfigStore
from zabbix_mcp.guard import evaluate
from zabbix_mcp.logging_setup import Audit, mask_obj
from zabbix_mcp.server import build_http_app, build_server
from zabbix_mcp.tools.dashboards import build_widget, expand_fields
from zabbix_mcp.trim import shrink

NOW = int(time.time())


async def run(store, tool, args=None):
    mcp, _ = build_server(store)
    async with connect(mcp._mcp_server) as client:
        res = await client.call_tool(tool, args or {})
    t = res.content[0].text
    return res.isError, json.loads(t[t.index("{"):] if t.startswith("Error") else t)


# --- trim -----------------------------------------------------------------------------------
def test_shrink_caps_a_single_oversized_list_item():
    big = [{"blob": "x" * 5000}]
    value, info = shrink(big, 1000)
    assert info and info["truncated"] and len(json.dumps(value)) <= 1100


# --- curated tools ----------------------------------------------------------------------------
async def test_include_suppressed_does_not_mean_only_suppressed(make_store):
    with respx.mock(assert_all_called=False) as router:
        z = FakeZabbix(router).on("problem.get", [])
        await run(make_store(), "get_active_problems", {"include_suppressed": True})
        assert "suppressed" not in z.params("problem.get")  # omitted => both kinds
        await run(make_store(), "get_active_problems", {})
        assert z.params("problem.get")["suppressed"] is False


async def test_long_trend_window_requests_enough_rows(make_store):
    with respx.mock(assert_all_called=False) as router:
        z = (FakeZabbix(router).on("host.get", [{"hostid": "1"}])
             .on("item.get", [{"itemid": "9", "name": "CPU", "key_": "k", "value_type": "0", "units": ""}])
             .on("trend.get", []))
        await run(make_store(), "query_metrics_history", {"host": "h", "item": "k", "minutes": 525600})
        assert z.params("trend.get")["limit"] >= 8760


# --- toolsets are enforced for the raw escape hatch ---------------------------------------------
async def test_raw_api_cannot_reach_disabled_toolsets(make_store):
    with respx.mock(assert_all_called=False) as router:
        z = FakeZabbix(router).on("proxy.get", [])
        st = make_store(ZABBIX_TOOLSETS="monitoring")
        err, out = await run(st, "zabbix_raw_api", {"method": "proxy.get"})
        assert err and "not enabled" in out["message"] and z.count("proxy.get") == 0
        st2 = make_store(ZABBIX_TOOLSETS="monitoring,hosts")
        err, out = await run(st2, "zabbix_raw_api", {"method": "proxy.get"})
        assert not err or "not enabled" not in out.get("message", "")


# --- guard ---------------------------------------------------------------------------------
def test_massupdate_and_propagate_need_confirmation_in_destructive_mode(make_store):
    s = make_store(READ_ONLY="false", CONFIRM_WRITES="destructive").settings
    assert evaluate(s, "host.massupdate").needs_confirm
    assert evaluate(s, "hostgroup.propagate").needs_confirm
    assert not evaluate(s, "host.create").needs_confirm


# --- dashboards -------------------------------------------------------------------------------
def test_bool_widget_flags_become_integers():
    f = {x["name"]: x for x in expand_fields({"show_tags": True, "hide_empty_groups": False})}
    assert type(f["show_tags"]["value"]) is int and f["show_tags"]["value"] == 1
    assert type(f["hide_empty_groups"]["value"]) is int
    assert f["show_tags"]["type"] == 0


def test_identical_widgets_get_distinct_references():
    spec = {"type": "problems", "name": "P", "fields": {"severities": [4]}}
    first = build_widget(spec, [])
    second = build_widget(spec, [first])
    refs = [next(f["value"] for f in w["fields"] if f["name"] == "reference") for w in (first, second)]
    assert refs[0] != refs[1]


async def test_remove_widget_refuses_ambiguous_names(make_store):
    dash = {"dashboardid": "7", "name": "NOC", "private": "1", "pages": [
        {"dashboard_pageid": "11", "widgets": [
            {"widgetid": "1", "type": "clock", "name": "Dup", "x": "0", "y": "0", "width": "18", "height": "5",
             "view_mode": "0", "fields": []},
            {"widgetid": "2", "type": "clock", "name": "Dup", "x": "18", "y": "0", "width": "18", "height": "5",
             "view_mode": "0", "fields": []}]}]}
    with respx.mock(assert_all_called=False) as router:
        z = FakeZabbix(router).on("dashboard.get", [dash]).on("dashboard.update", {})
        st = make_store(READ_ONLY="false", CONFIRM_WRITES="none")
        err, out = await run(st, "manage_dashboard",
                             {"operation": "remove_widget", "dashboard": "NOC", "widget_name": "Dup"})
        assert err and "2 widgets" in out["message"] and z.count("dashboard.update") == 0


# --- config / logging / transport -----------------------------------------------------------
def test_update_does_not_clobber_changes_made_by_another_process(make_store, tmp_path):
    a = make_store(MCP_TRANSPORT="http")
    other = ConfigStore(a.path, env={"ZABBIX_URL": "https://zbx.example.com", "ZABBIX_API_TOKEN": "t",
                                     "DATA_DIR": str(tmp_path)})
    token = other.add_mcp_token()  # e.g. `zabbix-mcp create-token` run via docker exec
    time.sleep(0.01)
    a.update({"default_limit": 10})  # the server saves an unrelated change afterwards
    from zabbix_mcp.config import hash_token
    assert hash_token(token) in ConfigStore(a.path, env=a._env).settings.mcp_token_hashes


def test_secret_looking_params_are_masked_in_audit():
    masked = mask_obj({"tls_psk": "abc", "snmp_community": "public", "privpassphrase": "pp",
                       "name": "web-01"})
    assert masked["tls_psk"] == masked["privpassphrase"] == masked["snmp_community"] == "***"
    assert masked["name"] == "web-01"


def test_audit_stops_writing_to_old_file_when_path_cleared(tmp_path):
    p = tmp_path / "audit.log"
    Audit(str(p)).record(method="host.get", params={}, outcome="ok", ms=1, mutating=False)
    assert p.read_text().count("host.get") == 1
    Audit("")  # path cleared in settings
    logging.getLogger("zabbix_mcp.audit").info('{"x":1}')
    assert p.read_text().count("\n") == 1


def test_auth_exemption_is_exact_not_a_prefix(make_store):
    st = make_store(MCP_TRANSPORT="http", MCP_AUTH_TOKEN="zmcp_t", ADMIN_ENABLED="true")
    mcp, svc = build_server(st)
    with TestClient(build_http_app(st, mcp, svc)) as c:
        assert c.get("/healthz").status_code == 200
        assert c.get("/healthzzz").status_code == 401
        assert c.get("/adminfoo").status_code == 401
        assert c.get("/admin").status_code == 200


def test_request_timeout_must_be_positive(make_store):
    import pytest

    from zabbix_mcp.errors import ConfigError
    with pytest.raises(ConfigError):
        make_store().update({"request_timeout": 0})
