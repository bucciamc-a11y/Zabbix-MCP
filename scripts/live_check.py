#!/usr/bin/env python3
"""Exercise every curated tool against a REAL Zabbix 7.4 server through the MCP protocol.

  ZABBIX_URL=https://zabbix.example.com ZABBIX_API_TOKEN=... python scripts/live_check.py
  ... --write     also create + delete a temporary maintenance window and dashboard

Read-only by default: safe to run against production. Exit code 1 if any check fails."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
import time

from mcp.shared.memory import create_connected_server_and_client_session as connect

from zabbix_mcp.config import ConfigStore
from zabbix_mcp.server import build_server

RESULTS: list[tuple[str, bool, str]] = []


def parse(res):
    t = res.content[0].text
    return json.loads(t[t.index("{"):] if t.startswith("Error") and "{" in t else t)


async def check(client, name, tool, args=None, expect=None):
    t0 = time.perf_counter()
    try:
        res = await client.call_tool(tool, args or {})
        data = parse(res)
        ok = not res.isError and (expect is None or expect(data))
        detail = "" if ok else json.dumps(data)[:300]
    except Exception as e:  # noqa: BLE001
        ok, data, detail = False, None, f"{type(e).__name__}: {e}"
    RESULTS.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  ({(time.perf_counter() - t0) * 1000:.0f} ms)"
          + (f"\n      {detail}" if detail else ""))
    return data


async def main(write: bool) -> int:
    d = tempfile.mkdtemp()
    env = {**os.environ, "DATA_DIR": d, "READ_ONLY": "false" if write else "true",
           "CONFIRM_WRITES": "none", "MCP_TRANSPORT": "stdio"}
    store = ConfigStore(os.path.join(d, "config.json"), env=env)
    mcp, svc = build_server(store)
    async with connect(mcp._mcp_server) as c:
        st = await check(c, "get_server_status", "get_server_status",
                         expect=lambda r: str(r["version"]).startswith("7.4"))
        print(f"      Zabbix {st['version'] if st else '?'}")
        hosts = await check(c, "search_hosts", "search_hosts", {"query": "*"}, lambda r: "hosts" in r)
        await check(c, "list_host_groups", "list_host_groups", {}, lambda r: isinstance(r, list | dict))
        host = (hosts or {}).get("hosts", [{}])[0].get("name") if hosts and hosts.get("hosts") else None
        if host:
            await check(c, "get_host_details", "get_host_details", {"host": host},
                        lambda r: r.get("found", True) is not False)
            vals = await check(c, "get_latest_values", "get_latest_values", {"host": host, "limit": 5},
                               lambda r: "items" in r)
            if vals and vals.get("items"):
                key = vals["items"][0]["key"]
                await check(c, "query_metrics_history", "query_metrics_history",
                            {"host": host, "item": key, "minutes": 60}, lambda r: "items" in r or "found" in r)
                await check(c, "query_metrics_history(trends)", "query_metrics_history",
                            {"host": host, "item": key, "minutes": 10080}, lambda r: "items" in r or "found" in r)
            await check(c, "get_triggers", "get_triggers", {"host": host, "only_problems": False}, lambda r: "triggers" in r)
        await check(c, "get_active_problems", "get_active_problems", {"min_severity": "information",
                    "unacknowledged_only": False}, lambda r: "problems" in r)
        await check(c, "get_problem_events", "get_problem_events", {"hours": 720}, lambda r: "events" in r)
        await check(c, "get_audit_log", "get_audit_log", {"hours": 720}, lambda r: "entries" in r)
        await check(c, "get_sla_report(list)", "get_sla_report", {}, lambda r: "slas" in r)
        await check(c, "manage_maintenance_window(list)", "manage_maintenance_window", {"operation": "list"},
                    lambda r: "maintenance" in r)
        await check(c, "manage_dashboard(list)", "manage_dashboard", {"operation": "list"}, lambda r: isinstance(r, list | dict))
        await check(c, "dashboard_widget_catalog", "dashboard_widget_catalog", {}, lambda r: "widgets" in r)
        await check(c, "zabbix_raw_api(item.get)", "zabbix_raw_api",
                    {"method": "item.get", "params": {"limit": 1}}, lambda r: isinstance(r, list | dict))
        await check(c, "zabbix_hosts(hostgroup.get)", "zabbix_hosts", {"method": "hostgroup.get"},
                    lambda r: isinstance(r, list | dict))
        await check(c, "zabbix_monitoring(trigger.get)", "zabbix_monitoring", {"method": "trigger.get"},
                    lambda r: isinstance(r, list | dict))

        if write:
            name = f"zmcp-live-check-{int(time.time())}"
            grp = await check(c, "list groups for maintenance", "list_host_groups", {"search": "*"}, None)
            gname = (grp[0] if isinstance(grp, list) else (grp or {}).get("result", [{}])[0]).get("name")
            if gname:
                await check(c, "maintenance create", "manage_maintenance_window", {
                    "operation": "create", "name": name, "groups": [gname], "duration_minutes": 5},
                    lambda r: "maintenanceids" in r)
                await check(c, "maintenance list shows it", "manage_maintenance_window", {"operation": "list"},
                            lambda r: any(m["name"] == name for m in r["maintenance"]))
                await check(c, "maintenance delete", "manage_maintenance_window",
                            {"operation": "delete", "name": name}, lambda r: "maintenanceids" in r)
            dn = f"zmcp-live-dash-{int(time.time())}"
            await check(c, "dashboard create", "manage_dashboard", {
                "operation": "create", "name": dn, "widgets": [
                    {"type": "clock", "name": "Clock"}, {"type": "systeminfo", "name": "Info"}]},
                lambda r: "dashboardids" in r)
            await check(c, "dashboard add_widget", "manage_dashboard", {
                "operation": "add_widget", "dashboard": dn,
                "widgets": [{"type": "problems", "name": "Problems", "width": 36, "height": 5,
                             "fields": {"severities": [3, 4, 5], "show_lines": 10}}]},
                lambda r: "dashboardids" in r)
            got = await check(c, "dashboard get", "manage_dashboard", {"operation": "get", "dashboard": dn},
                              lambda r: len(r["pages"][0]["widgets"]) == 3)
            if got:
                print("      widgets:", [w["name"] for w in got["pages"][0]["widgets"]])
            await check(c, "dashboard remove_widget", "manage_dashboard", {
                "operation": "remove_widget", "dashboard": dn, "widget_name": "Clock"},
                lambda r: "dashboardids" in r)
            await check(c, "dashboard delete", "manage_dashboard", {"operation": "delete", "dashboard": dn},
                        lambda r: "dashboardids" in r)
    await svc.aclose()
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="also test create/delete (temporary objects)")
    sys.exit(asyncio.run(main(ap.parse_args().write)))
