"""Tier 1: curated workflow tools. Each composes a few Zabbix calls into a compact answer."""

from __future__ import annotations

import asyncio
import re
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..errors import BlockedError
from ..service import ZabbixService
from .common import (
    READ,
    SEVERITY_INDEX,
    WRITE,
    age,
    bucketize,
    call,
    call_with_fallback,
    finish,
    gather_safe,
    iso,
    now,
    resolve_ids,
    safe,
    sev_name,
)

MinSeverity = Literal["information", "warning", "average", "high", "disaster"]
_IP_LIKE = re.compile(r"^[\d.]{3,}$")
ACK_ACTIONS = {"close": 1, "acknowledge": 2, "message": 4, "change_severity": 8, "unacknowledge": 16}
AUDIT_ACTIONS = {"add": 0, "update": 1, "delete": 2, "login": 3, "failed_login": 4, "logout": 5,
                 "execute": 6, "push": 7}
_AUDIT_NAMES = {v: k for k, v in AUDIT_ACTIONS.items()}


def _sev_list(min_sev: str) -> list[int]:
    return list(range(SEVERITY_INDEX[min_sev], 6))


def register(mcp: FastMCP, svc: ZabbixService) -> None:
    @mcp.tool(annotations=READ)
    @safe
    async def get_active_problems(
        min_severity: Annotated[MinSeverity, Field(description="Lowest severity to include")] = "average",
        unacknowledged_only: bool = True,
        host: Annotated[str | None, Field(description="Host name filter (wildcard * allowed)")] = None,
        group: Annotated[str | None, Field(description="Host group name filter (wildcard allowed)")] = None,
        include_suppressed: bool = False,
        limit: Annotated[int, Field(ge=1, le=200)] = 25,
    ):
        """Current unresolved problems (newest first) with host, severity and age."""
        p: dict[str, Any] = {
            "output": ["eventid", "objectid", "name", "severity", "clock", "acknowledged", "opdata"],
            "severities": _sev_list(min_severity), "suppressed": include_suppressed,
            "sortfield": ["eventid"], "sortorder": "DESC", "limit": limit}
        if unacknowledged_only:
            p["acknowledged"] = False
        for key, kind, val in (("hostids", "host", host), ("groupids", "group", group)):
            if val:
                ids = await resolve_ids(svc, kind, val)
                if not ids:
                    return {"count": 0, "problems": [], "note": f"No {kind} matched '{val}'."}
                p[key] = ids
        rows = await call(svc, "problem.get", p)
        hosts: dict[str, str] = {}
        if rows:
            trig = await call(svc, "trigger.get", {
                "triggerids": list({r["objectid"] for r in rows}), "output": ["triggerid"],
                "selectHosts": ["name"], "preservekeys": True})
            hosts = {tid: ", ".join(h["name"] for h in t.get("hosts", [])) for tid, t in trig.items()}
        t = now()
        out = []
        for r in rows:
            item = {"eventid": r["eventid"], "host": hosts.get(r["objectid"], "?"),
                    "problem": r["name"], "severity": sev_name(r["severity"]),
                    "age": age(t - int(r["clock"])), "ack": r["acknowledged"] == "1"}
            if r.get("opdata"):
                item["opdata"] = r["opdata"]
            out.append(item)
        return finish(svc, {"count": len(out), "problems": out})

    @mcp.tool(annotations=READ)
    @safe
    async def get_host_details(
        host: Annotated[str, Field(description="Host name or technical name (wildcard * allowed)")],
    ):
        """Status, interfaces, groups, templates, tags and item/problem counts for one host."""
        full = ["hostid", "host", "name", "status", "description", "maintenance_status",
                "active_available"]
        base = {"search": {"host": host, "name": host}, "searchByAny": True,
                "searchWildcardsEnabled": True, "limit": 5,
                "selectInterfaces": ["ip", "dns", "port", "type", "main", "available", "useip"],
                "selectHostGroups": ["name"], "selectParentTemplates": ["name"],
                "selectTags": ["tag", "value"], "selectItems": "count"}
        rows = await call_with_fallback(svc, "host.get", {**base, "output": full},
                                        {**base, "output": full[:-1]})
        if not rows:
            return {"found": False, "message": f"No host matches '{host}'. Try search_hosts."}
        if len(rows) > 1:
            exact = [r for r in rows if host in (r["host"], r["name"])]
            if len(exact) != 1:
                return {"found": True, "ambiguous": True,
                        "matches": [{"hostid": r["hostid"], "name": r["name"]} for r in rows],
                        "message": "Several hosts match; use a more specific name."}
            rows = exact
        h = rows[0]
        problems = await call(svc, "problem.get", {"hostids": [h["hostid"]], "countOutput": True})
        iface_type = {"1": "agent", "2": "snmp", "3": "ipmi", "4": "jmx"}
        avail = {"0": "unknown", "1": "available", "2": "unavailable"}
        return finish(svc, {
            "hostid": h["hostid"], "host": h["host"], "name": h["name"],
            "enabled": h["status"] == "0", "in_maintenance": h.get("maintenance_status") == "1",
            "active_agent": avail.get(h.get("active_available", "0"), "unknown"),
            "description": h.get("description", ""),
            "interfaces": [{"type": iface_type.get(i["type"], i["type"]),
                            "addr": i["ip"] if i.get("useip") == "1" else i["dns"],
                            "port": i["port"], "main": i["main"] == "1",
                            "availability": avail.get(i.get("available", "0"), "unknown")}
                           for i in h.get("interfaces", [])],
            "groups": [g["name"] for g in h.get("hostgroups", [])],
            "templates": [t["name"] for t in h.get("parentTemplates", [])],
            "tags": [f"{t['tag']}={t['value']}" if t["value"] else t["tag"] for t in h.get("tags", [])],
            "items": h.get("items"), "open_problems": int(problems)})

    @mcp.tool(annotations=READ)
    @safe
    async def search_hosts(
        query: Annotated[str, Field(description="Name fragment (wildcard *) or IP/DNS fragment")],
        group: Annotated[str | None, Field(description="Restrict to host group name")] = None,
        limit: Annotated[int, Field(ge=1, le=100)] = 20,
    ):
        """Find hosts by name, technical name, IP or DNS."""
        gids = await resolve_ids(svc, "group", group) if group else []
        if group and not gids:
            return {"count": 0, "hosts": [], "note": f"No group matches '{group}'."}
        if _IP_LIKE.match(query):
            ifs = await call(svc, "hostinterface.get", {
                "output": ["hostid", "ip", "dns"], "search": {"ip": query, "dns": query},
                "searchByAny": True, "selectHosts": ["hostid", "name", "status"], "limit": limit})
            seen: dict[str, dict] = {}
            for i in ifs:
                for h in i.get("hosts", []):
                    seen.setdefault(h["hostid"], {"hostid": h["hostid"], "name": h["name"],
                                                  "enabled": h["status"] == "0", "ip": i["ip"]})
            hosts = list(seen.values())
        else:
            p: dict[str, Any] = {
                "output": ["hostid", "host", "name", "status", "maintenance_status"],
                "search": {"host": query, "name": query}, "searchByAny": True,
                "searchWildcardsEnabled": True, "sortfield": "name", "limit": limit}
            if gids:
                p["groupids"] = gids
            rows = await call(svc, "host.get", p)
            hosts = [{"hostid": r["hostid"], "name": r["name"], "enabled": r["status"] == "0",
                      "maintenance": r["maintenance_status"] == "1"} for r in rows]
        return finish(svc, {"count": len(hosts), "hosts": hosts})

    @mcp.tool(annotations=READ)
    @safe
    async def list_host_groups(
        search: Annotated[str | None, Field(description="Name filter (wildcard allowed)")] = None,
        limit: Annotated[int, Field(ge=1, le=200)] = 50,
    ):
        """Host groups with host counts."""
        p: dict[str, Any] = {"output": ["groupid", "name"], "selectHosts": "count",
                             "sortfield": "name", "limit": limit}
        if search:
            p.update(search={"name": search}, searchWildcardsEnabled=True)
        rows = await call(svc, "hostgroup.get", p)
        return finish(svc, [{"groupid": r["groupid"], "name": r["name"], "hosts": r.get("hosts")}
                            for r in rows])

    @mcp.tool(annotations=READ)
    @safe
    async def get_triggers(
        host: Annotated[str | None, Field(description="Host name filter")] = None,
        min_severity: MinSeverity = "warning",
        only_problems: Annotated[bool, Field(description="Only triggers currently in PROBLEM state")] = True,
        limit: Annotated[int, Field(ge=1, le=200)] = 25,
    ):
        """Triggers (monitored, enabled) with severity and state."""
        p: dict[str, Any] = {
            "output": ["triggerid", "description", "priority", "value", "lastchange"],
            "expandDescription": True, "selectHosts": ["name"], "monitored": True,
            "skipDependent": True, "min_severity": SEVERITY_INDEX[min_severity],
            "sortfield": ["priority", "lastchange"], "sortorder": "DESC", "limit": limit}
        if only_problems:
            p["only_true"] = True
        if host:
            ids = await resolve_ids(svc, "host", host)
            if not ids:
                return {"count": 0, "triggers": [], "note": f"No host matches '{host}'."}
            p["hostids"] = ids
        t = now()
        rows = await call(svc, "trigger.get", p)
        return finish(svc, {"count": len(rows), "triggers": [
            {"triggerid": r["triggerid"], "host": ", ".join(h["name"] for h in r.get("hosts", [])),
             "name": r["description"], "severity": sev_name(r["priority"]),
             "state": "PROBLEM" if r["value"] == "1" else "OK",
             "since": age(t - int(r["lastchange"]))} for r in rows]})

    @mcp.tool(annotations=READ)
    @safe
    async def get_latest_values(
        host: Annotated[str, Field(description="Host name (wildcard allowed)")],
        pattern: Annotated[str | None, Field(description="Item name or key fragment, e.g. 'cpu' or 'vfs.fs'")] = None,
        limit: Annotated[int, Field(ge=1, le=200)] = 30,
    ):
        """Latest collected values of a host's items, optionally filtered by name/key."""
        ids = await resolve_ids(svc, "host", host, limit=10)
        if not ids:
            return {"count": 0, "items": [], "note": f"No host matches '{host}'."}
        p: dict[str, Any] = {
            "hostids": ids, "monitored": True, "sortfield": "name", "limit": limit,
            "output": ["itemid", "name", "key_", "lastvalue", "lastclock", "units", "state"],
            "selectHosts": ["name"]}
        if pattern:
            p.update(search={"name": pattern, "key_": pattern}, searchByAny=True,
                     searchWildcardsEnabled=True)
        rows = await call(svc, "item.get", p)
        t = now()
        return finish(svc, {"count": len(rows), "items": [
            {"itemid": r["itemid"], "host": r["hosts"][0]["name"] if r.get("hosts") else "",
             "name": r["name"], "key": r["key_"], "value": r["lastvalue"], "units": r["units"],
             "age": age(t - int(r["lastclock"])) if r["lastclock"] != "0" else "never",
             **({"unsupported": True} if r["state"] == "1" else {})} for r in rows]})

    @mcp.tool(annotations=READ)
    @safe
    async def query_metrics_history(
        host: Annotated[str, Field(description="Host name (exact or wildcard)")],
        item: Annotated[str, Field(description="Item key or name fragment, e.g. 'system.cpu.load' or 'Memory'")],
        minutes: Annotated[int, Field(ge=1, le=525600, description="Look-back window in minutes")] = 60,
        max_points: Annotated[int, Field(ge=3, le=120)] = 30,
    ):
        """History (or trends for windows >48h) of up to 5 matching items, downsampled to min/avg/max buckets."""
        hids = await resolve_ids(svc, "host", host, limit=10)
        if not hids:
            return {"found": False, "note": f"No host matches '{host}'."}
        items = await call(svc, "item.get", {
            "hostids": hids, "monitored": True, "limit": 5, "sortfield": "name",
            "output": ["itemid", "name", "key_", "value_type", "units"],
            "search": {"key_": item, "name": item}, "searchByAny": True,
            "searchWildcardsEnabled": True})
        if not items:
            return {"found": False, "note": f"No item on '{host}' matches '{item}'. Try get_latest_values."}
        t_from = now() - minutes * 60
        use_trends = minutes > 2880

        async def one(it: dict) -> dict:
            vt = int(it["value_type"])
            numeric = vt in (0, 3)
            if use_trends and numeric:
                rows = await call(svc, "trend.get", {
                    "itemids": [it["itemid"]], "time_from": t_from, "limit": 5000,
                    "output": ["clock", "num", "value_min", "value_avg", "value_max"]})
                pts = [{"t": iso(r["clock"]), "min": float(r["value_min"]), "avg": float(r["value_avg"]),
                        "max": float(r["value_max"])} for r in rows]
                step = max(len(pts) // max_points, 1)
                series: Any = pts[::step][:max_points]
                vals = [float(r["value_avg"]) for r in rows]
                src = "trends(hourly)"
            else:
                rows = await call(svc, "history.get", {
                    "itemids": [it["itemid"]], "history": vt, "time_from": t_from,
                    "sortfield": "clock", "sortorder": "DESC", "limit": 5000,
                    "output": ["clock", "value"]})
                src = "history"
                if numeric:
                    pts2 = [(int(r["clock"]), float(r["value"])) for r in rows]
                    series = bucketize(pts2, max_points)
                    vals = [v for _, v in pts2]
                else:
                    series = [{"t": iso(r["clock"]), "v": r["value"][:200]}
                              for r in rows[:max_points]]
                    vals = []
            out = {"item": it["name"], "key": it["key_"], "units": it["units"], "source": src,
                   "samples": len(rows), "series": series}
            if vals:
                out["summary"] = {"min": round(min(vals), 4), "avg": round(sum(vals) / len(vals), 4),
                                  "max": round(max(vals), 4)}
            return out

        results = await asyncio.gather(*(one(it) for it in items))
        return finish(svc, {"window_minutes": minutes, "items": results})

    @mcp.tool(annotations=READ)
    @safe
    async def get_problem_events(
        hours: Annotated[int, Field(ge=1, le=2160)] = 24,
        min_severity: MinSeverity = "warning",
        host: Annotated[str | None, Field(description="Host name filter")] = None,
        limit: Annotated[int, Field(ge=1, le=200)] = 50,
    ):
        """Problem events (including resolved ones) in a time window, newest first."""
        p: dict[str, Any] = {
            "source": 0, "object": 0, "value": 1, "time_from": now() - hours * 3600,
            "severities": _sev_list(min_severity), "sortfield": ["clock", "eventid"],
            "sortorder": "DESC", "limit": limit, "selectHosts": ["name"],
            "output": ["eventid", "name", "severity", "clock", "acknowledged", "r_eventid"]}
        if host:
            ids = await resolve_ids(svc, "host", host)
            if not ids:
                return {"count": 0, "events": [], "note": f"No host matches '{host}'."}
            p["hostids"] = ids
        rows = await call(svc, "event.get", p)
        return finish(svc, {"count": len(rows), "events": [
            {"eventid": r["eventid"], "time": iso(r["clock"]),
             "host": ", ".join(h["name"] for h in r.get("hosts", [])), "problem": r["name"],
             "severity": sev_name(r["severity"]), "resolved": r["r_eventid"] != "0",
             "ack": r["acknowledged"] == "1"} for r in rows]})

    @mcp.tool(annotations=WRITE)
    @safe
    async def acknowledge_problem(
        eventid: Annotated[str | list[str], Field(description="Event id(s) from get_active_problems")],
        actions: Annotated[list[Literal["acknowledge", "unacknowledge", "message", "change_severity", "close"]],
                           Field(description="What to do")] = ["acknowledge"],  # noqa: B006
        message: Annotated[str | None, Field(description="Comment to add")] = None,
        severity: Annotated[int | None, Field(ge=0, le=5, description="New severity for change_severity")] = None,
        confirm_token: Annotated[str | None, Field(description="Token from the preview call")] = None,
    ):
        """Acknowledge, comment on, re-rate or close problems. Two-step: first call returns a preview."""
        acts = set(actions)
        if message:
            acts.add("message")
        if "message" in acts and not message:
            raise BlockedError("'message' action needs the message text.")
        if "change_severity" in acts and severity is None:
            raise BlockedError("'change_severity' needs a severity (0-5).")
        if {"acknowledge", "unacknowledge"} <= acts:
            raise BlockedError("Choose either acknowledge or unacknowledge, not both.")
        params: dict[str, Any] = {
            "eventids": [eventid] if isinstance(eventid, str) else eventid,
            "action": sum(ACK_ACTIONS[a] for a in acts)}
        if message:
            params["message"] = message
        if "change_severity" in acts:
            params["severity"] = severity
        return await svc.execute("event.acknowledge", params, confirm_token=confirm_token, trim=False)

    @mcp.tool(annotations=WRITE)
    @safe
    async def manage_maintenance_window(
        operation: Literal["list", "create", "delete"],
        name: Annotated[str | None, Field(description="create: window name; delete: window name")] = None,
        hosts: Annotated[list[str] | None, Field(description="create: host names")] = None,
        groups: Annotated[list[str] | None, Field(description="create: host group names")] = None,
        duration_minutes: Annotated[int, Field(ge=1, le=525600)] = 60,
        start_in_minutes: Annotated[int, Field(ge=0, le=525600, description="create: delay before start")] = 0,
        data_collection: Annotated[bool, Field(description="create: keep collecting data during maintenance")] = True,
        description: str = "",
        maintenanceids: Annotated[list[str] | None, Field(description="delete: ids")] = None,
        active_only: Annotated[bool, Field(description="list: only currently active windows")] = False,
        confirm_token: Annotated[str | None, Field(description="Token from the preview call (create/delete)")] = None,
    ):
        """List, schedule (one-time) or remove maintenance windows. create/delete are two-step."""
        if operation == "list":
            rows = await call(svc, "maintenance.get", {
                "output": ["maintenanceid", "name", "maintenance_type", "active_since", "active_till"],
                "selectHostGroups": ["name"], "selectHosts": ["name"], "sortfield": "name", "limit": 100})
            t = now()
            out = []
            for r in rows:
                active = int(r["active_since"]) <= t <= int(r["active_till"])
                if active_only and not active:
                    continue
                out.append({"maintenanceid": r["maintenanceid"], "name": r["name"], "active": active,
                            "from": iso(r["active_since"]), "until": iso(r["active_till"]),
                            "data_collection": r["maintenance_type"] == "0",
                            "hosts": [h["name"] for h in r.get("hosts", [])],
                            "groups": [g["name"] for g in r.get("hostgroups", [])]})
            return finish(svc, {"count": len(out), "maintenance": out})
        if operation == "create":
            if not name or not (hosts or groups):
                raise BlockedError("create needs 'name' and at least one of 'hosts' or 'groups'.")
            hids = await resolve_ids(svc, "host", hosts) if hosts else []
            gids = await resolve_ids(svc, "group", groups) if groups else []
            if (hosts and not hids) or (groups and not gids):
                raise BlockedError("Some hosts/groups were not found; check names with search_hosts / "
                                   "list_host_groups.")
            start = (now() + start_in_minutes * 60) // 60 * 60
            params: dict[str, Any] = {
                "name": name, "active_since": start, "active_till": start + duration_minutes * 60,
                "maintenance_type": 0 if data_collection else 1, "description": description,
                "timeperiods": [{"timeperiod_type": 0, "start_date": start,
                                 "period": duration_minutes * 60}]}
            if hids:
                params["hosts"] = [{"hostid": i} for i in hids]
            if gids:
                params["groups"] = [{"groupid": i} for i in gids]
            return await svc.execute("maintenance.create", params, confirm_token=confirm_token, trim=False)
        ids = maintenanceids
        if not ids and name:
            rows = await call(svc, "maintenance.get", {"output": ["maintenanceid"], "filter": {"name": [name]}})
            ids = [r["maintenanceid"] for r in rows]
        if not ids:
            raise BlockedError("delete needs 'maintenanceids' or an existing maintenance 'name'.")
        return await svc.execute("maintenance.delete", ids, confirm_token=confirm_token, trim=False)

    @mcp.tool(annotations=READ)
    @safe
    async def get_sla_report(
        sla: Annotated[str | None, Field(description="SLA name; omit to list SLAs")] = None,
        service: Annotated[str | None, Field(description="Service name (default: all services of the SLA)")] = None,
        periods: Annotated[int, Field(ge=1, le=24, description="Number of reporting periods")] = 3,
    ):
        """SLA/SLI per service for recent periods; without 'sla' lists available SLAs."""
        if not sla:
            rows = await call(svc, "sla.get", {"output": ["slaid", "name", "period", "slo", "status"],
                                               "sortfield": "name", "limit": 100})
            return finish(svc, {"slas": rows})
        found = await call(svc, "sla.get", {"output": ["slaid", "name", "slo", "period"],
                                            "filter": {"name": [sla]}})
        if not found:
            return {"found": False, "note": f"No SLA named '{sla}'. Call without 'sla' to list them."}
        p: dict[str, Any] = {"slaid": found[0]["slaid"], "periods": periods}
        names: dict[str, str] = {}
        if service:
            svcs = await call(svc, "service.get", {"output": ["serviceid", "name"], "filter": {"name": [service]}})
            if not svcs:
                return {"found": False, "note": f"No service named '{service}'."}
            p["serviceids"] = [s["serviceid"] for s in svcs]
            names = {s["serviceid"]: s["name"] for s in svcs}
        data = await call(svc, "sla.getsli", p)
        if not names and data.get("serviceids"):
            rows = await call(svc, "service.get", {"serviceids": data["serviceids"], "output": ["serviceid", "name"]})
            names = {s["serviceid"]: s["name"] for s in rows}
        periods_out = [{"from": iso(x["period_from"]), "to": iso(x["period_to"])} for x in data.get("periods", [])]
        report = []
        for sid, series in zip(data.get("serviceids", []), data.get("sli", []), strict=False):
            report.append({"service": names.get(sid, sid), "sli": [
                {"period": periods_out[i]["from"] if i < len(periods_out) else i,
                 "sli": round(float(v["sli"]), 4), "uptime_s": v["uptime"], "downtime_s": v["downtime"],
                 "error_budget_s": v["error_budget"]} for i, v in enumerate(series)]})
        return finish(svc, {"sla": found[0]["name"], "slo": found[0]["slo"], "report": report})

    @mcp.tool(annotations=READ)
    @safe
    async def get_audit_log(
        hours: Annotated[int, Field(ge=1, le=2160)] = 24,
        user: Annotated[str | None, Field(description="Username filter")] = None,
        action: Literal["add", "update", "delete", "login", "failed_login", "logout", "execute", "push"] | None = None,
        limit: Annotated[int, Field(ge=1, le=200)] = 30,
    ):
        """Zabbix audit log entries (who changed what), newest first."""
        flt: dict[str, Any] = {}
        if user:
            flt["username"] = [user]
        if action:
            flt["action"] = [AUDIT_ACTIONS[action]]
        p: dict[str, Any] = {
            "output": ["auditid", "clock", "username", "action", "resourcetype", "resourcename",
                       "ip", "details"], "time_from": now() - hours * 3600,
            "sortfield": ["clock"], "sortorder": "DESC", "limit": limit}
        if flt:
            p["filter"] = flt
        rows = await call(svc, "auditlog.get", p)
        return finish(svc, {"count": len(rows), "entries": [
            {"time": iso(r["clock"]), "user": r["username"],
             "action": _AUDIT_NAMES.get(int(r["action"]), r["action"]),
             "resource": r["resourcename"], "resourcetype": r["resourcetype"], "ip": r["ip"],
             "details": (r.get("details") or "")[:200]} for r in rows]})

    @mcp.tool(annotations=READ)
    @safe
    async def get_server_status():
        """Zabbix version, HA nodes, proxies, host counts and open problem counts."""
        ver, ha, proxies, hosts_on, hosts_off, probs = await gather_safe(
            svc.client().version(),
            call(svc, "hanode.get", {"output": ["name", "status", "address", "lastaccess"]}),
            call(svc, "proxy.get", {"output": ["name", "operating_mode", "state", "lastaccess"], "limit": 50}),
            call(svc, "host.get", {"countOutput": True, "filter": {"status": 0}}),
            call(svc, "host.get", {"countOutput": True, "filter": {"status": 1}}),
            call(svc, "problem.get", {"countOutput": True}))
        ha_states = {"0": "standby", "1": "stopped", "2": "unavailable", "3": "active"}
        px_states = {"0": "unknown", "1": "offline", "2": "online"}
        t = now()
        return finish(svc, {
            "version": ver,
            "ha_nodes": ha if isinstance(ha, dict) else [
                {"name": n["name"] or "default", "status": ha_states.get(n["status"], n["status"]),
                 "last_seen": age(t - int(n["lastaccess"])) + " ago"} for n in ha],
            "proxies": proxies if isinstance(proxies, dict) else [
                {"name": p["name"], "state": px_states.get(p.get("state", "0"), "unknown"),
                 "mode": "active" if p["operating_mode"] == "0" else "passive",
                 "last_seen": age(t - int(p["lastaccess"])) + " ago" if p["lastaccess"] != "0" else "never"}
                for p in proxies],
            "hosts_enabled": hosts_on, "hosts_disabled": hosts_off, "open_problems": probs})

