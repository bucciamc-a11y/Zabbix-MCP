"""Dashboard management (Zabbix 7.4): widget catalog, validation, shorthand field expansion,
safe read-modify-write updates (dashboard.update replaces pages/widgets, so we always send the
full set) and automatic placement on the 72x64 grid."""

from __future__ import annotations

import hashlib
import json
import string
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..errors import BlockedError
from ..service import ZabbixService
from .common import READ, WRITE, call, finish, safe

GRID_W, GRID_H = 72, 64

# type -> (description, key shorthand fields). Field names per the Zabbix 7.4 widget_fields docs.
WIDGET_TYPES: dict[str, tuple[str, str]] = {
    "problems": ("Problems list", "show(1 recent,2 history,3 problems) groupids hostids severities "
                 "tags show_tags show_opdata acknowledgement_status sort_triggers show_lines"),
    "problemsbysv": ("Problems by severity", "groupids hostids severities show_type(0 groups,1 totals) "
                     "layout ext_ack hide_empty_groups"),
    "problemhosts": ("Problem hosts", "groupids hostids severities hide_empty_groups"),
    "item": ("Item value", "itemid show[1 desc,2 value,3 time,4 change,5 sparkline] units "
             "decimal_places bg_color thresholds aggregate_function time_period"),
    "gauge": ("Gauge", "itemid min max show angle(180|270) value_arc_color thresholds"),
    "svggraph": ("Graph (current)", "ds[{hosts,items,color,type}] time_period lefty righty legend "
                 "show_problems"),
    "piechart": ("Pie / doughnut chart", "ds[{hosts,items,color}] draw_type time_period legend"),
    "tophosts": ("Top hosts", "groupids hostids columns[{name,data,item,display}] column order "
                 "show_lines"),
    "topitems": ("Top items", "groupids hostids items order show_lines"),
    "toptriggers": ("Top triggers", "groupids hostids severities show_lines"),
    "hostavail": ("Host availability", "groupids interface_type layout only_totals maintenance"),
    "systeminfo": ("System information", "info_type(0 stats,1 HA nodes)"),
    "clock": ("Clock", "time_type(0 local,1 server,2 host) clock_type(0 analog,1 digital) show"),
    "map": ("Map", "sysmapid"),
    "navtree": ("Map navigation tree", "navtree.N.name navtree.N.sysmapid"),
    "geomap": ("Geomap", "groupids hostids severities"),
    "graph": ("Graph classic", "source_type(0 graph,1 item) graphid itemid show_legend"),
    "graphprototype": ("Graph prototype", "graphid columns rows"),
    "hostnavigator": ("Host navigator", "groupids host_tags status group_by[{attribute}]"),
    "itemnavigator": ("Item navigator", "groupids hostids group_by"),
    "hostcard": ("Host card", "hostid sections"),
    "itemcard": ("Item card", "itemid sections"),
    "itemhistory": ("Item history", "columns[{itemid,name}] show_lines"),
    "honeycomb": ("Honeycomb", "groupids hostids items"),
    "slareport": ("SLA report", "slaid serviceid show_periods"),
    "actionlog": ("Action log", "show_lines sort_triggers"),
    "discovery": ("Discovery status", ""),
    "favgraphs": ("Favorite graphs", ""),
    "favmaps": ("Favorite maps", ""),
    "trigover": ("Trigger overview", "groupids hostids show"),
    "url": ("URL / iframe", "url"),
    "web": ("Web monitoring", "groupids hostids"),
}
NEEDS_REFERENCE = {"problems", "problemsbysv", "svggraph", "piechart", "tophosts", "topitems",
                   "toptriggers", "hostnavigator", "itemnavigator", "hostavail", "honeycomb"}

# Field-name (last non-index segment) -> Zabbix widget field type code.
FIELD_TYPES: dict[str, int] = {
    "groupids": 2, "exclude_groupids": 2, "hostids": 3, "exclude_hostids": 3, "hostid": 3,
    "override_hostid": 3, "itemid": 4, "itemids": 4, "itemprototypeid": 5, "graphid": 6,
    "graphprototypeid": 7, "sysmapid": 8, "serviceid": 9, "serviceids": 9, "slaid": 10,
    "userid": 11, "actionid": 12, "mediatypeid": 13,
}


def expand_fields(fields: Any) -> list[dict[str, Any]]:
    """Accept either Zabbix's native [{type,name,value}] list or a friendly nested dict and return
    the native list. Lists become name.0, name.1 ...; nested dicts/lists become dotted paths."""
    if isinstance(fields, list) and all(isinstance(f, dict) and {"type", "name", "value"} <= f.keys()
                                        for f in fields):
        return fields
    if not isinstance(fields, dict):
        raise BlockedError("'fields' must be an object like {\"groupids\":[4],\"severities\":[4,5]} "
                           "or a native list of {type,name,value}.")
    out: list[dict[str, Any]] = []

    def walk(path: str, val: Any) -> None:
        if isinstance(val, dict):
            for k, v in val.items():
                walk(f"{path}.{k}" if path else k, v)
        elif isinstance(val, list):
            for i, v in enumerate(val):
                walk(f"{path}.{i}", v)
        else:
            out.append({"type": _ftype(path, val), "name": path, "value": val})

    walk("", fields)
    return out


def _ftype(path: str, val: Any) -> int:
    segs = [s for s in path.split(".") if not s.isdigit()]
    last = segs[-1] if segs else ""
    if last.startswith("_") or "_reference" in path:
        return 1
    if last in FIELD_TYPES:
        return FIELD_TYPES[last]
    if isinstance(val, bool) or isinstance(val, int):
        return 0
    return 1


def validate_widget(w: dict[str, Any]) -> list[str]:
    issues = []
    t = w.get("type")
    if t not in WIDGET_TYPES:
        issues.append(f"unknown widget type {t!r}; use dashboard_widget_catalog")
    for k, lo, hi in (("x", 0, GRID_W - 1), ("y", 0, GRID_H - 1), ("width", 1, GRID_W),
                      ("height", 1, GRID_H)):
        v = w.get(k)
        if not isinstance(v, int) or not lo <= v <= hi:
            issues.append(f"{k} must be an integer {lo}-{hi}, got {v!r}")
    if not issues and (w["x"] + w["width"] > GRID_W or w["y"] + w["height"] > GRID_H):
        issues.append(f"widget exceeds the {GRID_W}x{GRID_H} grid")
    for f in w.get("fields", []):
        if not isinstance(f, dict) or {"type", "name", "value"} - f.keys():
            issues.append(f"malformed field {f!r}")
            break
    return issues


def _overlap(a: dict, b: dict) -> bool:
    return not (a["x"] + a["width"] <= b["x"] or b["x"] + b["width"] <= a["x"]
                or a["y"] + a["height"] <= b["y"] or b["y"] + b["height"] <= a["y"])


def find_free_slot(widgets: list[dict], width: int, height: int) -> tuple[int, int] | None:
    """First (x, y) scanning rows top-to-bottom where the box fits without overlap."""
    for y in range(0, GRID_H - height + 1):
        for x in range(0, GRID_W - width + 1):
            cand = {"x": x, "y": y, "width": width, "height": height}
            if not any(_overlap(cand, w) for w in widgets):
                return x, y
    return None


def check_layout(widgets: list[dict]) -> list[str]:
    issues = []
    for i, w in enumerate(widgets):
        issues += [f"widget {i} ({w.get('name') or w.get('type')}): {m}" for m in validate_widget(w)]
    if not issues:
        for i in range(len(widgets)):
            for j in range(i + 1, len(widgets)):
                if _overlap(widgets[i], widgets[j]):
                    issues.append(f"widgets {i} and {j} overlap")
    return issues


def build_widget(spec: dict[str, Any], existing: list[dict]) -> dict[str, Any]:
    """Normalize a user widget spec: expand fields, add reference, place if x/y missing."""
    w = {k: v for k, v in spec.items() if k != "fields"}
    w.setdefault("width", 18)
    w.setdefault("height", 5)
    w.setdefault("view_mode", 0)
    fields = expand_fields(spec.get("fields", {}))
    if w.get("type") in NEEDS_REFERENCE and not any(f["name"] == "reference" for f in fields):
        digest = hashlib.sha1(json.dumps(spec, sort_keys=True, default=str).encode()).digest()
        ref = "".join(string.ascii_uppercase[b % 26] for b in digest[:5])
        fields.append({"type": 1, "name": "reference", "value": ref})
    w["fields"] = fields
    if "x" not in w or "y" not in w:
        if isinstance(w.get("width"), int) and isinstance(w.get("height"), int):
            slot = find_free_slot(existing, w["width"], w["height"])
            if slot is None:
                raise BlockedError("No free space on this dashboard page; use another page or resize.")
            w["x"], w["y"] = slot
    return w



def register(mcp: FastMCP, svc: ZabbixService) -> None:
    @mcp.tool(annotations=READ)
    @safe
    async def dashboard_widget_catalog():
        """Supported dashboard widget types with their key field names, plus layout rules."""
        return {
            "grid": f"{GRID_W} columns x {GRID_H} rows; x 0-71, y 0-63, width 1-72, height 1-64; no overlap. "
                    "Four across = width 18, two across = width 36.",
            "fields": "Pass 'fields' as a friendly object, e.g. {\"groupids\":[4],\"severities\":[4,5],"
                      "\"show_tags\":1}; lists expand to name.0,name.1; nested objects to dotted paths "
                      "(ds:[{hosts:[\"web*\"],items:[\"cpu*\"],color:\"FF0000\"}]). Types are inferred "
                      "(groupids->host group, hostids->host, itemid->item; colors are hex without #). "
                      "Zabbix does NOT validate field names, so copy names from this catalog or from "
                      "manage_dashboard(get) on a UI-built dashboard.",
            "widgets": {k: {"title": v[0], "key_fields": v[1]} for k, v in WIDGET_TYPES.items()}}

    @mcp.tool(annotations=WRITE)
    @safe
    async def manage_dashboard(
        operation: Literal["list", "get", "create", "add_widget", "remove_widget", "rename",
                           "set_sharing", "replace_pages", "delete"],
        dashboard: Annotated[str | None, Field(description="Dashboard name or id (get/modify operations)")] = None,
        name: Annotated[str | None, Field(description="create/rename: dashboard name")] = None,
        widgets: Annotated[list[dict[str, Any]] | None, Field(
            description="create: widgets for the first page; add_widget: widget(s) to add. Each: "
                        "{type, name, x?, y?, width?, height?, fields?}. x/y are auto-placed when omitted.")] = None,
        page: Annotated[int, Field(ge=0, description="Page index for add/remove_widget")] = 0,
        widget_name: Annotated[str | None, Field(description="remove_widget: widget name")] = None,
        pages: Annotated[list[dict[str, Any]] | None, Field(description="replace_pages: full page list")] = None,
        private: Annotated[bool | None, Field(description="create/set_sharing: private (true) or public")] = None,
        user_groups: Annotated[list[dict[str, Any]] | None, Field(
            description="set_sharing: [{usrgrpid, permission(2 read,3 write)}] (replaces list)")] = None,
        confirm_token: Annotated[str | None, Field(description="Token from the preview call")] = None,
    ):
        """Create and edit Zabbix dashboards. Changes are validated, then two-step confirmed."""
        if operation == "list":
            rows = await call(svc, "dashboard.get", {
                "output": ["dashboardid", "name", "private"], "sortfield": "dashboardid", "limit": 200})
            return finish(svc, [{"dashboardid": r["dashboardid"], "name": r["name"],
                                 "private": r["private"] == "1"} for r in rows])

        if operation == "create":
            if not name:
                raise BlockedError("create needs 'name'.")
            placed: list[dict] = []
            for spec in widgets or []:
                placed.append(build_widget(spec, placed))
            if issues := check_layout(placed):
                raise BlockedError("Invalid widgets: " + "; ".join(issues))
            params: dict[str, Any] = {"name": name, "pages": [{"widgets": placed}]}
            if private is not None:
                params["private"] = 1 if private else 0
            return await svc.execute("dashboard.create", params, confirm_token=confirm_token, trim=False)

        if not dashboard:
            raise BlockedError("This operation needs 'dashboard' (name or id).")
        dash = await _load(svc, dashboard)

        if operation == "get":
            return finish(svc, _compact(dash))
        did = dash["dashboardid"]

        if operation == "delete":
            return await svc.execute("dashboard.delete", [did], confirm_token=confirm_token, trim=False)
        if operation == "rename":
            if not name:
                raise BlockedError("rename needs 'name'.")
            return await svc.execute("dashboard.update", {"dashboardid": did, "name": name},
                                     confirm_token=confirm_token, trim=False)
        if operation == "set_sharing":
            p2: dict[str, Any] = {"dashboardid": did}
            if private is not None:
                p2["private"] = 1 if private else 0
            if user_groups is not None:
                p2["userGroups"] = user_groups
            if len(p2) == 1:
                raise BlockedError("set_sharing needs 'private' and/or 'user_groups'.")
            return await svc.execute("dashboard.update", p2, confirm_token=confirm_token, trim=False)
        if operation == "replace_pages":
            if not pages:
                raise BlockedError("replace_pages needs 'pages'.")
            norm = []
            for pg in pages:
                placed = []
                for spec in pg.get("widgets", []):
                    placed.append(build_widget(spec, placed))
                if issues := check_layout(placed):
                    raise BlockedError("Invalid widgets: " + "; ".join(issues))
                norm.append({**{k: v for k, v in pg.items() if k != "widgets"}, "widgets": placed})
            return await svc.execute("dashboard.update", {"dashboardid": did, "pages": norm},
                                     confirm_token=confirm_token, trim=False)

        # add_widget / remove_widget: read-modify-write on the page list
        cur_pages = dash.get("pages", [])
        if page >= len(cur_pages):
            raise BlockedError(f"Dashboard has {len(cur_pages)} page(s); page {page} does not exist.")
        pg = cur_pages[page]
        pg_widgets = [_clean_widget(w) for w in pg.get("widgets", [])]
        if operation == "add_widget":
            if not widgets:
                raise BlockedError("add_widget needs 'widgets'.")
            for spec in widgets:
                pg_widgets.append(build_widget(spec, pg_widgets))
        else:
            if not widget_name:
                raise BlockedError("remove_widget needs 'widget_name'.")
            kept = [w for w in pg_widgets if w.get("name") != widget_name]
            if len(kept) == len(pg_widgets):
                raise BlockedError(f"No widget named '{widget_name}' on page {page}.")
            pg_widgets = kept
        if issues := check_layout(pg_widgets):
            raise BlockedError("Invalid layout: " + "; ".join(issues))
        new_pages = [{"dashboard_pageid": p["dashboard_pageid"],
                      "widgets": pg_widgets if i == page else [_clean_widget(w) for w in p.get("widgets", [])]}
                     for i, p in enumerate(cur_pages)]
        return await svc.execute("dashboard.update", {"dashboardid": did, "pages": new_pages},
                                 confirm_token=confirm_token, trim=False)


async def _load(svc: ZabbixService, ref: str) -> dict[str, Any]:
    p: dict[str, Any] = {"output": ["dashboardid", "name", "private"], "selectPages": "extend",
                         "limit": 5}
    if ref.isdigit():
        p["dashboardids"] = [ref]
    else:
        p["filter"] = {"name": [ref]}
    rows = await call(svc, "dashboard.get", p)
    if not rows:
        raise BlockedError(f"No dashboard matches '{ref}'. Use manage_dashboard(list).")
    if len(rows) > 1:
        raise BlockedError(f"Several dashboards match '{ref}'; use the numeric id.")
    return rows[0]


def _clean_widget(w: dict[str, Any]) -> dict[str, Any]:
    """Keep widgetid so Zabbix updates the widget in place instead of recreating it."""
    keep = ("widgetid", "type", "name", "x", "y", "width", "height", "view_mode", "fields")
    out = {k: w[k] for k in keep if k in w}
    for k in ("x", "y", "width", "height", "view_mode"):
        if k in out:
            out[k] = int(out[k])
    return out


def _compact(dash: dict[str, Any]) -> dict[str, Any]:
    return {"dashboardid": dash["dashboardid"], "name": dash["name"], "private": dash["private"] == "1",
            "pages": [{"page": i, "name": p.get("name", ""), "widgets": [
                {"name": w.get("name", ""), "type": w["type"],
                 "pos": f"{w['x']},{w['y']} {w['width']}x{w['height']}",
                 "fields": {f["name"]: f["value"] for f in w.get("fields", [])}}
                for w in p.get("widgets", [])]} for i, p in enumerate(dash.get("pages", []))]}
