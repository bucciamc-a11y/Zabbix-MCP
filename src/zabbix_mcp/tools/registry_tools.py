"""Tiers 2 and 3: domain tools covering every Zabbix 7.4 API method, plus search/describe/raw."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .. import guard
from ..errors import BlockedError
from ..registry import API_GROUPS, TOOLSETS, all_methods, get_method, toolset_for_group
from ..service import ZabbixService
from .common import READ, WRITE, finish, safe

DOCS = "https://www.zabbix.com/documentation/7.4/en/manual/api/reference/{group}/{action}"
Params = dict[str, Any] | list[Any] | None

GET_HELP = ("Common get params: output (field list or 'extend'), filter {field:[values]} (exact), "
            "search {field:'text'} (substring; use searchWildcardsEnabled for *), searchByAny, "
            "select<Related> (e.g. selectHostGroups, selectTags), <objects>ids filters, sortfield, "
            "sortorder, limit, countOutput. Defaults here: a small 'output' and limit 50.")
ACTION_HELP = {
    "create": "params: object (or array of objects) with the required properties. Returns new ids.",
    "update": "params: object (or array) with the object id plus only the properties to change.",
    "delete": "params: array of ids, e.g. [\"10084\"] (some groups take objects; see docs).",
}


def _domain_doc(ts: str) -> str:
    lines = []
    for g in TOOLSETS[ts]:
        lines.append(f"{g}: {', '.join(API_GROUPS[g])}")
    return "; ".join(lines)


def register(mcp: FastMCP, svc: ZabbixService, enabled_toolsets: list[str]) -> None:
    @mcp.tool(annotations=READ)
    @safe
    async def zabbix_search_methods(
        query: Annotated[str, Field(description="Words to look for, e.g. 'maintenance' or 'host create'")],
        limit: Annotated[int, Field(ge=1, le=60)] = 20,
    ):
        """Find Zabbix 7.4 API methods by name. Shows which tool runs each and if it is allowed."""
        terms = query.lower().replace(".", " ").split()
        s = svc.settings
        rows = []
        for m in all_methods():
            if all(t in m.name.lower() for t in terms):
                d = guard.evaluate(s, m.name)
                ts = toolset_for_group(m.group)
                rows.append({"method": m.name, "write": m.mutating, "tool": f"zabbix_{ts}",
                             "allowed": d.allowed, **({} if d.allowed else {"why": d.reason[:80]})})
        return finish(svc, {"count": len(rows), "methods": rows[:limit]})

    @mcp.tool(annotations=READ)
    @safe
    async def zabbix_describe_method(
        method: Annotated[str, Field(description="e.g. 'host.create'")],
    ):
        """Docs link, read/write class, permission status and usage tips for one API method."""
        info = get_method(method)
        if info is None:
            raise BlockedError(f"Unknown method '{method}'. Use zabbix_search_methods.")
        d = guard.evaluate(svc.settings, method)
        ts = toolset_for_group(info.group)
        out: dict[str, Any] = {
            "method": method, "write": info.mutating, "tool": f"zabbix_{ts}", "allowed": d.allowed,
            "requires_confirmation": d.needs_confirm, "docs": DOCS.format(group=info.group, action=info.action)}
        if not d.allowed:
            out["why_not"] = d.reason
        out["usage"] = GET_HELP if info.action == "get" else ACTION_HELP.get(
            info.action, "See the docs link for this method's parameters.")
        if info.mutating:
            out["note"] = "Write: the first call returns a preview and confirm_token; repeat with the token."
        return out

    @mcp.tool(annotations=WRITE)
    @safe
    async def zabbix_raw_api(
        method: Annotated[str, Field(description="Any Zabbix 7.4 method, e.g. 'item.get'")],
        params: Annotated[Params, Field(description="JSON-RPC params (object, or array for delete methods)")] = None,
        confirm_token: Annotated[str | None, Field(description="Token from the preview call (writes)")] = None,
    ):
        """Escape hatch: call any 7.4 API method. Same safety rules (read-only, blocklist, confirmation)."""
        return await svc.execute(method, params, confirm_token=confirm_token)

    for ts in enabled_toolsets:
        _add_domain_tool(mcp, svc, ts)


def _add_domain_tool(mcp: FastMCP, svc: ZabbixService, ts: str) -> None:
    groups = set(TOOLSETS[ts])

    @safe
    async def domain_tool(
        method: Annotated[str, Field(description="Method name, e.g. 'host.get'")],
        params: Annotated[Params, Field(description="JSON-RPC params (object, or array of ids for deletes)")] = None,
        confirm_token: Annotated[str | None, Field(description="Token from the preview call (writes)")] = None,
    ):
        group = method.split(".", 1)[0]
        if group not in groups:
            home = toolset_for_group(group)
            hint = f" Use zabbix_{home}." if home else " Use zabbix_search_methods."
            raise BlockedError(f"'{method}' does not belong to zabbix_{ts}.{hint}")
        return await svc.execute(method, params, confirm_token=confirm_token)

    desc = (f"Zabbix {ts} API. Methods: {_domain_doc(ts)}. Reads return compact defaults; "
            "writes are two-step (preview, then repeat with confirm_token). "
            "Use zabbix_describe_method for docs and parameters.")
    mcp.add_tool(domain_tool, name=f"zabbix_{ts}", description=desc, annotations=WRITE)
