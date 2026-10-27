"""Keep responses small: default `output` fields, default `limit`, size-capped results."""

from __future__ import annotations

import json
from typing import Any

# Only fields that exist on the object in 7.4. Callers can pass output="extend" for everything.
DEFAULT_OUTPUT: dict[str, list[str]] = {
    "host": ["hostid", "host", "name", "status", "maintenance_status", "description"],
    "hostgroup": ["groupid", "name"],
    "templategroup": ["groupid", "name"],
    "template": ["templateid", "host", "name"],
    "item": ["itemid", "hostid", "name", "key_", "type", "value_type", "units", "lastvalue",
             "lastclock", "state", "status", "delay"],
    "trigger": ["triggerid", "description", "expression", "priority", "status", "value",
                "lastchange", "state", "error"],
    "problem": ["eventid", "objectid", "name", "severity", "clock", "acknowledged", "suppressed",
                "opdata"],
    "event": ["eventid", "objectid", "name", "severity", "clock", "value", "acknowledged",
              "r_eventid"],
    "alert": ["alertid", "eventid", "actionid", "clock", "status", "subject", "error"],
    "dashboard": ["dashboardid", "name", "userid", "private"],
    "templatedashboard": ["dashboardid", "name", "templateid"],
    "maintenance": ["maintenanceid", "name", "maintenance_type", "active_since", "active_till"],
    "usermacro": ["hostmacroid", "hostid", "macro", "value", "type"],
    "user": ["userid", "username", "name", "surname", "roleid"],
    "usergroup": ["usrgrpid", "name", "gui_access", "users_status"],
    "role": ["roleid", "name", "type"],
    "service": ["serviceid", "name", "status", "algorithm"],
    "sla": ["slaid", "name", "period", "slo", "timezone", "status"],
    "map": ["sysmapid", "name", "width", "height"],
    "action": ["actionid", "name", "eventsource", "status"],
    "mediatype": ["mediatypeid", "name", "type", "status"],
    "proxy": ["proxyid", "name", "operating_mode"],
    "proxygroup": ["proxygroupid", "name"],
    "script": ["scriptid", "name", "type", "scope"],
    "valuemap": ["valuemapid", "name"],
    "httptest": ["httptestid", "hostid", "name", "delay", "status"],
    "drule": ["druleid", "name", "iprange", "status"],
    "discoveryrule": ["itemid", "hostid", "name", "key_", "delay", "status", "state"],
    "itemprototype": ["itemid", "hostid", "name", "key_", "type", "value_type", "status"],
    "triggerprototype": ["triggerid", "description", "expression", "priority", "status"],
    "graph": ["graphid", "name", "width", "height"],
    "graphprototype": ["graphid", "name", "width", "height"],
    "hostprototype": ["hostid", "host", "name", "status"],
    "image": ["imageid", "name", "imagetype"],
    "connector": ["connectorid", "name", "status"],
    "correlation": ["correlationid", "name", "status"],
    "regexp": ["regexpid", "name"],
    "iconmap": ["iconmapid", "name"],
    "report": ["reportid", "name", "status"],
}

# `.get` methods without a `limit` parameter (singletons) or where a limit makes no sense.
NO_LIMIT_GROUPS = {"settings", "housekeeping", "authentication", "autoregistration"}


def prepare_params(method: str, params: dict[str, Any] | None, default_limit: int) -> dict[str, Any]:
    """Return params with token-friendly defaults for `*.get`. Never mutates the input."""
    p = dict(params or {})
    group, _, action = method.partition(".")
    if action != "get" or group in NO_LIMIT_GROUPS:
        return p
    if p.get("countOutput"):
        return p
    if "output" not in p and group in DEFAULT_OUTPUT:
        p["output"] = DEFAULT_OUTPUT[group]
    if "limit" not in p:
        p["limit"] = default_limit
    return p


def shrink(result: Any, max_chars: int) -> tuple[Any, dict[str, Any] | None]:
    """Fit a result into max_chars. Lists are cut to whole items; long strings are clipped.
    Returns (value, truncation_info | None)."""
    if isinstance(result, list):
        out: list[Any] = []
        used = 2
        for item in result:
            n = len(json.dumps(item, separators=(",", ":"), default=str)) + 1
            if used + n > max_chars:
                hint = ("Result too large: narrow the filters, request fewer "
                        "fields via 'output', or use a smaller 'limit'.")
                if not out:  # even the first item exceeds the cap: clip it rather than ignore the cap
                    clipped = json.dumps(item, separators=(",", ":"), default=str)[:max_chars]
                    return [clipped], {"truncated": True, "returned": 1, "total": len(result), "hint": hint}
                return out, {"truncated": True, "returned": len(out), "total": len(result), "hint": hint}
            out.append(item)
            used += n
        return out, None
    if isinstance(result, str) and len(result) > max_chars:
        return result[:max_chars], {"truncated": True, "chars": len(result),
                                    "hint": "String truncated; request a narrower export."}
    if isinstance(result, dict):
        s = json.dumps(result, separators=(",", ":"), default=str)
        if len(s) > max_chars:
            return s[:max_chars], {"truncated": True, "chars": len(s),
                                   "hint": "Object truncated; request fewer fields."}
    return result, None


def dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), default=str, ensure_ascii=False)
