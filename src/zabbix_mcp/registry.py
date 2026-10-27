"""Method registry for the Zabbix 7.4 API.

Single source of truth for which API methods exist, whether each is read-only or
mutating, and which are blocked by default. Toolsets group API groups into the
domains selectable through ZABBIX_TOOLSETS.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase

# group -> methods (Zabbix 7.4 method reference)
API_GROUPS: dict[str, tuple[str, ...]] = {
    "action": ("create", "delete", "get", "update"),
    "alert": ("get",),
    "auditlog": ("get",),
    "authentication": ("get", "update"),
    "autoregistration": ("get", "update"),
    "configuration": ("export", "import", "importcompare"),
    "connector": ("create", "delete", "get", "update"),
    "correlation": ("create", "delete", "get", "update"),
    "dashboard": ("create", "delete", "get", "update"),
    "dhost": ("get",),
    "dservice": ("get",),
    "dcheck": ("get",),
    "drule": ("create", "delete", "get", "update"),
    "event": ("acknowledge", "get"),
    "graph": ("create", "delete", "get", "update"),
    "graphitem": ("get",),
    "graphprototype": ("create", "delete", "get", "update"),
    "hanode": ("get",),
    "history": ("clear", "get", "push"),
    "host": ("create", "delete", "get", "massadd", "massremove", "massupdate", "update"),
    "hostgroup": (
        "create", "delete", "get", "massadd", "massremove", "massupdate", "propagate", "update",
    ),
    "hostinterface": (
        "create", "delete", "get", "massadd", "massremove", "replacehostinterfaces", "update",
    ),
    "hostprototype": ("create", "delete", "get", "update"),
    "housekeeping": ("get", "update"),
    "httptest": ("create", "delete", "get", "update"),
    "httpstep": ("get",),
    "iconmap": ("create", "delete", "get", "update"),
    "image": ("create", "delete", "get", "update"),
    "item": ("create", "delete", "get", "update"),
    "itemprototype": ("create", "delete", "get", "update"),
    "discoveryrule": ("create", "delete", "get", "update"),
    "discoveryruleprototype": ("create", "delete", "get", "update"),
    "mfa": ("create", "delete", "get", "update"),
    "maintenance": ("create", "delete", "get", "update"),
    "map": ("create", "delete", "get", "update"),
    "mediatype": ("create", "delete", "get", "update"),
    "module": ("create", "delete", "get", "update"),
    "problem": ("get",),
    "proxy": ("create", "delete", "get", "update"),
    "proxygroup": ("create", "delete", "get", "update"),
    "regexp": ("create", "delete", "get", "update"),
    "report": ("create", "delete", "get", "update"),
    "role": ("create", "delete", "get", "update"),
    "sla": ("create", "delete", "get", "getsli", "update"),
    "script": (
        "create", "delete", "execute", "get", "getscriptsbyevents", "getscriptsbyhosts", "update",
    ),
    "service": ("create", "delete", "get", "update"),
    "settings": ("get", "update"),
    "task": ("create", "get"),
    "template": ("create", "delete", "get", "massadd", "massremove", "massupdate", "update"),
    "templatedashboard": ("create", "delete", "get", "update"),
    "templategroup": (
        "create", "delete", "get", "massadd", "massremove", "massupdate", "propagate", "update",
    ),
    "token": ("create", "delete", "generate", "get", "update"),
    "trend": ("get",),
    "trigger": ("create", "delete", "get", "update"),
    "triggerprototype": ("create", "delete", "get", "update"),
    "user": (
        "checkAuthentication", "create", "delete", "get", "login", "logout", "provision",
        "resettotp", "unblock", "update",
    ),
    "userdirectory": ("create", "delete", "get", "test", "update"),
    "usergroup": ("create", "delete", "get", "update"),
    "usermacro": (
        "create", "createglobal", "delete", "deleteglobal", "get", "update", "updateglobal",
    ),
    "valuemap": ("create", "delete", "get", "update"),
}

# Methods that never change state (everything else is treated as mutating).
_READ_SUFFIXES = ("get",)
_READ_EXTRA = {
    "apiinfo.version",
    "configuration.export",
    "configuration.importcompare",
    "sla.getsli",
    "script.getscriptsbyevents",
    "script.getscriptsbyhosts",
    "user.checkAuthentication",
    "userdirectory.test",
}

# Blocked unless explicitly allowed via ZABBIX_ALLOW_METHODS.
DEFAULT_BLOCKED_PATTERNS: tuple[str, ...] = (
    "user.*",
    "usergroup.*",
    "role.*",
    "token.*",
    "mfa.*",
    "userdirectory.*",
    "authentication.update",
    "settings.update",
    "housekeeping.update",
    "module.*",
    "configuration.import",
    "script.execute",
    "history.clear",
)

# Read-only methods that are safe even though they match a blocked pattern.
DEFAULT_BLOCK_EXEMPT: frozenset[str] = frozenset(
    {"user.get", "usergroup.get", "role.get", "token.get", "mfa.get", "userdirectory.get",
     "authentication.get", "settings.get", "housekeeping.get", "module.get"}
)

# Toolset domains -> API groups.
TOOLSETS: dict[str, tuple[str, ...]] = {
    "monitoring": (
        "problem", "event", "alert", "trigger", "history", "trend", "item", "graph",
        "graphitem", "hanode", "task", "auditlog",
    ),
    "hosts": (
        "host", "hostgroup", "hostinterface", "template", "templategroup", "proxy",
        "proxygroup", "maintenance",
    ),
    "config": (
        "itemprototype", "triggerprototype", "graphprototype", "hostprototype",
        "discoveryrule", "discoveryruleprototype", "drule", "dhost", "dservice", "dcheck",
        "httptest", "httpstep", "usermacro", "valuemap", "regexp", "correlation",
        "configuration",
    ),
    "visualization": ("dashboard", "templatedashboard", "map", "iconmap", "image", "report"),
    "services": ("service", "sla"),
    "alerting": ("action", "mediatype", "script", "connector"),
    "admin": (
        "user", "usergroup", "role", "token", "mfa", "userdirectory", "authentication",
        "autoregistration", "settings", "housekeeping", "module",
    ),
}

DEFAULT_TOOLSETS: tuple[str, ...] = (
    "monitoring", "hosts", "config", "visualization", "services", "alerting",
)


@dataclass(frozen=True)
class MethodInfo:
    name: str
    group: str
    action: str
    mutating: bool
    blocked_by_default: bool


def is_mutating(method: str) -> bool:
    if method in _READ_EXTRA:
        return False
    return method.rsplit(".", 1)[-1] not in _READ_SUFFIXES


def is_blocked_by_default(method: str) -> bool:
    if method in DEFAULT_BLOCK_EXEMPT:
        return False
    return any(fnmatchcase(method, pat) for pat in DEFAULT_BLOCKED_PATTERNS)


def all_methods() -> list[MethodInfo]:
    out: list[MethodInfo] = []
    for group, actions in API_GROUPS.items():
        for action in actions:
            name = f"{group}.{action}"
            out.append(MethodInfo(name, group, action, is_mutating(name), is_blocked_by_default(name)))
    return out


def get_method(name: str) -> MethodInfo | None:
    group, _, action = name.partition(".")
    if action in API_GROUPS.get(group, ()):
        return MethodInfo(name, group, action, is_mutating(name), is_blocked_by_default(name))
    return None


def toolset_for_group(group: str) -> str | None:
    for toolset, groups in TOOLSETS.items():
        if group in groups:
            return toolset
    return None
