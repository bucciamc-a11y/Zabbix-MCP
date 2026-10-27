"""Shared helpers for tools: error wrapping, formatting, name->id resolution."""

from __future__ import annotations

import asyncio
import functools
import logging
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

from ..errors import ZabbixAPIError, ZabbixMCPError
from ..service import ZabbixService
from ..trim import dumps, shrink

log = logging.getLogger(__name__)

SEVERITIES = ["not classified", "information", "warning", "average", "high", "disaster"]
SEVERITY_INDEX = {n: i for i, n in enumerate(SEVERITIES)}

READ = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True,
                       openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False,
                        openWorldHint=False)


def safe(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[str]]:
    """Turn results into compact JSON text and failures into MCP tool errors (isError=true)
    carrying a safe, actionable message. Unexpected exceptions never leak internals."""

    @functools.wraps(fn)
    async def wrapper(*args, **kwargs) -> str:
        try:
            return dumps(await fn(*args, **kwargs))
        except ZabbixMCPError as e:
            raise ToolError(dumps(e.to_dict())) from None
        except Exception:
            log.exception("unexpected error in tool %s", fn.__name__)
            raise ToolError(dumps({"error": "internal_error",
                                   "message": "Unexpected server error; see server logs."})) from None

    return wrapper


def finish(svc: ZabbixService, obj: Any) -> Any:
    """Apply the response size cap to a composed result."""
    value, info = shrink(obj, svc.settings.max_response_chars)
    return {"result": value, **info} if info else value


def sev_name(n: Any) -> str:
    try:
        return SEVERITIES[int(n)]
    except (ValueError, IndexError):
        return str(n)


def age(seconds: float) -> str:
    s = max(int(seconds), 0)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m = s // 60
    if d:
        return f"{d}d{h}h"
    if h:
        return f"{h}h{m}m"
    return f"{m}m" if m else f"{s}s"


def iso(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(int(ts), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError, OSError):
        return str(ts)


def now() -> int:
    return int(time.time())


async def call(svc: ZabbixService, method: str, params: dict | list | None = None) -> Any:
    """Internal read/write through the guard without default trimming (callers set their own)."""
    return await svc.execute(method, params, trim=False)


async def resolve_ids(svc: ZabbixService, kind: str, names: list[str] | str | None,
                      *, limit: int = 100) -> list[str]:
    """Resolve host or host-group names (wildcards '*' allowed) to ids. [] means none matched."""
    if not names:
        return []
    names = [names] if isinstance(names, str) else names
    if kind == "host":
        rows = await call(svc, "host.get", {
            "output": ["hostid"], "search": {"host": names, "name": names}, "searchByAny": True,
            "searchWildcardsEnabled": True, "limit": limit})
        return [r["hostid"] for r in rows]
    if kind == "group":
        rows = await call(svc, "hostgroup.get", {
            "output": ["groupid"], "search": {"name": names}, "searchByAny": True,
            "searchWildcardsEnabled": True, "limit": limit})
        return [r["groupid"] for r in rows]
    raise ValueError(kind)


async def call_with_fallback(svc: ZabbixService, method: str, params: dict, fallback: dict) -> Any:
    """Retry once with simpler params if Zabbix rejects an optional field (-32602)."""
    try:
        return await call(svc, method, params)
    except ZabbixAPIError as e:
        if e.code != -32602:
            raise
        log.warning("%s rejected params, retrying with fallback: %s", method, e.data)
        return await call(svc, method, fallback)


async def gather_safe(*aws: Awaitable[Any]) -> list[Any]:
    """Run concurrently; failed parts become {'error': msg} so partial results survive."""
    res = await asyncio.gather(*aws, return_exceptions=True)
    out = []
    for r in res:
        if isinstance(r, ZabbixMCPError):
            out.append({"error": r.message})
        elif isinstance(r, BaseException):
            raise r
        else:
            out.append(r)
    return out


def bucketize(points: list[tuple[int, float]], n: int) -> list[dict[str, Any]]:
    """Downsample (clock, value) points into <= n time buckets with min/avg/max."""
    if not points:
        return []
    points = sorted(points)
    t0, t1 = points[0][0], points[-1][0]
    if len(points) <= n:
        return [{"t": iso(t), "v": v} for t, v in points]
    if t1 == t0:
        vals = [v for _, v in points]
        return [{"t": iso(t0), "min": min(vals), "avg": sum(vals) / len(vals), "max": max(vals)}]
    width = (t1 - t0) / n
    buckets: list[list[float]] = [[] for _ in range(n)]
    for t, v in points:
        buckets[min(int((t - t0) / width), n - 1)].append(v)
    out = []
    for i, b in enumerate(buckets):
        if b:
            out.append({"t": iso(t0 + i * width), "min": round(min(b), 4),
                        "avg": round(sum(b) / len(b), 4), "max": round(max(b), 4)})
    return out
