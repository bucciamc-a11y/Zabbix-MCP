"""stderr-only logging with secret masking, plus a JSON audit logger.

stdout is reserved for the MCP stdio protocol; nothing here ever writes to it."""

from __future__ import annotations

import json
import logging
import re
import sys
import time
from typing import Any

_REDACT_KEYS = re.compile(r"(token|password|passwd|secret|auth|apikey|api_key|sessionid)", re.IGNORECASE)
_BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")
_ZMCP = re.compile(r"zmcp_[A-Za-z0-9_-]+")
MASK = "***"


def mask_text(text: str) -> str:
    return _ZMCP.sub(MASK, _BEARER.sub(r"\1" + MASK, text))


def mask_obj(obj: Any, _depth: int = 0) -> Any:
    """Recursively mask values under secret-looking keys."""
    if _depth > 8:
        return obj
    if isinstance(obj, dict):
        return {k: (MASK if _REDACT_KEYS.search(str(k)) and v not in (None, "", False)
                    else mask_obj(v, _depth + 1)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_obj(v, _depth + 1) for v in obj]
    if isinstance(obj, str):
        return mask_text(obj)
    return obj


class _MaskFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = mask_text(str(record.getMessage()))
        record.args = ()
        return True


def setup_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.handlers.clear()
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    h.addFilter(_MaskFilter())
    root.addHandler(h)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    logging.getLogger("httpx").setLevel(logging.WARNING)  # URLs only, but keep quiet


class Audit:
    """One JSON line per Zabbix call. Params are masked and size-capped."""

    def __init__(self, path: str = ""):
        self._log = logging.getLogger("zabbix_mcp.audit")
        self._log.propagate = not path
        if path:
            self._log.handlers.clear()
            fh = logging.FileHandler(path)
            fh.setFormatter(logging.Formatter("%(message)s"))
            self._log.addHandler(fh)
            self._log.setLevel(logging.INFO)

    def record(self, *, method: str, params: Any, outcome: str, ms: float,
               mutating: bool, detail: str = "") -> None:
        p = json.dumps(mask_obj(params), default=str, separators=(",", ":"))
        entry = {"ts": round(time.time(), 3), "method": method, "mutating": mutating,
                 "outcome": outcome, "ms": round(ms, 1), "params": p[:500]}
        if detail:
            entry["detail"] = mask_text(detail)[:300]
        self._log.info(json.dumps(entry, separators=(",", ":")))
