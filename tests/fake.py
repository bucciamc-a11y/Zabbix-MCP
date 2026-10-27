"""In-memory fake Zabbix JSON-RPC endpoint for tool tests."""

import json
from collections.abc import Callable
from typing import Any

import httpx

from tests.conftest import API


class FakeZabbix:
    def __init__(self, router):
        self.handlers: dict[str, Callable[[dict], Any] | Any] = {}
        self.calls: list[tuple[str, Any]] = []
        self.route = router.post(API).mock(side_effect=self._handle)

    def on(self, method: str, result: Any):
        self.handlers[method] = result
        return self

    def _handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        m, p = body["method"], body["params"]
        self.calls.append((m, p))
        h = self.handlers.get(m)
        if h is None:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": {
                "code": -32601, "message": "Method not found.", "data": f"no fake for {m}"}})
        res = h(p) if callable(h) else h
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": res})

    def params(self, method: str, index: int = -1) -> dict:
        return [p for m, p in self.calls if m == method][index]

    def count(self, method: str) -> int:
        return sum(1 for m, _ in self.calls if m == method)
