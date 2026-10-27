import json

import httpx
import pytest
import respx
from starlette.testclient import TestClient

from tests.conftest import API, ok
from zabbix_mcp.admin.auth import (
    LoginLimiter,
    Sessions,
    check_password_strength,
    hash_password,
    verify_password,
)
from zabbix_mcp.server import build_http_app, build_server

PW = "correct horse battery staple"
TOKEN = "zmcp_boot_token"


def test_password_hashing():
    h = hash_password(PW, iterations=1000)
    assert verify_password(PW, h) and not verify_password("nope", h) and not verify_password(PW, "garbage")
    assert check_password_strength("short") and check_password_strength(PW) is None


def test_sessions_sign_expire_tamper(tmp_path):
    s = Sessions(tmp_path)
    cookie, csrf = s.issue(ttl=10, now=1000)
    assert s.verify(cookie, now=1005)["csrf"] == csrf
    assert s.verify(cookie, now=1011) is None
    assert s.verify(cookie[:-2] + "xx", now=1005) is None
    assert s.verify(None) is None and s.verify("a.b") is None
    assert Sessions(tmp_path).verify(cookie, now=1005)  # key persisted


def test_login_limiter():
    now = [0.0]
    lim = LoginLimiter(max_fails=3, window=60, lockout=100, clock=lambda: now[0])
    for _ in range(3):
        lim.fail("ip")
    assert lim.blocked("ip") == 100
    now[0] = 101
    assert lim.blocked("ip") == 0
    lim.fail("x")
    lim.success("x")
    assert lim.blocked("x") == 0


@pytest.fixture
def admin(make_store):
    store = make_store(MCP_TRANSPORT="http", MCP_AUTH_TOKEN=TOKEN, ADMIN_ENABLED="true")
    store.update({"admin_password_hash": hash_password(PW, iterations=1000)})
    mcp, svc = build_server(store)
    app = build_http_app(store, mcp, svc)
    with TestClient(app, base_url="https://testserver") as c:
        yield c, store


def login(c, pw=PW):
    r = c.post("/admin/api/login", json={"password": pw})
    return r, (r.json().get("csrf") if r.status_code == 200 else None)


def H(csrf):
    return {"X-CSRF-Token": csrf, "Content-Type": "application/json"}


def test_pages_and_security_headers(admin):
    c, _ = admin
    for path in ("/admin", "/admin/"):
        r = c.get(path)  # no redirect, no bearer token needed for the UI shell
        assert r.status_code == 200 and "Zabbix MCP" in r.text
        assert "default-src 'none'" in r.headers["content-security-policy"]
        assert r.headers["x-frame-options"] == "DENY"
    assert c.get("/admin/static/app.js").status_code == 200
    assert c.get("/admin/static/evil.js").status_code == 404
    assert c.post("/mcp", json={}).status_code == 401  # MCP still protected


def test_api_requires_login(admin):
    c, _ = admin
    assert c.get("/admin/api/state").status_code == 401
    assert c.post("/admin/api/settings", json={"changes": {}}).status_code == 401


def test_login_failures_lock_out(admin):
    c, _ = admin
    for _ in range(5):
        assert login(c, "wrong")[0].status_code == 401
    r, _ = login(c, PW)
    assert r.status_code == 429


def test_login_cookie_flags_and_prefix(admin):
    c, _ = admin
    r = c.post("/admin/api/login", json={"password": PW}, headers={"X-Forwarded-Prefix": "/zabbix-mcp"})
    sc = r.headers["set-cookie"]
    assert "HttpOnly" in sc and "SameSite=strict" in sc and "Secure" in sc and "Path=/zabbix-mcp/admin" in sc


def test_csrf_required_for_changes(admin):
    c, _ = admin
    _, csrf = login(c)
    assert c.post("/admin/api/settings", json={"changes": {"read_only": False}}).status_code == 403
    assert c.post("/admin/api/settings", json={"changes": {"read_only": False}},
                  headers={"X-CSRF-Token": "bad"}).status_code == 403
    r = c.post("/admin/api/settings", json={"changes": {"read_only": False}}, headers=H(csrf))
    assert r.status_code == 200


def test_settings_roundtrip_and_validation(admin):
    c, store = admin
    _, csrf = login(c)
    st = c.get("/admin/api/state").json()
    assert st["settings"]["zabbix_api_token"] is True and "tok-secret-123" not in json.dumps(st)
    r = c.post("/admin/api/settings", headers=H(csrf), json={"changes": {
        "toolsets": ["monitoring"], "read_only": False, "deny_methods": ["host.delete"]}})
    d = r.json()
    assert d["ok"] and d["restart_required"] is True
    assert store.settings.read_only is False and store.settings.deny_methods == ["host.delete"]
    r = c.post("/admin/api/settings", headers=H(csrf), json={"changes": {"toolsets": ["bogus"]}})
    assert r.status_code == 400
    r = c.post("/admin/api/settings", headers=H(csrf), json={"changes": {"admin_password_hash": "x"}})
    assert r.status_code == 400 and store.settings.admin_password_hash != "x"
    r = c.post("/admin/api/settings", headers=H(csrf), json={"changes": {"mcp_token_hashes": []}})
    assert r.status_code == 400


def test_token_lifecycle(admin):
    c, store = admin
    _, csrf = login(c)
    t = c.post("/admin/api/tokens", headers=H(csrf), json={"action": "create"}).json()
    assert t["token"].startswith("zmcp_")
    assert c.post("/mcp", headers={"Authorization": f"Bearer {t['token']}", "Accept": "application/json, text/event-stream",
                                   "Content-Type": "application/json"},
                  json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).status_code == 200
    assert len(c.get("/admin/api/state").json()["tokens"]) == 2
    assert c.post("/admin/api/tokens", headers=H(csrf),
                  json={"action": "revoke", "fingerprint": t["fingerprint"]}).json()["ok"]
    assert c.post("/mcp", headers={"Authorization": f"Bearer {t['token']}"}, json={}).status_code == 401
    assert c.post("/admin/api/tokens", headers=H(csrf),
                  json={"action": "revoke", "fingerprint": "zzzz"}).status_code == 404


def test_password_change(admin):
    c, _ = admin
    _, csrf = login(c)
    assert c.post("/admin/api/password", headers=H(csrf), json={"current": "x", "new": PW + "!"}).status_code == 401
    assert c.post("/admin/api/password", headers=H(csrf), json={"current": PW, "new": "short"}).status_code == 400
    assert c.post("/admin/api/password", headers=H(csrf), json={"current": PW, "new": PW + "!"}).status_code == 200
    c.cookies.clear()
    assert login(c, PW)[0].status_code == 401
    assert login(c, PW + "!")[0].status_code == 200


def test_test_connection_never_sends_stored_token_to_a_new_host(admin):
    c, _ = admin
    _, csrf = login(c)
    seen = []

    def handler(request):
        body = json.loads(request.content)
        seen.append((str(request.url), request.headers.get("authorization"), body["method"]))
        return httpx.Response(200, json=ok("7.4.0" if body["method"] == "apiinfo.version" else []))

    with respx.mock(assert_all_called=False) as router:
        router.post(url__regex=r"https://new\.example\.com/.*").mock(side_effect=handler)
        # URL changed, no new credentials: refused, nothing is sent anywhere
        d = c.post("/admin/api/test-connection", headers=H(csrf),
                   json={"candidate": {"zabbix_url": "https://new.example.com", "zabbix_api_token": ""}}).json()
        assert d["ok"] is False and d["error"] == "credentials_required" and not seen
        # with a new token it works and uses that token, not the stored one
        d = c.post("/admin/api/test-connection", headers=H(csrf),
                   json={"candidate": {"zabbix_url": "https://new.example.com", "zabbix_api_token": "new-tok"}}).json()
    assert d["ok"] and d["version"] == "7.4.0" and d["supported"] and d["can_read_hosts"]
    assert seen[-1][1] == "Bearer new-tok"


def test_test_connection_same_url_may_reuse_stored_token(admin):
    c, _ = admin
    _, csrf = login(c)
    with respx.mock(assert_all_called=False) as router:
        route = router.post(API).mock(side_effect=lambda r: httpx.Response(
            200, json=ok("7.4.0" if json.loads(r.content)["method"] == "apiinfo.version" else [])))
        d = c.post("/admin/api/test-connection", headers=H(csrf),
                   json={"candidate": {"zabbix_url": "https://zbx.example.com/", "zabbix_api_token": ""}}).json()
    assert d["ok"] and route.calls[-1].request.headers["authorization"] == "Bearer tok-secret-123"


def test_malformed_json_bodies_are_400_not_500(admin):
    c, _ = admin
    _, csrf = login(c)
    for path in ("settings", "test-connection", "tokens", "password"):
        r = c.post(f"/admin/api/{path}", headers=H(csrf), content=b"{not json")
        assert r.status_code == 400, path
        r = c.post(f"/admin/api/{path}", headers=H(csrf), json=[1, 2])
        assert r.status_code == 400, path
    assert c.post("/admin/api/settings", headers=H(csrf), json={"changes": "x"}).status_code == 400
    assert c.post("/admin/api/login", content=b"nope").status_code == 400


def test_login_throttle_uses_proxy_appended_address_not_spoofable_prefix(admin):
    c, _ = admin
    for i in range(5):  # attacker rotates the leftmost (client-supplied) XFF entry
        r = c.post("/admin/api/login", json={"password": "bad"},
                   headers={"X-Forwarded-For": f"10.9.9.{i}, 203.0.113.7"})
        assert r.status_code == 401
    r = c.post("/admin/api/login", json={"password": PW},
               headers={"X-Forwarded-For": "10.1.1.1, 203.0.113.7"})
    assert r.status_code == 429  # same real client (203.0.113.7) is locked out
    r = c.post("/admin/api/login", json={"password": PW}, headers={"X-Forwarded-For": "198.51.100.9"})
    assert r.status_code == 200  # a different client is unaffected


def test_password_change_signs_out_other_sessions(admin):
    c, _ = admin
    r, csrf = login(c)
    old_cookie = c.cookies.get("zmcp_admin")
    r = c.post("/admin/api/password", headers=H(csrf), json={"current": PW, "new": PW + "!"})
    assert r.status_code == 200 and r.json()["csrf"]
    assert c.get("/admin/api/state").status_code == 200  # this session was re-issued
    c.cookies.clear()
    c.cookies.set("zmcp_admin", old_cookie, path="/admin")
    assert c.get("/admin/api/state").status_code == 401  # the old cookie no longer verifies


def test_revoke_needs_a_specific_fingerprint(admin):
    c, store = admin
    _, csrf = login(c)
    assert c.post("/admin/api/tokens", headers=H(csrf), json={"action": "revoke", "fingerprint": "a"}).status_code == 404
    assert len(store.settings.mcp_token_hashes) == 1


def test_test_connection_reports_failure(admin):
    c, _ = admin
    _, csrf = login(c)
    with respx.mock(assert_all_called=False) as router:
        router.post(API).mock(side_effect=httpx.ConnectError("x"))
        d = c.post("/admin/api/test-connection", headers=H(csrf), json={"candidate": {}}).json()
    assert d["ok"] is False and d["error"] == "connection_error" and "tok-secret" not in json.dumps(d)


def test_audit_tail(admin, tmp_path):
    c, store = admin
    _, csrf = login(c)
    assert c.get("/admin/api/audit").json()["configured"] is False
    log = tmp_path / "audit.log"
    log.write_text('{"ts":1,"method":"host.get","outcome":"ok","ms":3,"mutating":false}\nnoise\n')
    store.update({"audit_log": str(log)})
    d = c.get("/admin/api/audit").json()
    assert d["configured"] and len(d["lines"]) == 1


def test_base_href_follows_proxy_prefix_and_rejects_injection(admin):
    c, _ = admin
    assert '<base href="/admin/">' in c.get("/admin").text
    r = c.get("/admin", headers={"X-Forwarded-Prefix": "/zabbix-mcp"})
    assert '<base href="/zabbix-mcp/admin/">' in r.text
    r = c.get("/admin/", headers={"X-Forwarded-Prefix": '/x"><script>alert(1)</script>'})
    assert "<script>alert" not in r.text and '<base href="/admin/">' in r.text
