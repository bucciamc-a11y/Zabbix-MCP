import pytest

from zabbix_mcp.config import Settings
from zabbix_mcp.guard import ConfirmStore, evaluate
from zabbix_mcp.logging_setup import mask_obj, mask_text
from zabbix_mcp.trim import prepare_params, shrink


def S(**kw):
    return Settings(**kw)


def test_read_only_blocks_writes_not_reads():
    s = S(read_only=True)
    assert evaluate(s, "host.get").allowed
    d = evaluate(s, "host.update")
    assert not d.allowed and "read-only" in d.reason


def test_unknown_method_blocked():
    assert not evaluate(S(read_only=False), "host.nope").allowed


def test_default_blocklist_and_allow_override():
    s = S(read_only=False)
    assert not evaluate(s, "user.create").allowed
    assert not evaluate(s, "script.execute").allowed
    assert evaluate(S(read_only=False, allow_methods=["user.create"]), "user.create").allowed
    assert evaluate(s, "user.get").allowed


def test_deny_beats_allow():
    s = S(read_only=False, deny_methods=["host.delete", "item.*"], allow_methods=["host.delete"])
    assert not evaluate(s, "host.delete").allowed
    assert not evaluate(s, "item.get").allowed


@pytest.mark.parametrize("mode,method,needs", [
    ("all", "host.update", True), ("all", "host.get", False),
    ("destructive", "host.update", False), ("destructive", "host.delete", True),
    ("none", "host.delete", False)])
def test_confirm_modes(mode, method, needs):
    d = evaluate(S(read_only=False, confirm_writes=mode), method)
    assert d.allowed and d.needs_confirm is needs


def test_confirm_token_single_use_and_bound():
    cs = ConfirmStore()
    t = cs.issue("host.update", {"hostid": "1", "status": 1})
    assert not cs.consume(t, "host.update", {"hostid": "1", "status": 0})  # wrong params; consumed
    t = cs.issue("host.update", {"hostid": "1", "status": 1})
    assert cs.consume(t, "host.update", {"status": 1, "hostid": "1"})
    assert not cs.consume(t, "host.update", {"hostid": "1", "status": 1})  # reuse


def test_confirm_token_expires():
    now = [0.0]
    cs = ConfirmStore(ttl=10, clock=lambda: now[0])
    t = cs.issue("a.b", {})
    now[0] = 11
    assert not cs.consume(t, "a.b", {})


def test_prepare_params_defaults():
    p = prepare_params("host.get", {}, 50)
    assert p["limit"] == 50 and "hostid" in p["output"]
    assert prepare_params("host.get", {"output": "extend", "limit": 5}, 50) == {
        "output": "extend", "limit": 5}
    assert "limit" not in prepare_params("host.get", {"countOutput": True}, 50)
    assert prepare_params("settings.get", {}, 50) == {}
    assert prepare_params("host.update", {"hostid": "1"}, 50) == {"hostid": "1"}
    orig = {}
    prepare_params("host.get", orig, 50)
    assert orig == {}


def test_shrink_list_keeps_whole_items():
    data = [{"i": i, "pad": "x" * 100} for i in range(50)]
    out, info = shrink(data, 1000)
    assert info["truncated"] and info["total"] == 50 and 0 < len(out) < 50
    assert all(isinstance(x, dict) for x in out)
    out2, info2 = shrink(data[:2], 100000)
    assert info2 is None and out2 == data[:2]


def test_shrink_always_returns_one_item():
    out, _ = shrink([{"big": "x" * 5000}, {"a": 1}], 1000)
    assert len(out) == 1


def test_masking():
    assert "abc123" not in mask_text("Authorization: Bearer abc123xyz")
    assert "zmcp_" not in mask_text("token zmcp_AbC-123_x")
    m = mask_obj({"password": "p", "nested": {"api_token": "t", "ok": 1}, "list": [{"secret": "s"}]})
    assert m == {"password": "***", "nested": {"api_token": "***", "ok": 1}, "list": [{"secret": "***"}]}
