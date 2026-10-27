import pytest

from zabbix_mcp.errors import BlockedError
from zabbix_mcp.tools.dashboards import (
    build_widget,
    check_layout,
    expand_fields,
    find_free_slot,
)


def test_expand_fields_types_and_indexes():
    f = expand_fields({"groupids": [4, 5], "severities": [4, 5], "show_tags": 1,
                       "ds": [{"hosts": ["web*"], "items": ["cpu*"], "color": "FF0000"}],
                       "itemid": 7, "hostids": {"_reference": "DASHBOARD._hostid"}})
    by = {x["name"]: x for x in f}
    assert by["groupids.0"] == {"type": 2, "name": "groupids.0", "value": 4}
    assert by["severities.1"]["type"] == 0 and by["show_tags"]["type"] == 0
    assert by["ds.0.hosts.0"] == {"type": 1, "name": "ds.0.hosts.0", "value": "web*"}
    assert by["ds.0.color"]["type"] == 1 and by["itemid"]["type"] == 4
    assert by["hostids._reference"]["type"] == 1


def test_native_fields_pass_through():
    native = [{"type": 1, "name": "reference", "value": "ABCDE"}]
    assert expand_fields(native) == native
    with pytest.raises(BlockedError):
        expand_fields("nope")


def test_free_slot_and_overlap():
    a = {"x": 0, "y": 0, "width": 36, "height": 5}
    assert find_free_slot([a], 36, 5) == (36, 0)
    row = [a, {"x": 36, "y": 0, "width": 36, "height": 5}]
    assert find_free_slot(row, 18, 3) == (0, 5)
    assert find_free_slot([{"x": 0, "y": 0, "width": 72, "height": 64}], 1, 1) is None


def test_build_widget_autoplaces_and_adds_reference_deterministically():
    w1 = build_widget({"type": "problems", "name": "P", "fields": {"severities": [4, 5]}}, [])
    w2 = build_widget({"type": "problems", "name": "P", "fields": {"severities": [4, 5]}}, [])
    ref1 = [f for f in w1["fields"] if f["name"] == "reference"][0]["value"]
    assert len(ref1) == 5 and ref1.isupper() and w1["fields"] == w2["fields"]
    assert (w1["x"], w1["y"], w1["width"], w1["height"]) == (0, 0, 18, 5)
    w3 = build_widget({"type": "clock", "name": "C"}, [w1])
    assert (w3["x"], w3["y"]) == (18, 0) and not any(f["name"] == "reference" for f in w3["fields"])


def test_validation():
    ok = {"type": "clock", "x": 0, "y": 0, "width": 10, "height": 3, "fields": []}
    assert check_layout([ok]) == []
    assert check_layout([{**ok, "type": "nope"}])
    assert check_layout([{**ok, "x": 70, "width": 10}])
    assert check_layout([ok, {**ok, "x": 5}])  # overlap
    assert check_layout([{**ok, "width": 0}])
