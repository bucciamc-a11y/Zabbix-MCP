from zabbix_mcp import registry as r


def test_group_count_and_method_count():
    assert len(r.API_GROUPS) == 60
    assert len(r.all_methods()) == 228


def test_every_group_in_exactly_one_toolset():
    seen: dict[str, str] = {}
    for ts, groups in r.TOOLSETS.items():
        for g in groups:
            assert g not in seen, f"{g} in {seen[g]} and {ts}"
            seen[g] = ts
    assert set(seen) == set(r.API_GROUPS)


def test_classification():
    assert not r.is_mutating("host.get")
    assert not r.is_mutating("sla.getsli")
    assert r.is_mutating("host.create")
    assert r.is_mutating("event.acknowledge")
    assert r.is_mutating("history.push")


def test_default_blocks():
    assert r.is_blocked_by_default("user.create")
    assert r.is_blocked_by_default("script.execute")
    assert not r.is_blocked_by_default("user.get")
    assert not r.is_blocked_by_default("host.update")


def test_get_method():
    assert r.get_method("dashboard.update") is not None
    assert r.get_method("dashboard.nope") is None
