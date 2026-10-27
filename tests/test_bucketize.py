from zabbix_mcp.tools.common import age, bucketize


def test_bucketize_small_and_large():
    assert bucketize([], 5) == []
    assert len(bucketize([(1, 1.0), (2, 2.0)], 5)) == 2
    pts = [(i, float(i)) for i in range(1000)]
    out = bucketize(pts, 10)
    assert len(out) == 10 and out[0]["min"] == 0.0 and out[-1]["max"] == 999.0
    assert all(b["min"] <= b["avg"] <= b["max"] for b in out)


def test_bucketize_same_timestamp():
    out = bucketize([(5, 1.0), (5, 3.0), (5, 2.0)] * 5, 3)
    assert out[0]["avg"] == 2.0


def test_age():
    assert age(5) == "5s" and age(125) == "2m" and age(7500) == "2h5m" and age(200000) == "2d7h"
