import pytest

from zabbix_mcp.config import ConfigStore

URL = "https://zbx.example.com"
API = URL + "/api_jsonrpc.php"


@pytest.fixture
def make_store(tmp_path):
    def _make(**env):
        base = {"ZABBIX_URL": URL, "ZABBIX_API_TOKEN": "tok-secret-123", "DATA_DIR": str(tmp_path)}
        base.update({k: str(v) for k, v in env.items()})
        return ConfigStore(tmp_path / "config.json", env=base)
    return _make


def ok(result, id_=1):
    return {"jsonrpc": "2.0", "result": result, "id": id_}


def err(code, message, data):
    return {"jsonrpc": "2.0", "error": {"code": code, "message": message, "data": data}, "id": 1}
