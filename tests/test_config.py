import json
import os
import stat

import pytest

from zabbix_mcp.config import ConfigStore, hash_token
from zabbix_mcp.errors import ConfigError


def test_env_defaults_are_safe(tmp_path):
    s = ConfigStore(tmp_path / "c.json", env={}).settings
    assert s.read_only is True and s.confirm_writes == "all" and s.transport == "stdio"


def test_env_parsing(tmp_path):
    env = {"READ_ONLY": "false", "ZABBIX_TOOLSETS": "monitoring, hosts", "MCP_PORT": "9000",
           "MCP_AUTH_TOKEN": "abc", "ZABBIX_VERIFY_TLS": "0"}
    s = ConfigStore(tmp_path / "c.json", env=env).settings
    assert s.read_only is False and s.toolsets == ["monitoring", "hosts"] and s.port == 9000
    assert s.mcp_token_hashes == [hash_token("abc")] and s.verify_tls is False


def test_invalid_values_rejected(tmp_path):
    with pytest.raises(ConfigError):
        ConfigStore(tmp_path / "c.json", env={"ZABBIX_TOOLSETS": "nope"})
    with pytest.raises(ConfigError):
        ConfigStore(tmp_path / "c.json", env={"MCP_PORT": "abc"})


def test_update_persists_with_0600_and_hot_reload(tmp_path):
    p = tmp_path / "c.json"
    a = ConfigStore(p, env={})
    a.update({"read_only": False, "zabbix_api_token": "secret"})
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    b = ConfigStore(p, env={})
    assert b.settings.read_only is False and b.settings.zabbix_api_token == "secret"
    # external edit is picked up by the other store
    data = json.loads(p.read_text())
    data["default_limit"] = 7
    p.write_text(json.dumps(data))
    os.utime(p, (os.path.getmtime(p) + 5, os.path.getmtime(p) + 5))
    assert b.settings.default_limit == 7


def test_blank_secret_keeps_existing(tmp_path):
    st = ConfigStore(tmp_path / "c.json", env={})
    st.update({"zabbix_api_token": "keep"})
    st.update({"zabbix_api_token": "", "log_level": "DEBUG"})
    assert st.settings.zabbix_api_token == "keep" and st.settings.log_level == "DEBUG"


def test_unknown_key_rejected(tmp_path):
    with pytest.raises(ConfigError):
        ConfigStore(tmp_path / "c.json", env={}).update({"bogus": 1})


def test_mcp_tokens_stored_hashed(tmp_path):
    st = ConfigStore(tmp_path / "c.json", env={})
    tok = st.add_mcp_token()
    assert tok.startswith("zmcp_")
    assert tok not in (tmp_path / "c.json").read_text()
    assert hash_token(tok) in st.settings.mcp_token_hashes
    st.revoke_mcp_tokens()
    assert st.settings.mcp_token_hashes == []


def test_public_dict_hides_secrets(tmp_path):
    st = ConfigStore(tmp_path / "c.json", env={"ZABBIX_API_TOKEN": "x" * 20})
    d = st.settings.public_dict()
    assert d["zabbix_api_token"] is True and "xxxx" not in json.dumps(d)
