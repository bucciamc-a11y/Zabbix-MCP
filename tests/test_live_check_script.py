"""Run scripts/live_check.py against a generic fake so the script itself stays healthy."""
import subprocess
import sys
from pathlib import Path

import respx
from httpx import Response

ROOT = Path(__file__).resolve().parent.parent


def test_live_check_script_imports_and_parses():
    r = subprocess.run([sys.executable, "-c", "import ast,sys;ast.parse(open('scripts/live_check.py').read())"],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


async def test_live_check_runs_against_fake(monkeypatch, tmp_path):
    import importlib.util
    import json
    monkeypatch.setenv("ZABBIX_URL", "https://zbx.example.com")
    monkeypatch.setenv("ZABBIX_API_TOKEN", "t")
    spec = importlib.util.spec_from_file_location("live_check", ROOT / "scripts" / "live_check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def handler(request):
        body = json.loads(request.content)
        m = body["method"]
        if m == "apiinfo.version":
            res = "7.4.1"
        elif body["params"].get("countOutput"):
            res = "0"
        elif m == "host.get":
            res = [{"hostid": "1", "host": "Zabbix server", "name": "Zabbix server", "status": "0",
                    "maintenance_status": "0", "interfaces": [], "hostgroups": [], "parentTemplates": [],
                    "tags": [], "items": "1", "description": ""}]
        elif m == "item.get":
            res = [{"itemid": "9", "name": "n", "key_": "k", "lastvalue": "1", "lastclock": "0",
                    "units": "", "state": "0", "value_type": "0", "hosts": [{"name": "Zabbix server"}]}]
        elif m == "sla.get":
            res = []
        else:
            res = []
        return Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": res})

    with respx.mock(assert_all_called=False) as router:
        router.post("https://zbx.example.com/api_jsonrpc.php").mock(side_effect=handler)
        rc = await mod.main(write=False)
    assert rc == 0
