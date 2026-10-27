import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pexpect
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SHIMS = ROOT / "tests" / "shims"
pytestmark = pytest.mark.skipif(shutil.which("jq") is None, reason="jq required")

DEBIAN12 = 'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\nPRETTY_NAME="Debian GNU/Linux 12"\n'
BASE = {
    "ZMCP_ZABBIX_URL": "https://zabbix.example.com",
    "ZMCP_ZABBIX_TOKEN": "api-token-abc",
    "ZMCP_EXPOSE": "traefik",
    "ZMCP_PUBLIC_URL": "https://example.com",
}


@pytest.fixture
def env(tmp_path):
    shim = tmp_path / "shim"
    shim.mkdir()
    osr = tmp_path / "os-release"
    osr.write_text(DEBIAN12)
    e = {
        "PATH": f"{SHIMS}:{os.environ['PATH']}", "SHIM_DIR": str(shim), "HOME": str(tmp_path),
        "ZMCP_SKIP_ROOT_CHECK": "1", "ZMCP_INSTALL_DIR": str(tmp_path / "opt"),
        "ZMCP_BIN_DIR": str(tmp_path / "bin"), "ZMCP_OS_RELEASE": str(osr), "SHIM_TRAEFIK": "1",
    }
    e["_tmp"] = str(tmp_path)
    return e


def run(env, args=("--non-interactive",), extra=None):
    e = {k: v for k, v in {**env, **BASE, **(extra or {})}.items() if k != "_tmp"}
    return subprocess.run(["bash", str(ROOT / "install.sh"), *args], env=e, capture_output=True,
                          text=True, stdin=subprocess.DEVNULL, timeout=60)


def opt(env):
    return Path(env["_tmp"]) / "opt"


def shimlog(env, name="docker.log"):
    p = Path(env["SHIM_DIR"]) / name
    return p.read_text() if p.exists() else ""


def test_traefik_install_end_to_end(env):
    r = run(env, extra={"ZMCP_TRAEFIK_RESOLVER": "le"})
    assert r.returncode == 0, r.stderr
    compose = yaml.safe_load((opt(env) / "docker-compose.yml").read_text())
    svc = compose["services"]["zabbix-mcp"]
    labels = {k: v for k, v in (x.split("=", 1) for x in svc["labels"])}
    assert labels["traefik.http.routers.zabbix-mcp.rule"] == \
        "Host(`example.com`) && PathPrefix(`/zabbix-mcp`)"
    assert labels["traefik.http.routers.zabbix-mcp.entrypoints"] == "websecure"  # auto-detected
    assert labels["traefik.http.routers.zabbix-mcp.tls.certresolver"] == "le"
    assert labels["traefik.http.middlewares.zabbix-mcp-strip.stripprefix.prefixes"] == "/zabbix-mcp"
    assert labels["traefik.http.services.zabbix-mcp.loadbalancer.server.port"] == "8000"
    assert "ports" not in svc and svc["read_only"] is True and svc["cap_drop"] == ["ALL"]
    assert svc["user"] == "10001:10001" and "no-new-privileges:true" in svc["security_opt"]
    assert compose["networks"]["proxy"] == {"external": True, "name": "proxy"}  # detected network
    assert stat.S_IMODE(os.stat(opt(env) / "docker-compose.yml").st_mode) == 0o600
    init = (Path(env["SHIM_DIR"]) / "init.env").read_text()
    assert "ZABBIX_URL=https://zabbix.example.com" in init and "READ_ONLY=true" in init
    assert "ZABBIX_API_TOKEN=api-token-abc" in init and "ADMIN_ENABLED=true" in init
    assert "MCP_PUBLIC_URL=https://example.com/zabbix-mcp" in init
    assert "admin" not in re.search(r"ZABBIX_TOOLSETS=(.*)", init).group(1).split(",")
    assert not list(opt(env).glob(".init-env.*"))  # secrets file cleaned up
    info = (opt(env) / "client-config.txt").read_text()
    assert "https://example.com/zabbix-mcp/mcp" in info and "zmcp_faketoken1234567890" in info
    assert "claude mcp add --transport http zabbix" in info
    assert stat.S_IMODE(os.stat(opt(env) / "client-config.txt").st_mode) == 0o600
    assert "api-token-abc" not in info and "api-token-abc" not in r.stderr  # never echoed
    assert "api-token-abc" not in shimlog(env)  # never on a command line
    assert "api-token-abc" in shimlog(env, "curl.cfg")  # only via curl config on stdin
    assert (Path(env["_tmp"]) / "bin" / "zabbix-mcp-ctl").exists()
    conf = (opt(env) / "install.conf").read_text()
    assert "ZMCP_PATH_PREFIX=/zabbix-mcp" in conf and "api-token" not in conf and "password" not in conf.lower()
    assert "Generated admin password" in r.stderr  # non-interactive generates and shows one


def test_direct_mode_and_write_enabled(env):
    r = run(env, extra={"ZMCP_EXPOSE": "direct", "ZMCP_ALLOW_WRITES": "yes", "ZMCP_CONFIRM": "destructive",
                        "ZMCP_ADMIN_TOOLSET": "yes", "ZMCP_ADMIN_UI": "no", "ZMCP_PORT": "9001",
                        "ZMCP_PUBLIC_URL": ""})
    assert r.returncode == 0, r.stderr
    svc = yaml.safe_load((opt(env) / "docker-compose.yml").read_text())["services"]["zabbix-mcp"]
    assert svc["ports"] == ["127.0.0.1:9001:8000"] and "labels" not in svc
    init = (Path(env["SHIM_DIR"]) / "init.env").read_text()
    assert "READ_ONLY=false" in init and "CONFIRM_WRITES=destructive" in init
    assert "ADMIN_ENABLED=false" in init and ",admin" in init
    assert "http://127.0.0.1:9001/mcp" in (opt(env) / "client-config.txt").read_text()


def test_rejects_bad_inputs(env):
    assert run(env, extra={"ZMCP_ZABBIX_TOKEN": ""}).returncode != 0  # token required
    r = run(env, extra={"ZMCP_PATH_PREFIX": "/bad path"})
    assert r.returncode != 0 and "invalid path" in r.stderr
    r = run(env, extra={"ZMCP_TRAEFIK_NETWORK": "x;rm -rf /"})
    assert r.returncode != 0
    r = run({**env, "SHIM_BAD_TOKEN": "1"})
    assert r.returncode != 0 and "token was rejected" in r.stderr
    r = run({**env, "SHIM_ZBX_VERSION": "6.0.30"})
    assert r.returncode != 0  # wrong version, non-interactive refuses to continue
    r = run({**env, "SHIM_TLS_FAIL": "1"})
    assert r.returncode != 0 and "TLS verification failed" in r.stderr
    (Path(env["_tmp"]) / "os-release").write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    r = run(env)
    assert r.returncode != 0 and "Debian 12 and 13" in r.stderr
    assert not (opt(env) / "docker-compose.yml").exists()  # nothing written on failure


def test_skip_tls_verification_option(env):
    r = run({**env, "SHIM_TLS_FAIL": "1"}, extra={"ZMCP_SKIP_VALIDATION": "1", "ZMCP_VERIFY_TLS": "no"})
    assert r.returncode == 0, r.stderr
    assert "ZABBIX_VERIFY_TLS=false" in (Path(env["SHIM_DIR"]) / "init.env").read_text()


def test_reconfigure_reuses_answers_and_upgrade_keeps_config(env):
    assert run(env).returncode == 0
    log_before = shimlog(env).count("\nrun ") + shimlog(env).startswith("run ")
    # reconfigure: only change write permission; everything else defaults to previous answers
    minimal = {k: v for k, v in env.items()}
    e = {k: v for k, v in {**minimal}.items() if k != "_tmp"}
    e["ZMCP_ALLOW_WRITES"] = "yes"
    r = subprocess.run(["bash", str(ROOT / "install.sh"), "--reconfigure", "--non-interactive"], env=e,
                       capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
    assert r.returncode == 0, r.stderr
    init = (Path(env["SHIM_DIR"]) / "init.env").read_text()
    assert "READ_ONLY=false" in init and "ZABBIX_URL=https://zabbix.example.com" in init
    assert "ZABBIX_API_TOKEN" not in init  # blank token on reconfigure keeps the stored one
    assert "MCP_PUBLIC_URL=https://example.com/zabbix-mcp" in init
    labels = yaml.safe_load((opt(env) / "docker-compose.yml").read_text())["services"]["zabbix-mcp"]["labels"]
    assert any("PathPrefix(`/zabbix-mcp`)" in x for x in labels)
    # upgrade must not run init (no new token / config rewrite)
    runs_before = shimlog(env).count("\nrun ")
    e2 = {k: v for k, v in env.items() if k != "_tmp"}
    r = subprocess.run(["bash", str(ROOT / "install.sh"), "--upgrade", "--non-interactive"], env=e2,
                       capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
    assert r.returncode == 0, r.stderr
    assert shimlog(env).count("\nrun ") == runs_before and log_before >= 0
    assert "upgraded" in r.stderr


def test_interactive_session(env):
    e = {k: v for k, v in env.items() if k != "_tmp"}
    child = pexpect.spawn("bash", [str(ROOT / "install.sh")], env=e, encoding="utf-8", timeout=30)
    child.logfile_read = None
    def say(prompt, answer):
        child.expect(prompt)
        child.sendline(answer)
    say(r"Zabbix web URL", "zabbix.example.com/")
    say(r"API token", "tok-interactive-123")
    say(r"Allow changes in Zabbix", "y")
    say(r"Write confirmation level", "")
    say(r"user/token/role", "")
    say(r"Expose via Traefik", "")
    say(r"Base URL of your server", "https://example.com/")
    say(r"URL path for this service", "zabbix")
    say(r"Docker network Traefik uses", "")
    say(r"HTTPS entrypoint", "")
    say(r"certificate resolver", "")
    say(r"Enable the web admin UI", "")
    say(r"Admin password", "short")
    child.expect("too short")
    say(r"Admin password", "a long enough password!")
    say(r"Repeat password", "a long enough password!")
    say(r"Proceed with installation", "")
    child.expect(pexpect.EOF)
    child.close()
    assert child.exitstatus == 0
    init = (Path(env["SHIM_DIR"]) / "init.env").read_text()
    assert "READ_ONLY=false" in init and "MCP_PUBLIC_URL=https://example.com/zabbix" in init
    assert "ZABBIX_URL=https://zabbix.example.com" in init
    assert (Path(env["SHIM_DIR"]) / "init.stdin").read_text().strip() == "a long enough password!"
    assert "tok-interactive-123" not in shimlog(env)


def helper(fn, *args):
    out = subprocess.run(
        ["bash", "-c", f'ZMCP_SOURCE_ONLY=1 source "{ROOT}/install.sh"; {fn} "$@"', "_", *args],
        capture_output=True, text=True)
    return out.stdout, out.returncode


@pytest.mark.parametrize("fn,arg,expected", [
    ("normalize_zabbix_url", "zabbix.example.com", "https://zabbix.example.com"),
    ("normalize_zabbix_url", "http://z.local/zabbix/", "http://z.local/zabbix"),
    ("normalize_zabbix_url", "https://z/api_jsonrpc.php", "https://z"),
    ("normalize_prefix", "zabbix-mcp/", "/zabbix-mcp"),
    ("normalize_prefix", "/", "/zabbix-mcp"),
    ("url_host", "https://example.com:8443/x", "example.com"),
])
def test_pure_helpers(fn, arg, expected):
    assert helper(fn, arg)[0] == expected


def test_validators():
    assert helper("valid_prefix", "/zabbix-mcp")[1] == 0 and helper("valid_prefix", "/a/b")[1] == 0
    assert helper("valid_prefix", "/a b")[1] != 0 and helper("valid_prefix", "nope")[1] != 0
    assert helper("valid_port", "8000")[1] == 0 and helper("valid_port", "70000")[1] != 0
    assert helper("valid_name", "websecure")[1] == 0 and helper("valid_name", "a;b")[1] != 0
    out, rc = helper("random_password")
    assert rc == 0 and len(out) == 32 and out.isalnum()


def _apt_update(env, apt_out):
    e = {k: v for k, v in env.items() if k != "_tmp"}
    e["ZMCP_SOURCE_ONLY"] = "1"
    e["SHIM_APT_OUT"] = apt_out
    return subprocess.run(["bash", "-c", f'source "{ROOT}/install.sh"; apt_update; echo done'], env=e,
                          capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=30)


def test_apt_update_explains_a_wrong_system_clock(env):
    r = _apt_update(env, "W: OpenPGP signature verification failed: ... Not live until 2026-10-27T20:43:58Z")
    assert r.returncode != 0 and "clock" in r.stderr and "timedatectl set-ntp true" in r.stderr
    assert "done" not in r.stdout


def test_apt_update_passes_on_clean_output(env):
    r = _apt_update(env, "Hit:1 http://deb.debian.org/debian trixie InRelease")
    assert r.returncode == 0 and "done" in r.stdout
