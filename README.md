# Zabbix-MCP

A production-oriented [Model Context Protocol](https://modelcontextprotocol.io) server for **Zabbix 7.4**. It lets
agent harnesses (Claude Desktop/Code, ChatGPT/Codex, Hermes, OpenClaw, Cursor…) triage problems, query
metrics, manage maintenance and **build/edit dashboards**, with guardrails so an LLM cannot do damage by accident.

* Python 3.11+, official `mcp` SDK (FastMCP), `httpx`, Streamable HTTP + stdio
* Docker image, Traefik path routing (no new hostname needed), interactive Debian installer
* Web admin UI for every setting, hot-reloaded
* Full API coverage (228 methods / 60 API groups) without 228 tools

## Tool design
| Tier | Tools |
|---|---|
| Curated | `get_active_problems`, `get_host_details`, `search_hosts`, `list_host_groups`, `get_triggers`, `get_latest_values`, `query_metrics_history`, `get_problem_events`, `acknowledge_problem`, `manage_maintenance_window`, `get_sla_report`, `get_audit_log`, `get_server_status`, `dashboard_widget_catalog`, `manage_dashboard` |
| Toolset | one `zabbix_<toolset>(method, params, confirm_token)` per enabled toolset: monitoring, hosts, config, visualization, services, alerting, admin |
| Escape hatch | `zabbix_search_methods`, `zabbix_describe_method`, `zabbix_raw_api` |

Outputs are trimmed to useful fields, `limit` defaults to 50, and responses are capped (20 000 chars by default) to protect the context window.

## Safety
* `READ_ONLY` (default on) hard-blocks every mutating method.
* Two-step writes: first call returns a single-use, 5-minute `confirm_token` bound to method + params (`CONFIRM_WRITES=all|destructive|none`).
* Unknown methods blocked; deny beats allow; users/roles/tokens/settings/modules/`script.execute`/`configuration.import` blocked by default.
* Secrets never logged (stderr only, masked); JSON-lines audit log; bearer tokens stored as hashes; admin password PBKDF2.

## Install
See [docs/INSTALL.md](docs/INSTALL.md). Short version: `git clone … && sudo ./install.sh`.

## Connect your agent
See [docs/CLIENTS.md](docs/CLIENTS.md) for Claude Desktop, Claude Code, ChatGPT desktop/Codex, Hermes, OpenClaw,
Cursor. Skill files that teach agents the workflow live in [`skills/`](skills):
`skills/zabbix-mcp` (generic/Claude), `skills/hermes/zabbix-mcp`, `skills/openclaw/zabbix-mcp`.

## Local development
```bash
uv sync
uv run pytest            # 111+ tests, no Zabbix needed (fake API)
uv run ruff check .
ZABBIX_URL=https://zbx ZABBIX_API_TOKEN=… uv run zabbix-mcp check        # verify connectivity
ZABBIX_URL=… ZABBIX_API_TOKEN=… uv run python scripts/live_check.py [--write]   # exercise tools on a real Zabbix
```
stdio mode (`MCP_TRANSPORT=stdio`) keeps stdout clean for the protocol.

## Verification status
Unit/integration tests run against a fake Zabbix. CI additionally builds the Docker image and runs a contract test
against a real Zabbix 7.4 stack (`scripts/live_check.py --write`). Run `live_check.py` against your own instance after
installing to validate the curated tools end to end.

## License

MIT, see [LICENSE](LICENSE).
