---
name: zabbix-mcp
description: Use the Zabbix MCP server to triage problems, inspect hosts and metrics, acknowledge events, schedule maintenance and build or edit dashboards on a Zabbix 7.4 instance, safely and with minimal token use.
version: 1.0.0
---

# Zabbix MCP

Tools come from the `zabbix` MCP server. Prefer the highest tier that does the job.

## Tool tiers
1. **Curated** (use first): `get_active_problems`, `get_host_details`, `search_hosts`, `list_host_groups`, `get_triggers`, `get_latest_values`, `query_metrics_history`, `get_problem_events`, `acknowledge_problem`, `manage_maintenance_window`, `get_sla_report`, `get_audit_log`, `get_server_status`, `dashboard_widget_catalog`, `manage_dashboard`.
2. **Toolset tools**: `zabbix_monitoring`, `zabbix_hosts`, `zabbix_config`, `zabbix_visualization`, `zabbix_services`, `zabbix_alerting` (and `zabbix_admin` if enabled). Each takes `method`, `params`, `confirm_token`.
3. **Discovery / escape hatch**: `zabbix_search_methods` -> `zabbix_describe_method` -> `zabbix_raw_api`. Never guess method names or params; look them up.

## Triage workflow
1. `get_server_status` once if connectivity is in doubt.
2. `get_active_problems` (start with `min_severity=high`, `limit` small), then widen.
3. For a problem: `get_host_details` -> `get_triggers` -> `get_latest_values` -> `query_metrics_history` for the relevant items (CPU, memory, disk, ping). Use `get_problem_events` for the timeline.
4. Summarise: what, since when, blast radius, likely cause, suggested next step. Quote event IDs and host names.

## Writing safely
- The server may be **read-only**. If a write is refused with a read-only message, stop and tell the user; do not try to route around it.
- Writes are **two-step**: the first call returns a `confirm_token` and a description of the change. Show the user what will change, get approval, then repeat the identical call with the token. Tokens are single-use, expire after 5 minutes and are bound to the exact method+params.
- Never batch destructive changes (`*.delete`, `*.massupdate`, template unlink) without listing every affected object first.
- Blocked by default and not to be attempted: users, roles, tokens, authentication, settings, modules, configuration.import, script.execute. If the user needs one, they must enable it in the admin UI.
- Prefer `acknowledge_problem` (with a comment) and `manage_maintenance_window` over raw calls.

## Dashboards
- Call `dashboard_widget_catalog` to see widget types and friendly fields before building.
- `manage_dashboard` ops: `list`, `get`, `create`, `add_widget`, `remove_widget`, `rename`, `set_sharing`, `replace_pages`, `delete`. Widgets are auto-placed on the 72x64 grid and field names are expanded for you.
- Read with `get` before modifying; edit with `add_widget`/`remove_widget` rather than `replace_pages`, which deletes pages not listed.
- Zabbix does not validate widget fields: after creating, `get` the dashboard to verify.

## Token economy
- Keep `limit` small, request only the fields you need, and prefer time-bounded history queries.
- Outputs are trimmed and capped; if a result says it was truncated, narrow the filter instead of re-requesting everything.

## Errors
`unauthorized` = bad MCP token. Zabbix auth errors = the API token is invalid or lacks permissions. `blocked` = guardrail; explain it to the user. Timeouts/connection errors: report, retry a read once, never retry a write blindly.
