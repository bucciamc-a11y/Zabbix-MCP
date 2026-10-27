# Installation (Debian 12/13 VPS with Traefik)

## Requirements
* Debian 12 or 13, root/sudo, outbound internet.
* An existing Traefik v2/v3 (Docker provider) with HTTPS on a hostname you already own, e.g. `example.com`.
* Zabbix **7.4** with an API token on a dedicated API-only user (User settings → API tokens).
  Give that user a role/permissions matching what you want the agents to do (read-only host-group access is a good start).

## One-line install
```bash
git clone https://github.com/bucciamc-a11y/Zabbix-MCP.git && cd Zabbix-MCP
sudo ./install.sh
```
The installer asks for:
1. **Your server URL** (e.g. `https://example.com`) and path (default `/zabbix-mcp`) → MCP endpoint `https://example.com/zabbix-mcp/mcp`, admin UI `…/zabbix-mcp/admin`. No new DNS needed.
2. Zabbix URL and API token (validated: version must be 7.4).
3. Traefik network, entrypoint and cert resolver (auto-detected, confirm or edit).
4. Read-only mode (default **on**), write-confirmation mode, enabled toolsets, admin UI password.

It installs Docker if needed, writes `/opt/zabbix-mcp/docker-compose.yml` + `data/config.json` (0600), starts the
container, waits for health and runs a smoke test. Connection details are saved to `/opt/zabbix-mcp/client-config.txt`.

Non-interactive: `ZMCP_PUBLIC_URL=… ZMCP_ZABBIX_URL=… ZMCP_ZABBIX_TOKEN=… sudo -E ./install.sh --non-interactive`.

## Day-2 operations
`zabbix-mcp-ctl status|logs|restart|check|token|set-admin-password|reconfigure|upgrade|uninstall`
(or `sudo ./install.sh --reconfigure | --upgrade | --uninstall`).

## Admin UI
Open `<server-url>/zabbix-mcp/admin`: connection settings, read-only switch, toolsets, allow/deny lists, MCP tokens,
audit log. Changes apply immediately (hot reload); connection changes rebuild the client.

## Security model
* MCP endpoint requires a bearer token (stored only as sha256 hashes). Rotate in the admin UI.
* Zabbix token never leaves the container config (0600) and is masked in logs/audit.
* Container: non-root, read-only rootfs, all capabilities dropped, memory/pids limited.
* Dangerous API areas (users, roles, tokens, settings, modules, script.execute, configuration.import) are blocked by default.

## Troubleshooting
| Symptom | Fix |
|---|---|
| 404 on `/zabbix-mcp/...` | Router rule/priority; check `docker logs traefik` and labels in the compose file |
| 401 | Wrong MCP token/header (`Authorization: Bearer …` or `X-API-Key`) |
| `check` fails with auth error | Zabbix API token invalid/expired or user lacks permission |
| Certificate errors to Zabbix | Set `ZABBIX_CA_BUNDLE`, or `VERIFY_TLS=false` (not recommended) |
