# Connecting agent harnesses

Every client needs two values from the installer's `client-config.txt` (or the admin UI → Tokens):

| Value | Example |
|---|---|
| MCP URL | `https://example.com/zabbix-mcp/mcp` |
| Token | `zmcp_xxxxxxxx…` sent as `Authorization: Bearer <token>` (or `X-API-Key: <token>`) |

Quick check from any machine:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://example.com/zabbix-mcp/healthz      # 200
curl -s -H "Authorization: Bearer $TOKEN" -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' https://example.com/zabbix-mcp/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | head -c 300
```

> Client products change quickly. The snippets below follow each product's documentation at the time of writing;
> if a menu name differs, the principle is the same: remote (Streamable HTTP) server + one custom header.

## Claude Desktop
Claude Desktop's JSON config launches local (stdio) servers, so use the `mcp-remote` bridge (needs Node.js):

`claude_desktop_config.json` (Settings → Developer → Edit Config):
```json
{
  "mcpServers": {
    "zabbix": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://example.com/zabbix-mcp/mcp",
               "--header", "Authorization:${ZABBIX_MCP_AUTH}"],
      "env": { "ZABBIX_MCP_AUTH": "Bearer zmcp_xxxxxxxx" }
    }
  }
}
```
(The token goes in `env` because spaces in `args` are mishandled on Windows.) Restart Claude Desktop.
Claude's *Connectors* UI (Settings → Connectors → Add custom connector) also accepts a remote URL; use it only if
your plan exposes a request-headers/bearer field, otherwise use the bridge above.

Add the skill: zip the `skills/zabbix-mcp` folder and upload it under Settings → Capabilities → Skills.

## Claude Code
```bash
claude mcp add --transport http zabbix https://example.com/zabbix-mcp/mcp \
  --header "Authorization: Bearer zmcp_xxxxxxxx"
mkdir -p ~/.claude/skills && cp -r skills/zabbix-mcp ~/.claude/skills/
```

## Cursor / generic `mcp.json` clients
```json
{ "mcpServers": { "zabbix": { "url": "https://example.com/zabbix-mcp/mcp",
                              "headers": { "Authorization": "Bearer zmcp_xxxxxxxx" } } } }
```

## ChatGPT desktop (and Codex)
* **Codex / ChatGPT desktop developer config** (`~/.codex/config.toml`) supports remote servers with a bearer env var:
  ```toml
  [mcp_servers.zabbix]
  url = "https://example.com/zabbix-mcp/mcp"
  bearer_token_env_var = "ZABBIX_MCP_TOKEN"     # export ZABBIX_MCP_TOKEN=zmcp_xxxxxxxx
  ```
  or `codex mcp add zabbix --url https://example.com/zabbix-mcp/mcp --bearer-token-env-var ZABBIX_MCP_TOKEN`.
* **ChatGPT web/desktop "Connectors" (developer mode)** only supports servers with OAuth or no auth, and cannot send a
  static bearer header. Options: use the Codex config above, or put an auth-aware front (e.g. a Traefik
  forward-auth/OAuth middleware) in front of the path. Do **not** expose the server without authentication.
* Agents skills (Codex): `mkdir -p ~/.agents/skills && cp -r skills/zabbix-mcp ~/.agents/skills/`.

## Hermes
`~/.hermes/config.yaml`:
```yaml
mcp_servers:
  zabbix:
    url: "https://example.com/zabbix-mcp/mcp"
    headers:
      Authorization: "Bearer zmcp_xxxxxxxx"
    timeout: 120
```
Skill: `cp -r skills/hermes/zabbix-mcp ~/.hermes/skills/devops/` (or `hermes skills install bucciamc-a11y/Zabbix-MCP/skills/hermes/zabbix-mcp`). Use `/zabbix-mcp` in chat.

## OpenClaw
```bash
openclaw mcp set zabbix '{"url":"https://example.com/zabbix-mcp/mcp","transport":"streamable-http","headers":{"Authorization":"Bearer zmcp_xxxxxxxx"}}'
```
or in `openclaw.json` under `mcp.servers.zabbix`. If your OpenClaw version does not forward custom headers to remote
MCP servers (known issue in some releases), send the token as `X-API-Key` where supported, or use the bridge:
`{"command":"npx","args":["-y","mcp-remote","<url>","--header","Authorization:${ZABBIX_MCP_AUTH}"],"env":{"ZABBIX_MCP_AUTH":"Bearer …"}}`.
Skill: `cp -r skills/openclaw/zabbix-mcp <workspace>/skills/` (highest precedence) or `~/.agents/skills/`.


## Least privilege tips
* Create one token per harness (admin UI → Tokens) so you can revoke individually.
* Keep `READ_ONLY=true` until you trust the workflow; the admin UI toggles it live.
* Keep `CONFIRM_WRITES=all` so every write needs the two-step confirmation.
