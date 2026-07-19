# Perseus Vault — client setup guide

One Vault, every agent. Point any MCP-capable client at the endpoint with a
bearer token:

- **Endpoint:** `https://vault.perseus.observer/message` (or your self-hosted URL)
- **Auth:** `Authorization: Bearer <PERSEUS_VAULT_MCP_TOKEN>`

---

## Hermes Agent

**MCP tools (simplest):**
```bash
hermes mcp add perseus-vault --url https://vault.perseus.observer/message
# prompts for the bearer token, stores it in ~/.hermes/.env
```

**Full memory provider** (prefetch injection, session distillation,
`perseus_remember/recall/forget` tools):
```bash
hermes plugins install Perseus-Computing-LLC/hermes-plugin-perseus-vault
hermes memory setup   # pick perseus-vault
```

## Claude Code

```bash
claude mcp add --transport http perseus-vault \
  https://vault.perseus.observer/message \
  --header "Authorization: Bearer $PERSEUS_VAULT_MCP_TOKEN"
```

## Claude Desktop

`claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "perseus-vault": {
      "type": "http",
      "url": "https://vault.perseus.observer/message",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

## Cursor

Settings → MCP → add server:
```json
{
  "mcpServers": {
    "perseus-vault": {
      "url": "https://vault.perseus.observer/message",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

## VS Code (Copilot)

`.vscode/mcp.json` or user settings:
```json
{
  "servers": {
    "perseus-vault": {
      "type": "http",
      "url": "https://vault.perseus.observer/message",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

## OpenAI Codex CLI

`~/.codex/config.toml`:
```toml
[mcp_servers.perseus-vault]
url = "https://vault.perseus.observer/message"
bearer_token_env_var = "PERSEUS_VAULT_MCP_TOKEN"
```

## Gemini CLI

`~/.gemini/settings.json`:
```json
{
  "mcpServers": {
    "perseus-vault": {
      "httpUrl": "https://vault.perseus.observer/message",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

## Docker MCP Toolkit

Catalog submission in progress (docker/mcp-registry#4482). Until merged:
**MCP Toolkit → Catalog → add custom server** with the endpoint + bearer header
above, or add to a [custom catalog](https://www.docker.com/blog/build-custom-mcp-catalog/).

## Official MCP Registry

Listed as `io.github.Perseus-Computing-LLC/perseus-vault` (self-hosted OCI
package). Registry-aware clients can discover it directly.

---

**Token:** never commit it. Every config above takes a placeholder; supply the
real value via env var or the client's secret store where supported.
