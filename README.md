# Perseus Vault memory provider for Hermes Agent

Connects [Hermes Agent](https://github.com/NousResearch/hermes-agent) to a
remote **Perseus Vault** MCP server as its external memory provider.

One Vault can be shared by many Hermes instances (workstations, cloud agents,
cron workers) so durable context — facts, decisions, corrections, ops notes —
follows you between machines and sessions.

## Features

- **Prefetch recall** — before each turn, relevant Vault memories
  (`recall_when` triggers + keyword recall) are injected as context.
- **Session distillation** — at session end, the transcript is distilled into
  durable Vault entities (primary sessions only; cron/subagent contexts are
  excluded so they don't pollute shared memory).
- **Built-in memory mirroring** — writes to Hermes's built-in `MEMORY.md` /
  `USER.md` are mirrored into the Vault.
- **Explicit tools** — `perseus_remember`, `perseus_recall`, `perseus_forget`.
- **Resilient transport** — one persistent streamable-HTTP MCP session on a
  background thread; reconnects transparently on transport errors.

## Requirements

- A reachable Perseus Vault MCP endpoint and a bearer token for it.
  (Run your own [Perseus Vault](https://github.com/Perseus-Computing-LLC/perseus-vault) server or
  use a hosted Vault.)
- The `mcp` Python package — installed automatically during
  `hermes memory setup` (declared in `plugin.yaml`).

## Install

```bash
hermes plugins install Perseus-Computing-LLC/hermes-plugin-perseus-vault
```

## Setup

```bash
# Token in .env (Hermes prompts for it during setup, or add it yourself)
hermes memory setup     # pick "perseus-vault", confirm endpoint + workspace
hermes memory status    # should show perseus-vault ← active, "available ✓"
```

Start a new session after setup — providers initialize at agent startup.

## Configuration

Resolution order: environment variables → `config.yaml` `memory.perseus-vault:`
→ defaults.

| Env var | Purpose | Default |
|---|---|---|
| `PERSEUS_VAULT_MCP_TOKEN` | Bearer token (**required**) | — |
| `PERSEUS_VAULT_URL` | MCP endpoint URL | `https://vault.perseus.observer/message` |
| `PERSEUS_VAULT_WORKSPACE` | Workspace scope hash | global / unscoped |

`config.yaml` equivalent:

```yaml
memory:
  provider: perseus-vault
  perseus-vault:
    url: https://vault.perseus.observer/message
    workspace_hash: ""
```

## Security

- The token is read from the environment or `.env` — never hardcode it in
  `config.yaml` or the plugin directory.
- Never store secret values in the Vault itself.

## Other clients

Claude Code/Desktop, Cursor, VS Code, Codex CLI, Gemini CLI, Docker MCP
Toolkit: see **[docs/clients.md](docs/clients.md)** for copy-paste configs.

## License

MIT — see [LICENSE](LICENSE).
