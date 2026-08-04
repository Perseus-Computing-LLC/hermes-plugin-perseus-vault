# Perseus Vault memory provider for Hermes Agent

Connects [Hermes Agent](https://github.com/NousResearch/hermes-agent) to a
remote **Perseus Vault** MCP server as its external memory provider.

One Vault can be shared by many Hermes instances (workstations, cloud agents,
cron workers) so durable context — facts, decisions, corrections, ops notes —
follows you between machines and sessions.

## Features

- **Prefetch recall** — before each turn, relevant Vault memories
  (`recall_when` triggers + keyword recall) are injected as context.
- **Lifecycle-safe prefetch** — warmed context is bound in memory to its
  generation, session, workspace, query, and source identities. Forget/removal,
  session changes, provider initialization, shutdown, and in-flight invalidation
  discard stale warm results before they can be consumed.
- **Session distillation** — at session end, the transcript is distilled into
  durable Vault entities (primary sessions only; cron/subagent contexts are
  excluded so they don't pollute shared memory).
- **Built-in memory mirroring** — writes to Hermes's built-in `MEMORY.md` /
  `USER.md` are mirrored into the Vault.
- **Explicit tools** — `perseus_remember`, `perseus_recall`, `perseus_forget`.
- **Resilient transport** — one persistent streamable-HTTP MCP session on a
  background thread; reconnects transparently on transport errors.
- **Authorized Action Receipts (optional)** — in shadow or enforcement mode,
  Hermes tool calls are checked against a Vault authority manifest before
  side effects run. The plugin records hash-only intent/outcome evidence,
  Vault-backed approvals, and short-lived execution leases.
- **Resource-bound constraints** — opted-in capabilities bind the concrete
  repository, deployment environment, destination, or payment merchant/amount/
  currency/expiry to the intent and approval. Retargeting and bound expansion
  fail closed before execution. See `docs/resource-constraints-contract.md`.

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

### Freshness boundary

A successful `perseus_forget` or built-in-memory removal prevents the forgotten
source from being returned by future provider prefetch. The provider cannot
retract tokens already delivered to a model; the host must cancel or recover an
already-composed turn according to its normal interruption policy.

The lifecycle capability surface reports addressed forget and prefetch
invalidation as supported. Semantic rejection, supersession, and derived
artifact invalidation are explicitly reported as unsupported until the mounted
Vault/provider contract supplies those operations.

## Configuration

Resolution order: environment variables → `config.yaml` `memory.perseus-vault:`
→ defaults.

| Env var | Purpose | Default |
|---|---|---|
| `PERSEUS_VAULT_MCP_TOKEN` | Bearer token (**required**) | — |
| `PERSEUS_VAULT_URL` | MCP endpoint URL | `https://vault.perseus.observer/message` |
| `PERSEUS_VAULT_WORKSPACE` | Workspace scope hash | global / unscoped |
| `PERSEUS_VAULT_AUTHORITY_MODE` | AAR policy: `off`, `shadow`, or fail-closed `enforce` | `off` |
| `PERSEUS_VAULT_AGENT_ID` | Registered Vault agent identity used by authority manifests | — |
| `PERSEUS_VAULT_AUTHORITY_SCOPE` | Trusted scope anchor, e.g. `github:Org/repo` (auto-detected from `origin` when possible) | — |
| `PERSEUS_VAULT_AUTHORITY_EXTERNAL_REF` | External system reference checked against manifest prefixes | scope anchor |
| `PERSEUS_VAULT_APPROVER_PRINCIPAL` | Vault principal allowed to record approval events | — |

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
- AAR sends only trusted identifiers and SHA-256 digests to durable action
  records. Raw commands, tool arguments, results, credentials, and client
  metadata are never written as evidence.
- Start with `PERSEUS_VAULT_AUTHORITY_MODE=shadow`. Switch to `enforce` only
  after creating an active authority manifest for the configured agent and
  workspace. Enforcement blocks unknown tools and any missing, revoked,
  expired, capability-mismatched, or scope-mismatched authority.

## Other clients

Claude Code/Desktop, Cursor, VS Code, Codex CLI, Gemini CLI, Docker MCP
Toolkit: see **[docs/clients.md](docs/clients.md)** for copy-paste configs.

## License

MIT — see [LICENSE](LICENSE).
