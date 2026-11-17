# Tech stack

## Principles

1. **The user's rights, not the agent's** (openbao-platform D-19): the MCP server verifies
   the Cognito ID token on every request and exchanges it at OpenBao `auth/jwt-mcp` (role
   `mcp-user`) for a 5-minute batch token. Identity Center groups → `mcp/<group>` external
   groups → `mcp-*` policies. No service identity, no token cache across requests.
2. **Values stay out of the model**: generated in the MCP server with `secrets`, or entered
   by the user in the OpenBao UI. Tool inputs have no value field; outputs and spans are
   checked for values in tests.
3. **OpenBao enforces, the agent explains**: group limits are policies (e.g. writers have no
   path to `apps/data/+/+/prod`); a 403 becomes a clear message, never a retry with
   different rights.
4. **Create-only**: KV v2 writes with `cas=0`; no update or delete tools.
5. **Untrusted text is data**: descriptions, team names and tickets come from users and are
   returned to the model; they are never followed as instructions.

## Stack

| Piece | Choice |
|---|---|
| Agent | kagent declarative `Agent` (Go ADK runtime, required for `tokenPassthrough`), model from the hub's default ModelConfig (Bedrock, Claude Opus 4.6) |
| MCP server | Python 3.12, MCP Python SDK (Streamable HTTP, stateless), `uv`, `pytest` |
| Auth | PyJWT + Cognito JWKS; OpenBao HTTP API via `httpx` |
| Secrets | OpenBao KV v2 mount `apps/`, path `apps/<product>/<service>/<environment>` |
| Metadata | KV v2 `custom_metadata`: `description`, `team`, `jira_ticket`, `created_by`, `sync_aws`, `aws_secret_name`, `value_state` |
| Sync | reconciler (Python) writing ESO `ExternalSecret` + `PushSecret`; AWS names under `openbao/` |
| Observability | OpenTelemetry → hub Collector → Phoenix project `secrets-agent` (no values in spans) |
| Deploy | image in ECR `secrets-agent` (openbao-platform layer 05); manifests in ai-hub `deploy/`, Argo CD |

## Open decisions

| Decision | Trigger to revisit |
|---|---|
| Semantic search by the agent's model over a keyword shortlist (no embeddings, no external API) | Search quality falls short in evals → TypeSafe Jev reranking or Bedrock embeddings (data leaves AWS with Jev) |
| Model: hub default (Opus 4.6) | Cost per conversation in Phoenix → try a smaller model |
| Per-product team ownership (only the owning team creates) | When more than one team uses the hub |
