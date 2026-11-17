# 002 – Create a secret

**Roadmap:** Phase 1 · **Status:** see `product/roadmap.md` (never here)

## Intent

Create `apps/<product>/<service>/<environment>` with its metadata, as the signed-in user,
with values either generated in the MCP server or entered later in the OpenBao UI.

**Out of scope:** updating or deleting secrets; the AWS sync itself (004, which reads the
metadata written here).

## Requirements

- **REQ-01** WHEN asked to create a secret THE AGENT SHALL collect product, service,
  environment, description, team, JIRA ticket, the key names and how each value is set,
  and whether to sync to AWS Secrets Manager, asking for whatever is missing, and SHALL
  show the full request (path, metadata, AWS name) before calling the tool.
- **REQ-02** THE SERVER SHALL validate: product and service `^[a-z][a-z0-9-]{1,30}$`;
  environment one of `dev`, `staging`, `prod`; description 10-300 characters; team
  `^[a-z][a-z0-9-]{1,40}$`; JIRA ticket `^[A-Z][A-Z0-9]{1,9}-[0-9]{1,6}$`; 1-10 key names
  `^[A-Za-z_][A-Za-z0-9_]{0,63}$`; AWS name (if syncing) starting with `openbao/`, default
  `openbao/<product>/<service>/<environment>`.
- **REQ-03** WHEN valid THE SERVER SHALL write the data with `cas=0` (create-only) using
  the user's token, then write `custom_metadata`: `description`, `team`, `jira_ticket`,
  `created_by` (email from the verified token), `sync_aws` (`true`/`false`),
  `aws_secret_name`, `value_state` (`generated` / `pending-ui` per key), `schema` (`1`).
- **REQ-04** WHEN a key's value is `generate` THE SERVER SHALL create it with Python
  `secrets` (kinds: `password` 32 chars, `hex` 32 bytes, `uuid`), write it to OpenBao and
  return only the key name and kind, never the value.
- **REQ-05** WHEN a key's value is `ui` THE SERVER SHALL write the placeholder
  `PENDING-SET-IN-OPENBAO-UI` and return the OpenBao UI link to the path.
- **REQ-06** IF OpenBao answers 403 THEN THE AGENT SHALL say which group the user would need
  (from `whoami`'s rules: prod needs `openbao-admins`), and not retry.
- **REQ-07** IF the path already exists THEN THE SERVER SHALL refuse with "already exists,
  created by <created_by> for <jira_ticket>" and not change it.
- **REQ-08** IF a message contains what looks like a secret value (the user pastes one)
  THEN THE AGENT SHALL refuse to use it and point to the generate / UI options.

## Tools

### `create_secret`

| Field | Value |
|---|---|
| Purpose | Create one secret at `apps/<product>/<service>/<environment>` with metadata |
| Input schema | `product`, `service`, `environment`, `description`, `team`, `jira_ticket`, `keys: [{name, value: "generate"|"ui", kind: "password"|"hex"|"uuid"|null}]`, `sync_aws: bool`, `aws_secret_name: string|null`; no value field anywhere |
| Output | path, keys with how each was set, metadata written, UI link, AWS name |
| Side effects | writes OpenBao `apps/data/...` and `apps/metadata/...` |
| Risk tier | medium (a write; reversible only by an admin) |
| Idempotent | no (second call fails with REQ-07) |
| Errors | validation messages with a valid example; 403 with the needed group; exists |
| Boundary rule | ask: the agent confirms the full request with the user first (REQ-01) |
| Trifecta legs | private data ☑ (metadata) · untrusted content ☑ (user text) · outbound ☐ |

## Guardrails

- **GUARD-01** The input schema has no value field; a test fails if one is added.
- **GUARD-02** Generated values never appear in tool output, logs or spans (test scans all three).
- **GUARD-03** Credential-looking text in a message is refused (REQ-08): pattern check in the
  server on every string field (high-entropy tokens, `AKIA…`, PEM blocks, `password=`), so a
  value can't be smuggled through `description`.

## Acceptance

- **EVAL-01** writer creates dev and staging; writer is refused prod with the right group named.
- **EVAL-02** admin creates prod; reader is refused everywhere.
- **EVAL-03** existing path → REQ-07 message, data unchanged.
- **EVAL-04** user pastes a password → refused, nothing written (REQ-08, GUARD-03).
- **EVAL-05** missing fields → agent asks, then confirms the full request before writing.
- **Safety invariants:** no value in any trace, no write outside `apps/`, no write without a
  confirmation turn.
