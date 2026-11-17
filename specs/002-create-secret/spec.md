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
  show the full request (path, metadata, AWS name) before calling the tool. The call
  itself waits for the user's Approve in the kagent UI (`requireApproval` on the
  `create_secret` binding), so no write happens without a confirmation turn even if the
  model skips it.
- **REQ-02** THE SERVER SHALL validate: product and service `^[a-z][a-z0-9-]{1,30}$`;
  environment one of `dev`, `staging`, `prod`; description one printable line of 10-300 characters (KV v2 refuses unprintable metadata); team
  `^[a-z][a-z0-9-]{1,40}$`; JIRA ticket `^[A-Z][A-Z0-9]{1,9}-[0-9]{1,6}$`; 1-10 key names
  `^[A-Za-z_][A-Za-z0-9_]{0,63}$`, no duplicates; AWS name (if syncing) starting with
  `openbao/`, no `..`, default `openbao/<product>/<service>/<environment>`; no unknown
  fields. These checks and GUARD-03 run before the OpenBao login: an invalid request makes
  no OpenBao call. Errors name every bad field with a valid example.
- **REQ-03** WHEN valid THE SERVER SHALL first write the data with `cas=0` (a true create:
  the policies grant no `update` on data, so nothing existing can be overwritten) using the
  user's token, then write `custom_metadata` (an update of the metadata the data write
  created; SA-003): `description`, `team`, `jira_ticket`,
  `created_by` (email from the verified token, never an argument), `sync_aws`
  (`true`/`false`), `aws_secret_name` (only when syncing: KV v2 refuses empty metadata values), `schema` (`1`), and one
  `key.<NAME>` entry per key: `generated:<kind>` or `pending-ui` (one entry per key because
  OpenBao caps each metadata value at 512 bytes). If the metadata write fails after the
  data write, the server says the secret exists without metadata and not to create it
  again.
- **REQ-04** WHEN a key's `source` is `generate` THE SERVER SHALL create it with Python
  `secrets` (kinds: `password` 32 chars with lower, upper and digit (default), `hex` 32
  bytes, `uuid` v4), write it to OpenBao and
  return only the key name and kind, never the value.
- **REQ-05** WHEN a key's `source` is `ui` THE SERVER SHALL write the placeholder
  `PENDING-SET-IN-OPENBAO-UI` and return the OpenBao UI links to the path
  (`/ui/vault/secrets/apps/show/<path>`, and `/edit/<path>` to set the values).
- **REQ-06** IF OpenBao answers 403 THEN THE SERVER SHALL name the group needed (prod:
  `openbao-admins`; dev/staging: `openbao-secrets-writers` or `openbao-admins`) and THE
  AGENT SHALL pass it on and not retry.
- **REQ-07** IF the path already exists (checked on its metadata before writing; `cas=0`
  and the create-only policy also refuse it) THEN THE SERVER SHALL refuse with "already
  exists, created by <created_by> for <jira_ticket>" and not change it.
- **REQ-08** IF a message contains what looks like a secret value (the user pastes one)
  THEN THE AGENT SHALL refuse to use it and point to the generate / UI options.

## Tools

### `create_secret`

| Field | Value |
|---|---|
| Purpose | Create one secret at `apps/<product>/<service>/<environment>` with metadata |
| Input schema | `product`, `service`, `environment`, `description`, `team`, `jira_ticket`, `keys: [{name, source: "generate"|"ui", kind: "password"|"hex"|"uuid"|null}]`, `sync_aws: bool`, `aws_secret_name: string|null`; no value field anywhere, `additionalProperties: false` on every object |
| Output | path, keys with how each was set, metadata written, UI link, AWS name |
| Side effects | writes OpenBao `apps/data/...` and `apps/metadata/...` |
| Risk tier | medium (a write; reversible only by an admin) |
| Idempotent | no (second call fails with REQ-07) |
| Errors | validation messages with a valid example; 403 with the needed group; exists |
| Boundary rule | ask: the agent confirms the full request first, and kagent's `requireApproval` holds the call until the user approves it (REQ-01) |
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
