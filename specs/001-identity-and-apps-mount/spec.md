# 001 – Identity end to end, and the `apps/` mount

**Roadmap:** Phase 0 · **Status:** see `product/roadmap.md` (never here)

## Intent

Prove that a request made in the kagent UI reaches the MCP server with **the signed-in
user's** Cognito ID token, and that the server turns it into that user's OpenBao token,
before any tool writes a secret. Also create the `apps/` mount and its policies, so specs
002-004 only add tools. Serves the mission's "never act with rights of its own".

**Out of scope:** creating or searching secrets (002, 003), AWS sync (004).

## Requirements

- **REQ-01** WHEN the MCP server receives a request THE SERVER SHALL read the bearer token
  from its `Authorization` header, verify its signature against the Cognito user pool's
  JWKS, and check `iss` (the pool), `aud` (the kagent client ID), `token_use = id` and `exp`.
- **REQ-02** IF the header is missing or the token fails REQ-01 THEN THE SERVER SHALL refuse
  the call with an error naming the reason (missing, expired, wrong audience, bad signature),
  and make no OpenBao call.
- **REQ-03** WHEN the token is valid THE SERVER SHALL log in at OpenBao
  `auth/jwt-mcp/login` (role `mcp-user`) with that token and use the returned token for
  this request only, never caching it across requests (one MCP session is shared by all
  users, D-19).
- **REQ-04** WHEN `whoami` is called THE SERVER SHALL return the user's email, their
  Identity Center groups (`cognito:groups`), the OpenBao policies on their token and what
  they may do under `apps/` (create in dev/staging, create in prod, search), and nothing else.
- **REQ-05** THE PLATFORM SHALL provide a KV v2 mount `apps/` where, through `jwt-mcp`:
  `openbao-secrets-writers` may create (not update) `apps/data/<p>/<s>/dev|staging` and
  write custom metadata there; `openbao-admins` may also create in `prod`; writers, readers
  and admins may list and read metadata under `apps/`; nobody may read secret data through
  `jwt-mcp`.
- **REQ-06** THE PLATFORM SHALL give the same groups matching rights in the OpenBao UI
  (`oidc` login), plus `update` on data for writers (dev/staging) and admins (all), so a
  placeholder value can be filled in there.
- **REQ-07** THE PLATFORM SHALL provide an ECR repository `secrets-agent` (persistent,
  layer 05) and an OpenTelemetry project `secrets-agent` in Phoenix.

## Tools

### `whoami`

| Field | Value |
|---|---|
| Purpose | Show who the agent is acting as and what they may do under `apps/` |
| Use when / not when | The user asks who they are / what they may create; before explaining a denial |
| Input schema | `{}` (`additionalProperties: false`) |
| Output | `email`, `groups[]`, `openbao_policies[]`, `may_create: {dev, staging, prod}`, `may_search` |
| Side effects | reads OpenBao `auth/token/lookup-self` and `sys/capabilities-self` |
| Risk tier | low |
| Idempotent | yes |
| Reversible | n/a |
| Errors | `not signed in` / `token expired, reload the page` / `OpenBao refused the login: <reason>` |
| Boundary rule | allow |
| Trifecta legs | private data ☐ · untrusted content ☐ · outbound ☐ |

## Guardrails

- **GUARD-01** No service identity: the server has no OpenBao token of its own and no
  Kubernetes auth role; a test fails if any code path calls OpenBao without a user token.
- **GUARD-02** Tokens never appear in tool output, logs or spans (the user's ID token, the
  OpenBao token).

## Memory and context

n/a: the server is stateless; kagent keeps the conversation.

## Budgets

| | Limit | Kind |
|---|---|---|
| OpenBao calls per tool call | 3 | hard |
| p95 latency of `whoami` | 1 s | soft |

## Human in the loop

n/a: read-only.

## Observability

Span per tool call (`TOOL`), attributes `user.id` (hashed Cognito `sub`), `mcp.tool`,
`openbao.status`; parented on the incoming `traceparent`. Phoenix project `secrets-agent`.

## Failure modes

| FM | Failure | Control | Proving test or eval |
|---|---|---|---|
| FM-01 | kagent doesn't forward the user's token to the MCP server | spike first (acceptance 1); stop and redesign if it fails | live check |
| FM-02 | A token from another app or an expired one is accepted | REQ-01 checks | unit tests with forged/expired/wrong-aud tokens |
| FM-03 | One user's OpenBao token used for another user's call | REQ-03 per-request login, no cache | unit test: two interleaved users |

## Acceptance

1. **Live:** signed in as `obao-test-admin`, `obao-test-developer` and `obao-test-engineer`,
   "who am I?" returns each user's own email and groups, and policies that match:
   admin → create dev/staging/prod; developer (writers + readers) → create dev/staging,
   search; engineer → no create, no search.
2. **Live:** a call to the MCP server without `Authorization` (from a pod in `agents`) is
   refused with REQ-02's message and no OpenBao login appears in the audit log.
3. **Unit:** REQ-01/02 (forged, expired, wrong audience, wrong `token_use`), REQ-03 (two
   interleaved users), GUARD-01/02 pass offline.
4. **Platform:** with `bao` as each test user: writers can't create in `prod`, can't
   overwrite an existing secret, and can't read data through `jwt-mcp`.
