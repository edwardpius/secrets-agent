# Roadmap

Status lives only here. A box is ticked only when the spec's acceptance checks passed,
with the date and the measured result.

## Phase 0: Identity end to end
**Goal:** prove the agent acts as the signed-in user, before any secret is written.
**Success:** each test user's `whoami` shows their own email, groups and OpenBao policies;
a request without a user token is refused.

- [x] `apps/` KV v2 mount, `mcp-*` / UI policies for it, ECR repository (openbao-platform) — spec 001 · 2026-11-17: acceptance 4 passed with scoped tokens (15/15 checks: writers dev/staging only, admins prod, no overwrite, no data reads, readers search only)
- [x] MCP server skeleton: per-request JWT verification and `jwt-mcp` login, `whoami` tool — spec 001 · 2026-11-17: acceptance 1 passed live (admin → create dev/staging/prod; developer → create dev/staging + search; engineer → neither), acceptance 2 (no token refused before any OpenBao call), acceptance 3 (18 unit tests). Needed policy `mcp-self` (openbao-platform D-25 finding)
- [x] kagent agent + RemoteMCPServer with token passthrough, deployed by Argo CD (ai-hub) — spec 001 · 2026-11-17: Ready on Agent Substrate; tokenPassthrough forwards each signed-in user's Cognito ID token (FM-01 resolved: works)

## Phase 1: Create
**Goal:** create secrets with metadata, limited by Identity Center group.
**Success:** writers create in dev/staging but not prod, admins also in prod, readers
can't create; no value appears in any trace.

- [x] `create_secret` with metadata and generated or UI-entered values — spec 002 · 2026-11-17, live in kagent: EVAL-01 developer created dev (product1/api, product2/db) and staging (opgateway/legacy-user), prod refused; EVAL-02 admin created prod (artifactory/api), engineer refused; EVAL-03 existing path refused, nothing changed; EVAL-04 pasted password refused, nothing written; EVAL-05 agent asked for missing fields, then kagent's Approve gated the write (SA-004). The prod/engineer/paste/exists refusals came from the agent before any tool call (audit log: no OpenBao request); the server's own versions (403 with group, REQ-07, GUARD-03) are proven by the 74 unit tests. Two live fixes on the way: no empty metadata values (KV v2 400), admins' `apps/metadata/*` (openbao-platform D-25)

## Phase 2: Search
**Goal:** find secrets by key or by meaning, only among those the user may see.

- [ ] `search_secrets` (keyed filters + shortlist the agent's model ranks) — spec 003

## Phase 3: Sync to AWS Secrets Manager
**Goal:** a secret created with sync on appears in AWS within minutes, under `openbao/`.

- [ ] sync reconciler (ESO ExternalSecret + PushSecret per requested secret) — spec 004

## Phase 4: Evals and hardening
- [ ] Golden set: group limits, value-in-chat refusal, injection in metadata, wrong paths
- [ ] Phoenix review of real traces; error analysis
