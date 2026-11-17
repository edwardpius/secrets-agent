# Roadmap

Status lives only here. A box is ticked only when the spec's acceptance checks passed,
with the date and the measured result.

## Phase 0: Identity end to end
**Goal:** prove the agent acts as the signed-in user, before any secret is written.
**Success:** each test user's `whoami` shows their own email, groups and OpenBao policies;
a request without a user token is refused.

- [ ] `apps/` KV v2 mount, `mcp-*` / UI policies for it, ECR repository (openbao-platform) — spec 001
- [ ] MCP server skeleton: per-request JWT verification and `jwt-mcp` login, `whoami` tool — spec 001
- [ ] kagent agent + RemoteMCPServer with token passthrough, deployed by Argo CD (ai-hub) — spec 001

## Phase 1: Create
**Goal:** create secrets with metadata, limited by Identity Center group.
**Success:** writers create in dev/staging but not prod, admins also in prod, readers
can't create; no value appears in any trace.

- [ ] `create_secret` with metadata and generated or UI-entered values — spec 002

## Phase 2: Search
**Goal:** find secrets by key or by meaning, only among those the user may see.

- [ ] `search_secrets` (keyed filters + shortlist the agent's model ranks) — spec 003

## Phase 3: Sync to AWS Secrets Manager
**Goal:** a secret created with sync on appears in AWS within minutes, under `openbao/`.

- [ ] sync reconciler (ESO ExternalSecret + PushSecret per requested secret) — spec 004

## Phase 4: Evals and hardening
- [ ] Golden set: group limits, value-in-chat refusal, injection in metadata, wrong paths
- [ ] Phoenix review of real traces; error analysis
