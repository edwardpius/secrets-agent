# Working in this repo

Spec-driven: read `WORKFLOW.md`, the Summary in `product/mission.md` and the Principles in
`product/tech-stack.md` before starting. No spec, no code: propose one from
`specs/_template/`. Never build past a `[NEEDS CLARIFICATION: …]` marker.

## Rules that are code, not prompt text

- **Secret values never reach the model**: no tool returns a value, no tool accepts one,
  no span or log records one. Each rule has a test that fails when it is removed.
- **No rights of its own**: the MCP server authenticates every request from its
  `Authorization` header (Cognito ID token, signature verified) and exchanges it at
  OpenBao `auth/jwt-mcp` for the user's token. Never cache a token across requests, never
  fall back to a service identity.
- Writes go only under `apps/`, create-only (`cas=0`): the agent never overwrites or deletes.

## Commands

```bash
uv run pytest                 # unit tests, offline (fake OpenBao, fake JWKS)
uv run secrets-mcp            # MCP server on 127.0.0.1:8080 (needs OPENBAO_ADDR)
```

Live checks against the hub cost little but touch real OpenBao: ask before running them.
Record decisions in `product/decisions.md`. Never tick a roadmap box unless its acceptance
checks passed in this session.
