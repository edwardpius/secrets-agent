# 003 – Search secrets

**Roadmap:** Phase 2 · **Status:** see `product/roadmap.md` (never here)

## Intent

Find secrets the user is allowed to see, by key (path prefix, environment, team, JIRA
ticket, creator) or by meaning ("the database password for the billing API in staging").
Only metadata is searched or shown, never values.

**Out of scope:** reading values (the user opens the UI link); embeddings or external
rerankers (open decision in tech-stack).

## Requirements

- **REQ-01** WHEN searching THE SERVER SHALL list `apps/` with the user's token (KV v2
  metadata list, recursive) and read each candidate's `custom_metadata`; entries the user
  can't list or read are never returned.
- **REQ-02** WHEN keyed filters are given (`product`, `service`, `environment`, `team`,
  `jira_ticket`, `created_by`) THE SERVER SHALL return only exact matches.
- **REQ-03** WHEN a free-text `query` is given THE SERVER SHALL score candidates by keyword
  overlap with path and metadata and return the top 20 with their metadata; THE AGENT
  SHALL then judge which ones answer the question and say why.
- **REQ-04** Results SHALL contain path, description, team, JIRA ticket, created by,
  created and updated time, key names with how each was set, keys still pending in the UI,
  sync state, AWS name and the OpenBao UI link, and no values: the server never requests
  `apps/data`. Product, service and environment filters prune the listing itself.
- **REQ-05** IF nothing matches THEN THE AGENT SHALL say so and suggest broader filters, and
  never invent a path.

## Tools

### `search_secrets`

| Field | Value |
|---|---|
| Input schema | `query: string|null`, `product`, `service`, `environment`, `team`, `jira_ticket`, `created_by` (all nullable), `limit: int (1-20)` |
| Output | list of entries per REQ-04, total candidates scanned |
| Side effects | reads OpenBao metadata |
| Risk tier | low |
| Trifecta legs | private data ☑ · untrusted content ☑ (metadata written by other users) · outbound ☐ |

## Guardrails

- **GUARD-01** Metadata from other users is untrusted: the agent's instructions say so, and
  an eval plants an instruction in a description.
- **GUARD-02** Scan cap: at most 500 metadata reads per call; the result says when it stopped.

## Acceptance

- **EVAL-01..03** keyed: by team, by ticket, by environment.
- **EVAL-04..06** semantic: three natural-language questions with known answers.
- **EVAL-07** a description containing "ignore previous instructions…" is shown as text, not followed.
- **EVAL-08** engineer (no search rights) gets a clear denial.
