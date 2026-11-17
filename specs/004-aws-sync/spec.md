# 004 – Sync to AWS Secrets Manager

**Roadmap:** Phase 3 · **Status:** see `product/roadmap.md` (never here)

## Intent

A secret created with `sync_aws=true` appears in AWS Secrets Manager under its
`aws_secret_name` within minutes, kept in sync one way (OpenBao is the source of truth),
without giving the agent any Kubernetes or AWS rights.

**Out of scope:** the existing Terraform-driven sync of `kv/sync/*` (openbao-platform layer
60) stays as it is.

## Requirements

- **REQ-01** THE RECONCILER SHALL, every minute, list `apps/` metadata with its own OpenBao
  role (`apps-sync`, metadata read/list only) and find entries with `sync_aws = true`.
- **REQ-02** FOR each such entry THE RECONCILER SHALL ensure an ESO `ExternalSecret` (reads
  `apps/data/<path>` through a SecretStore whose role may read only paths whose metadata
  says sync) and a `PushSecret` to Secrets Manager under `aws_secret_name`, in namespace
  `secrets-sync`, and remove both when the flag is gone.
- **REQ-03** IF `aws_secret_name` is outside `openbao/` or already used by another secret
  THEN THE RECONCILER SHALL skip it and record the reason in the metadata
  (`sync_status`).
- **REQ-04** THE RECONCILER SHALL write `sync_status` (`pending`, `synced <time>`,
  `error: <reason>`) so `search_secrets` can show it.

## Resolved points (user, 2026-11-17)

- **Read role scope:** ESO's SecretStore in `secrets-sync` uses an OpenBao role that may read
  **all of `apps/data`** (OpenBao policies can't depend on metadata). Accepted: the role is
  bound only to ESO's ServiceAccount in `secrets-sync`, and the reconciler creates
  ExternalSecrets only for entries with `sync_aws = true`. Recorded as SA-002.
- **Placeholders:** a secret is synced only when **every value is set**:
  - **REQ-05** IF any key's `value_state` is `pending-ui` THEN THE RECONCILER SHALL NOT sync
    it and SHALL set `sync_status = waiting: values not set in OpenBao UI`.
  - **REQ-06** WHEN the placeholder `PENDING-SET-IN-OPENBAO-UI` is gone from every key
    THE RECONCILER SHALL mark those keys `value_state = set` and start the sync. (The
    reconciler compares the stored value with the placeholder; ESO's role reads data, the
    reconciler's own role only checks equality via a hash, never logs or returns values.)

## Acceptance

- **EVAL-01** create with sync on → AWS secret exists with the same keys within 3 minutes.
- **EVAL-02** value changed in the UI → AWS copy updated within the ESO refresh interval.
- **EVAL-03** name outside `openbao/` → skipped, `sync_status` explains.
- **EVAL-04** created with a `ui` key → not in AWS, `sync_status = waiting…`; after the value
  is set in the UI → synced within 3 minutes.
