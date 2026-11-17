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

## Open points

- [NEEDS CLARIFICATION: ESO reads data with a role that can read **all** of `apps/data`,
  since OpenBao policies can't depend on metadata. Accept that (the role is used only by
  ESO in `secrets-sync`), or have the reconciler copy synced secrets to `kv/sync/apps/...`
  and reuse layer 60's narrower path?]
- [NEEDS CLARIFICATION: values still `PENDING-SET-IN-OPENBAO-UI` — sync the placeholder, or
  wait until every key is set (`value_state` has no `pending-ui`)?]

## Acceptance

- **EVAL-01** create with sync on → AWS secret exists with the same keys within 3 minutes.
- **EVAL-02** value changed in the UI → AWS copy updated within the ESO refresh interval.
- **EVAL-03** name outside `openbao/` → skipped, `sync_status` explains.
