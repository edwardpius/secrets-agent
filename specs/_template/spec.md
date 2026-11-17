# NNN – Feature name

**Roadmap:** Phase N / item name · **Status:** see `product/roadmap.md` (never here)

Size each section to the feature. For a read-only tool, many sections are one line. Delete a
section only if it truly doesn't apply, and write "n/a: reason" instead of leaving it blank.

## Intent

One paragraph: what this feature does and why, and how it serves `product/mission.md`.

**Out of scope:** what this feature deliberately doesn't do.

## Requirements

EARS wording, stable IDs. Every ID must be covered by a test or an eval case.

- **REQ-01** WHEN <event> THE AGENT SHALL <behaviour>.
- **REQ-02** IF <unwanted condition> THEN THE AGENT SHALL <behaviour>.
- [NEEDS CLARIFICATION: …]

## Tools

One block per tool this feature adds or changes. Aim for few, well-chosen tools.

### `tool_name`

| Field | Value |
|---|---|
| Purpose | What it does, written for a new hire |
| Use when / not when | |
| Input schema | Strict: `additionalProperties: false`, every field required (optional = nullable) |
| Output | Human-readable fields, not opaque IDs. Token cap: N. Concise/detailed option? |
| Side effects | none · reads X · writes Y · sends Z |
| Risk tier | low (read-only) · medium (reversible write) · high (irreversible / outbound) |
| Idempotent | yes / no |
| Reversible | yes / no / how |
| Errors | Specific and actionable, with a valid example input |
| Boundary rule | allow · ask (approval) · deny, with the rule name |
| Trifecta legs | private data ☐ · untrusted content ☐ · outbound ☐ |

## Guardrails

How this feature's tools fit the principles in `product/tech-stack.md`. Only list what's
new or specific to this feature.

- **GUARD-01** …

## Memory and context

- What this feature writes to the Store, and to which destination
- What the Distiller does with this feature's tool results
- Memory read back is untrusted: how that's handled here

## Budgets

| | Limit | Kind |
|---|---|---|
| Max turns | N | hard: stop reason `max_turns` |
| Max USD per run | $N | hard: stop reason `max_usd` |
| Tool output | N tokens | hard: truncated by the Distiller |
| Median cost per task | $N | soft: measured in evals |
| p95 latency | N s | soft: measured in evals |

All numbers are placeholders until the first eval runs give baselines.

## Human in the loop

| Risk tier | Behaviour |
|---|---|
| low | runs |
| medium | dry_run by default; real run needs a flag |
| high | pauses for approval; the approver sees the real arguments and the dry-run output |

**On deny:** … **On timeout:** … **Resume rule:** never repeat a non-idempotent action.
**Escalate when:** repeated failure on the same step, or any high-risk action.

## Observability

New trace fields or spans this feature adds. Content capture stays off unless stated.

## Failure modes

| FM | Failure | Control | Proving test or eval |
|---|---|---|---|
| FM-01 | Loops on a denied call | boundary escalation after `max_repeats` | eval: denial-loop case |
| FM-02 | Claims success without doing it | outcome graded on environment state | eval: outcome check |
| FM-03 | Follows instructions injected in a tool result | trifecta: no outbound after untrusted input | eval: injection case |

## Acceptance

Golden cases live in `./evals/`. These are hypotheses until error analysis on real traces
revises them.

- **EVAL-01** … (covers REQ-01)
- **Threshold:** pass^3 ≥ N of M cases (or pass@k for capability work)
- **Safety invariants (0 violations on every trajectory):**
  - no high-risk call without a prior approval event
  - no call to an undeclared tool
  - no outbound call after untrusted input in the same session
  - no more than N identical consecutive calls
