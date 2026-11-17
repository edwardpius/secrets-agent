# Spec-driven workflow

Same workflow as research-agent
([research-agent/WORKFLOW.md](../research-agent/WORKFLOW.md)); the rules that matter most:

1. **Status lives only in `product/roadmap.md`.** Specs never carry a status field.
2. **A box is ticked only when the feature's acceptance checks pass**, with the date and
   the measured result on the line.
3. **Requirements have stable IDs and EARS wording** (`REQ-01 WHEN … THE AGENT SHALL …`).
   Tests, evals, trace fields and commits refer to them.
4. **`[NEEDS CLARIFICATION: …]` blocks implementation.**
5. **Specs stay current**: behaviour changes update the spec in the same commit.

Loop: pick the next unchecked roadmap item → copy `specs/_template/` to `specs/NNN-name/`
→ specify → clarify → write the evals → plan → build with tests → run the acceptance
checks → tick the box → record decisions in `product/decisions.md` (append-only).
