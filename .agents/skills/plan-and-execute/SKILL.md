---
name: plan-and-execute
description: Research, plan, implement, and verify multi-file mkit changes or specification and architecture evaluations. Use for coordinated investigation or an explicit plan-and-execute request.
---

# Plan and execute

Complete the requested work through research, planning, execution, and verification.
Read any applicable `AGENTS.md` and `CLAUDE.md`, then `CONTRIBUTING.md` and
`docs/INVARIANTS.md`. Paths below are relative to the repository root.
For planning-only requests, stop after the plan. For evaluations, the deliverable
is an evidence-backed report and remediation plan; do not silently implement
protocol or product changes. Keep the phases brief for small changes.

## Research

Inspect the current diff before editing and preserve unrelated work.
Trace affected callers, contracts, configuration, and tests in current code.
For spec work, read `docs/specs/README.md`, `SPEC-CONVENTIONS.md`, and the
relevant specifications. Separate normative requirements from implementation
behavior, acknowledged limitations, and proposed designs.
Verify external API claims against official documentation and installed versions
when the task depends on those claims.

Use native subagents for useful bounded, independent research. Give each agent
the task, relevant paths, boundaries, and required file/line evidence. Research
agents do not edit files. Use configured models unless the user specifies otherwise.
If delegation is unavailable, do the same research sequentially.

## Plan

Synthesize a concrete plan naming deliverables, files, behavior changes, and
verification commands. Resolve disagreements against code and authoritative sources.
For evaluations, prioritize concrete failure scenarios, missing contracts, and
cross-spec contradictions. State impact, evidence, confidence, a proposed decision,
and a meaningful conformance or regression test. Mark open questions explicitly.
Do not describe an unexecuted scenario as a reproduced bug.

For implementation, identify regression coverage and expected failures before
editing. Document new cross-cutting invariants in `docs/INVARIANTS.md` with
Always/Because/If-violated and actual enforcement status.
Resolve routine ambiguity from context; ask only for material missing decisions.
A completed plan is a handoff within the task, not an approval gate for authorized work.

## Execute

Execute within the user's scope and adjust the plan when better evidence emerges.
For behavior fixes, follow `CONTRIBUTING.md`'s test-first requirement: confirm
the regression fails before the fix, implement until it passes, then refactor.
Preserve security, serialization, and public API contracts unless changing them
is part of the request. Never weaken assertions to make checks pass.
Delegate implementation only with separate file ownership; integrate dependent
results before editing shared files.

## Verify and finish

Choose checks from the current `justfile`, manifests, and relevant CI workflows:
- Rust: focused crate/feature regression tests and applicable formatting/lint
  checks; use `just ci-macos` or `just ci-linux` when full workspace parity is needed.
- Separate Workers, signers, and web packages: inspect their own manifests and
  CI commands rather than assuming they belong to the root Rust workspace.
- Prose and skills only: inspect the diff, links, evidence, instruction consistency,
  and available skill validation. Skip application suites.

For substantial work, delegate an independent read-only review while completing
validation. Supply the final diff/report, invariants, and check evidence; request
actionable defects, unsupported conclusions, scope drift, and missing verification.
Fix confirmed issues and rerun only affected checks. If delegation is unavailable,
review locally. Distinguish passing checks from unrun checks and design inferences
from demonstrated failures. Report completed work and any exact blocker.
Commit, push, publish issues/PRs, merge, or deploy only when authorized by the user.
