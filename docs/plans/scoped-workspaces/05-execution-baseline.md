# Scoped-workspaces execution baseline

Setup recorded 2026-09-16 for issue #1036. This note records execution
infrastructure only; it does not revise the approved product scope or authorize
PR01.

## Branch baseline

- Approved planning baseline: `9f7511d0852d57fa033572b3942f1d49af3e9bd6`.
- Initial feature baseline: `cace229e6ae464bdec25ed1b87f063db16e9d1a1`.
- Initial feature branch: `feat/scoped-workspaces`, created from that current
  `origin/main` commit without rewriting existing history.
- Every implementation PR targets `feat/scoped-workspaces`. Only the initial
  feature branch starts from `origin/main`.

The feature baseline is one commit ahead of the planning baseline:
`perf(core): roll delta::encode's block hash instead of recomputing it (#1034)`.
It changes delta implementation and benchmarks plus explanatory comments in
`transfer.rs`. No planning boundary, CI workflow, Cloud Build configuration,
repository instruction or invariant changed.

The only relevant citation drift is that the full-closure planning reference in
`rust/crates/mkit-core/src/transfer.rs` moved from line 664 to line 666
(`plan_pack_with` moved from line 655 to line 657). Its behavior is unchanged.
This is not material to the approved raw-only partial-update design, which does
not use delta or compressed entries. The nine approved planning documents are
carried unchanged from the planning worktree.

## CI setup and remaining operator action

GitHub validation workflows accept pull requests targeting both `main` and
`feat/scoped-workspaces`; their push filters remain main-only. Release,
deployment, publishing, scheduled and manual workflows are unchanged.
The initial setup PR cannot bootstrap target filters that are still main-only
in its base branch, so absent GitHub checks on that PR are missing coverage,
not successful runs. The widened filters take effect for subsequent feature-
target PR events after this setup lands.

The five live Cloud Build PR triggers were inspected read-only in project
`official-unofficial`, region `us-east4`. At setup time their base-branch regex
is still `^main$`, so their checks are missing—not passing—on feature-target
pull requests until an authorized operator runs the five-trigger update in
`cloudbuild/README.md`. The `*-main` push triggers and `mkit-coverage-main`
must remain unchanged.

Separate pre-existing Cloud Build drift was observed but not folded into this
setup: live codegen trigger filters omit `buf.yaml` and
`scripts/regen-transport-proto.sh` even though the checked-in setup includes
them, and `cloudbuild/codegen.yaml` performs its secondary Buf breaking
comparison against `main`. The unconditional GitHub `CI: Buf` workflow remains
the authoritative PR-base comparison. Resolving live filter drift requires
separate owner authorization.

No cloud resources, permissions, branch protection, release configuration or
deployment configuration were changed during setup.
