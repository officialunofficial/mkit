# WP-2.13/2.14 E2 brief: private-clone end-to-end tests

## Purpose

Prove the grant CLI and the private-repository server work together end to end.

## A. Fixed

The committed briefs `WP-2.13-2.14.md` (E1/E2 sections) and `WP-2.9-2.11.md`; SPEC-WRITE-GRANTS §9.1–§9.3; R-152
and R-156.

## B. Decided

- **Style:** reuse the E1 harness from #1211. That means the real `mkit` binary against an in-process `mkit-server`
  (a dev-dependency only; `check-cli-baseline.sh` must still pass). Find it in `mkit-cli/tests/grant_e2e.rs`.
- **Required cases:**
  1. `mkit visibility set <remote> private` in **envelope mode** makes the repository private, and `public` restores
     it.
  2. The same in **statement mode** (`--statement`), with an Ed25519 owner. The server needs `GrantConfig` for
     statement mode (R-152), so configure it in the harness.
  3. On a private repository:
     - a clone with the **owner key** succeeds;
     - a clone by a grantee holding a **read grant** from the store (created with `mkit grant create --cap read`,
       then added with `mkit grant add`) succeeds;
     - a grantee holding a **write-only grant** gets `not_found`, reported as the CLI's not-found error;
     - an **anonymous** clone gets `not_found`.
  4. An `epoch bump` makes the read grant fail (`not_found`), and a reissued grant at the new epoch works.
  5. An older, unsubmitted `public` statement can't undo a later envelope flip to private (#1214's L1 rule).
- Each assertion checks the specific error text or kind, not just a non-zero exit.

## D. Escalate if

A case reveals a production bug needing more than about 100 lines, or a spec disagreement.

## Gates

- fmt and clippy for the touched crates.
- The new tests plus the existing `grant_e2e` and `grant_cli` tests.
- `scripts/check-cli-baseline.sh`.
