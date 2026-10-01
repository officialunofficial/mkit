# WP-1.9a amendment 1: STC §5 carve-out scope

You are the WP-1.9a executor, continuing the stopped work.

**Where to work:**
- Worktree: `$REPO/.claude/worktrees/wp-1-9a`
- Branch: `mkit-server/wp-1-9a-begin-upload`
- Your partial commit: `188c9b0c`
- Your status file: `docs/plans/mkit-server/briefs/WP-1.9a-status.md`

**Before continuing,** read the original prompt again,
`<local path>`,
and the common rules file it names.

The escalation is valid. B.7 intended the carve-out to apply wherever STC §5 classifies `failed_precondition`, and it
didn't say so. The decisions below are **Section B, fixed**.

**Definition of done:** an open PR. Work until the PR is open.
- Flaky gates, lockfile refreshes and base conflicts are not stops: merge `origin/feat/mkit-server` and keep both
  sides.
- Never end with uncommitted work, unpushed work, or no PR.
- Delete `WP-1.9a-status.md` in the final diff, and move its content into the PR body.

---

## B.7 (amended): the STC §5 edits

Make B.7's three edits, plus these two:

1. **The intro paragraph before the table** ("Subject to the checks above, a v2 client maps `failed_precondition` on
   `BeginUpload`, … to a ticket failure …"). Append:
   > , except for the two cases the paragraph after the table excludes

   Keep the sentence grammatical.
2. **The paragraph after the table.** Replace "Except for the indexed delta-base case above," with:
   > Except for the indexed delta-base case and the `BeginUpload` open-ticket cap case (`too many open upload
   > tickets`) above,

   Right after that sentence, add:
   > On the cap case, the client fails the operation with a user-visible error and does not call `BeginUpload` again.

   Keep that sentence only once; drop it from the mapping paragraph if B.7's edit already put it there.

No other STC §5 text changes.

## C (added): testing the cap on the wire

How the wire baselines reach the open-ticket cap is your decision. For example:
- a dedicated in-process baseline configured with a small cap;
- the TestFaults clock-skew path.

Record your choice in the PR body. Don't add a TestFaults feature to baselines that don't already advertise one only to
make this test possible.

## Reminders from your status file (still required)

- Refresh `rust/Cargo.lock` and the affected app lockfiles (the 00-plan rule on `apps/vcs-worker/Cargo.lock`).
- Keep the new token golden entry when regenerating `uploads/MANIFEST`, and verify that the existing bytes are
  unchanged.
- Run all of the original prompt's gates, and put the evidence in the PR body.
