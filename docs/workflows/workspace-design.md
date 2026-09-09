# Workspace interaction verification

Use `apps/web/scripts/preview-workspace.mjs` against a built web preview on port 4173. The fixture listens on 4180, provides an owner session and a populated project, and rejects writes. Open `/create?id=dddddddddddddddddddddddddddddddd`.

1. Inspect Files at 1440px and 390px in both themes. Select files, search, and create a draft. The explorer indicates edits and the agent asks you to save them first.
2. Switch to Changes and History, then back. Edits remain. Browser Back/Forward also retains session-scoped drafts. Reload warns when drafts exist; drafts are never persisted to storage.
3. Open Save version. Verify the list includes both browser drafts and working files. A message is required. Cancel and Escape preserve edits and return focus.
4. Inspect History: actor, timestamp, shortened hash and full-hash copy, parent comparison, and comparison with current files. On mobile, select another version using the compact selector.
5. Open restore and remix confirmations. Restore explains replacement and creation of a new child version; remix identifies the saved source. Cancel without writing.
6. Verify Terminal starts collapsed, and the agent is disabled while browser drafts exist. Sign out with drafts opens a discard confirmation; cancel preserves edits.

Run `bunx vitest run`, `bunx tsc --noEmit`, `bun run lint`, and `bun run build` in `apps/web`. Run `npm test` and `npm run typecheck` in `apps/workspace-worker`. Integration tests exercise actual signed batch writes, atomic rejection, file preconditions and terminal capture. The read-only visual fixture does not prove a production write.
