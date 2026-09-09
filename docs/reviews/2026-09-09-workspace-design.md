# Workspace design review

Implemented against the repository's Pigment standard: dense records, neutral actions, actor attribution, underlined tabs, border-only selection, token-based spacing, native modal focus handling, and progressive controls.

| Before | After |
| --- | --- |
| File editing and individual saves obscure the project version boundary | Files → Changes → Save version; one named atomic save includes drafts and working files |
| History is a list of hashes | Attributed timeline, named versions, per-file diffs, parent and current comparisons |
| Navigation drops edits | Memory-only drafts survive route changes; logout asks before discarding |
| A stale file can repeatedly fail saves | Current content refreshes by hash; explicit conflict review updates the save precondition |
| Terminal and administrative actions compete with editing | Terminal starts closed; project menu and focused confirmations reveal secondary actions |
| Wide history consumes mobile space | Compact native version selector and wrapped primary toolbar |

Validation: 344 web tests pass, web TypeScript and production build pass; lint has no errors. Backend suite has 159 passing tests and TypeScript passes. Visual checks covered 390px mobile and 1440px desktop, light and dark themes, file editing, changes review, grouped save dialog, Escape dismissal, and restore confirmation. Browser checks used the read-only owner fixture; signed write behavior is covered by backend integration tests.

Deployment completed: workspace worker `560ca0f4-dc1a-47c5-a3b0-eca3f987d39e`; web `be72dec6-36f0-4853-ada5-75c84d1a9a23`. Production public workspace loaded through the browser with Files/Changes/History and read-only controls. Its API returned the new per-file hashes and changes contract successfully. No production workspace write was performed during this design verification.
