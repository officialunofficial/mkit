# Site content and design

The documentation site uses literal language and the Pigment design system.
This guide applies to pages, demo instructions, labels, errors, tooltips,
reference summaries, metadata, and social cards.

## Small review workflow

1. Read the page and its supporting component and data files. Identify the
   reader’s task, then remove sentences that do not help complete it. Preserve
   command names, measurements, limitations, and protocol requirements.
2. Check the rendered result against Pigment. Use existing role tokens and
   shared controls. Review narrow and wide layouts, both themes, keyboard
   focus, reduced motion, and overlay dismissal.
3. Run formatting, lint, type checking, relevant tests, and the production
   build. Read the final diff for factual changes and inspect affected routes.
   Update this guide when an intentional design exception changes.

## Writing

Use the literal phrase whenever one exists. Name the subject and its action:
“A file change changes its parent folder’s hash,” rather than “an edit ripples
up the tree.” Remove promotional judgments such as “where it counts” and
“earns its keep.”

Use sentence case for headings and controls. Keep proper names and code
identifiers in their canonical form. Button labels name actions, such as
“Sign and push.” Link text names its destination. Errors explain what happened
and give a recovery action when one is available.

State exactly what a demonstration proves. A signature identifies a signing
key; it does not establish a person’s identity. Distinguish measured results
from examples and identify excluded costs. Keep benchmark numbers and their
measurement context together.

Avoid repeating information already visible in the interface. Introduce an
unfamiliar technical term before relying on it. Retain established terms such
as hash, branch, Merkle tree, and attestation when they identify the mechanism.

## Pigment

The reference is `@officialunofficial/pigment` 0.2.1:

- [Design principles and foundations](https://github.com/officialunofficial/monorepo/blob/ba69f5c4c3976a5837e402d5a7857c0cb426f41f/client/packages/pigment/docs/DESIGN.md)
- [Component rules](https://github.com/officialunofficial/monorepo/blob/ba69f5c4c3976a5837e402d5a7857c0cb426f41f/client/packages/pigment/docs/DESIGN_COMPONENTS.md)
- [Canonical tokens](https://github.com/officialunofficial/monorepo/blob/ba69f5c4c3976a5837e402d5a7857c0cb426f41f/client/packages/pigment/styles/tokens.css)

The site’s token mapping is in [src/styles.css](src/styles.css). This package
maintains that mapping locally; it does not import Pigment’s React components.
When updating it, compare values and theme behavior with the canonical source.

Use DM Sans for prose and DM Mono for code, hashes, and raw values. Headings use
the documented size and tracking. Text is at least 11px; values are at least
12px. Use neutral action colors and semantic status colors. Selection and
status must also have a text or shape indication.

Reuse `.btn` variants, `.ds-link`, `.ds-h1` through `.ds-h3`, `.data-frame`,
and `.code-region`. Use `.touch-target` for compact isolated controls. Adjacent
touch controls need enough layout space to keep their hit areas separate.
On coarse pointers, `.btn` reserves at least 44px in both dimensions; only
isolated `.touch-target` controls expand their hit area outside the layout.
Use the shared motion tokens and honor reduced motion.

Use `TopLayer` for nonmodal overlays and `ModalLayer` for dialogs. Radix portals
inside a modal must use `useOverlayContainer()` so native modal inertness does
not disable them. Check Escape dismissal and focus restoration in a browser.

Keep data readable, actors identifiable, and state understandable without
color. Use space to separate related groups, not as decoration.

## Rendering exceptions

- Hash chips and identity avatars derive color from data. These colors do not
  style primary actions, selection, or status.
- Image previews retain the image’s background. Their pixels are content,
  not theme surfaces.
- Social images use a fixed light palette and sizes suitable for a 1200 × 630
  export. Their typeface and color roles match Pigment; interactive control
  sizes do not apply to this raster output.

## Audit record: September 8, 2026

Reviewed all six site routes, the 404 page, shared navigation and layout,
all six concept demos, multiplayer and lobby components, reference data,
metadata, the web README, and the social-card renderer.

Replaced metaphorical headings and promotional copy with direct descriptions.
Shortened benchmark notes while preserving measurements. Clarified signature
verification, specification status, Git compatibility, and the push demo’s
actual sample size. Converted older demo controls to Pigment role colors,
restored high-contrast overrides, and corrected typography, motion, touch
targets, and overlay placement.

Simplified the source link, grouped expanded navigation into Learn and
Reference columns, and added layout-matched loading placeholders for demos,
lobby activity, repositories, and commit details.
Review fixes reserve button touch dimensions in layout and match the tree
placeholder's output-first order, breakpoint, spacing, and column widths to
the loaded demo.

The lobby uses TanStack Virtual's end anchoring, stable item keys, dynamic
measurement, and immediate following when the reader is at the bottom.
Removed the custom initial frame loop and smooth scrolling on arrivals:
background updates and resume batches previously requested animated scrolling.
Updated React Virtual to 3.14.11 (core 3.17.9), which also fixes a measured
row growing before the scroll container's size has committed. Regression
tests reproduced both failures before the changes. The feed has a fixed,
keyboard-focusable viewport and a Latest button for returning from history.

The site links to repository specifications; this audit changes their site
summaries, not the normative specification documents. User-authored messages
and commit text remain data. Generated installers and the published CLI skill
retain their source files and are not edited as site copy.

### Validation

- Web: formatting, lint, TypeScript, 267 tests, and the production build pass.
  The build verifies six prerendered routes, the custom 404, installer, and
  security headers. Lint reports existing warnings in unchanged library files.
- Social cards: 21 tests, TypeScript, and the Worker dry-run build pass. A real
  image rendered through the local Worker was inspected.
- Browser: checked the home page, concept navigation, signature verification
  in dark mode, mobile multiplayer layout, and reference routes at 390px.
  Confirmed the native modal, nested reaction popover, Escape dismissal, and
  focus restoration. No messages, commits, or reactions were submitted.
- Feed: eight regression tests use the real virtualizer with simulated DOM
  geometry. They cover hidden/resume updates, history anchoring, loading,
  Latest, row resizing, and bounded rendering with 10,000 messages. The live
  browser preview confirms the fixed viewport and immediate scroll behavior;
  a browser's full operating-system suspension cycle was not automated.
- High-contrast values match the canonical token source. Reduced-motion CSS
  and overlay cleanup have source and unit-test coverage; OS preference
  switching and every device/browser combination were not tested.
