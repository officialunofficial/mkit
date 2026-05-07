# Homebrew tap publication flow

This directory holds the formula template for a future
`officialunofficial/homebrew-tap` repository. It is **not** consumed by
Homebrew directly from this repo — Homebrew taps must live at
`<user>/homebrew-<name>`.

## One-time tap setup

```sh
# Create a new public GitHub repo named `homebrew-tap` under the
# `officialunofficial` org. Then:
git clone git@github.com:officialunofficial/homebrew-tap.git
cd homebrew-tap
mkdir -p Formula
```

## Per-release publication

After each `v*.*.*` release is published on `officialunofficial/mkit`:

1. Download the release archives (or read the `SHA256SUMS` file from the
   release page).
2. Copy `contrib/homebrew/mkit.rb` from this repo into
   `homebrew-tap/Formula/mkit.rb`.
3. Update `version` to the new version.
4. Replace every `PLACEHOLDER_SHA_*` with the matching sha256 from
   `SHA256SUMS` (one per target triple).
5. Commit + push to the tap repo.

## User install flow

```sh
brew tap officialunofficial/tap
brew install mkit
mkit version
```

## Automation (TODO)

Once a tap repo exists we can automate this with
[`dawidd6/action-homebrew-bump-formula`](https://github.com/dawidd6/action-homebrew-bump-formula)
or a hand-rolled job in `release.yml` that opens a PR against the tap repo.
Each release is still promoted by hand to keep the publication boring and
auditable.
