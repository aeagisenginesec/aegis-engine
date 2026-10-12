# Corpus-v2 split

- **Dev set**: 150 projects (`projects/`, `manifest.json`) — visible to rule authors.
- **Held-out set**: 50 projects (`heldout/projects/`, `heldout/manifest.json`) — RESTRICTED.
- **Selection**: stratified secret-seed shuffle — 35 vulnerable + 15 secure held out.
  known_gap projects (documented scanner limitations) are forced into dev.
- **Held-out manifest sha256**: `089a25fb1a54cc8ce28208b82dabf269654348a049dc0059de0476ddedbe898e`
- **Seed sha256**: `9e548d4db59b83d719ce169081bb59baa21ca9a0d2f332099df92659cf23e352` (seed itself in `heldout/.seed`, chmod 600, gitignored)

## Policy

Do NOT tune rules against held-out projects or inspect `heldout/manifest.json`
during development. The held-out set measures generalization. In CI, inject the
seed as a secret and verify `heldout/manifest.json` against the sha256 above
before scoring; any mismatch means the labels were tampered with.

In this local environment true access control is not enforceable — this file,
the chmod-600 permissions, and the integrity hash are the mechanism, plus
reviewer discipline. Treat any held-out tuning as a benchmark integrity violation.
