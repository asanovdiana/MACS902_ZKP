# F9.06 flips to todo by itself when a multi-party key is committed

F9.06 carries `{ todo: F906_SUPERSEDED }`, computed at module load: `false` while both
`circuits/setup/*.manifest.json` have numeric `phase2.contributions < 2`, a "superseded by F9.12"
string once either claims >= 2. Do not hand-edit it to `todo` and do not delete it (floor 10).

F9.12 (`provenanceViolations`, `fixtureTextViolations` in floor09) is the real rule: multi-party
needs the full evidence AND the transcript named by `phase2.transcript` must exist in the tree, hash
to `transcript_sha256` and agree on contributors, beacon and phase-1 blake2b. So a ceremony install
commit must include `circuits/ceremony/<name>/transcript.json`, or F9.12 goes red.

Trap: the current single-party limitation says "replace via the multi-party ceremony", so a bare
`/multi-party/` regex matches it; F9.12 matches `/multi-party phase 2 \(/` for the claim.

See [[rekey-provenance-checks]], [[safety-tier-layout]].
