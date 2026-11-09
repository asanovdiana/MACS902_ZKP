# v4 fixtures: names, obligations and shared nullifiers

`circuits/scripts/access-fixtures.js` proves with the COMMITTED pair in `$SETUP_OUT` (default
circuits/setup, no build dir needed) and refuses with exit 2 (class Refusal) on any hash mismatch;
`plan()` is exported and deterministic, so tests reproduce every public.json from circuits/lib
without proving. Inputs come from `test/vectors/v4/credentials.json` via buildInputV4.
Each fixture carries `gateway_obligations` (contract numbering 1-8), `presented_to` and
`gateway_state`. Gotchas: stale_now uses its own epoch = epochOf(old now) because buildInputV4's
precheck demands epoch == floor(now/600); every Alice->Wiki fixture in the current epoch shares
one nullifier, and bob_wiki/stale_root_bob_wiki share another, so gateway tests need fresh state
per scenario. Secret-scan threshold: the vectors give only ~40 distinct long private values
(empty-subtree siblings dedupe). The README may name `credentialSecret` in prose; the key-name
regex applies to JSON only. See [[v4-proving-pair-committed]], [[access-fixtures-are-tied-to-one-setup-run]].
