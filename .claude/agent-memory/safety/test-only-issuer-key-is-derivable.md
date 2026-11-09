# The TEST-ONLY vector issuer key is derivable, and it is the fixtures' pinned key

`prv = sha256(vectors.issuer.seedLabel)` (circuits/scripts/gen-vectors.js). It reproduces
`circuits/fixtures/v4/fixtures.json` `context.pinned_issuer`, so a test can sign ANY attributes
"by the issuer" (used for expired / out-of-range / per-clause policy cases in floor02). The flip
side is finding SR-07: a gateway configured from fixtures.json accepts forgeries.
See [[committed-wasm-is-a-fast-witness-oracle]].
