# Phase 1 is PSE ppot 0080 since G2-S1-CIRC-040a; manifest status stays "DEV-ONLY"

Hermez ptau is gone at the source (AccessDenied, not a proxy 403). `ptau.sh` source `pse` reads
`~/zkp-cache/ptau/ppot_0080_15.ptau`; only power 15 is pinned (blake2b a6dd3adc..., pinned on first
download, PSE publishes none); `auto` = pse -> hermez -> dev. On first use it writes a
`.info.json` with source `pse-ppot-0080` + a `provenance` string that `setup-manifest.js` copies
into `ptau.provenance`. `npm run setup:v3|v4` now set `PTAU_SOURCE=pse`.
Manifest `status` is kept `"DEV-ONLY"` because tests/safety F9.06 asserts it with `assert.equal`
(and fixtures TEST_ONLY must match /DEV-ONLY/); the DEMO-ONLY wording is in `status_detail`.
Changing `status` needs safety first. A re-key leaves public.json identical; only proofs, vkey
copy and fixtures.json hashes change. v3 wasm came out byte-identical; v4 wasm bytes differ.
Unrelated time bomb: client/test/e2e.v4.test.js "an expired credential is refused locally" uses a
fixed NOW=1794128400 and fails once wall clock passes it (issuer refuses a past expiry).
See [[v4-proving-pair-committed]], [[ptau-dev-fallback]], [[v4-fixtures-and-obligations]].
