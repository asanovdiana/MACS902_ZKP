# Reference vectors are generated, never hand-edited

`scripts/gen-vectors.js` (circomlibjs + @zk-kit/incremental-merkle-tree 1.1.0) writes
`test/vectors/*.json`; `npm run vectors` regenerates, `node scripts/gen-vectors.js` checks drift,
and `test/vectors.test.js` fails on any byte difference. Clock is fixed (now 2026-11-02T09:00Z,
expiry 2028-01-01) so output is deterministic. Keys/secrets = sha256(public TEST-ONLY label); the
issuer private key is stored only as its label (floor 9). zk-kit `createProof` returns
`siblings[i]` as a 1-element array for arity 2 — flatten with `s[0]`.
