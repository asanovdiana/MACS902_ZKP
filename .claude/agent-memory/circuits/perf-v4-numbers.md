# v4 depth-16 performance (quiet host, 2026-11-08)

`npm run perf:v4` (circuits/scripts/perf-v4.js): fullProve median 942 ms / p95 1064 ms over 60
runs; warm verify() fast median 5.6 ms / p95 7.6 ms, ZKGATE_VERIFY_IMPL=snarkjs 15.5 / 20.2 ms,
bare snarkjs 14.3 / 18.4 ms over 500 round-robin rounds; cold first verify() ~270 ms. Load average
rises from ~0.4 to ~2.4 during the run from our own proving worker pool, not peers. Proof JSON is
806 B indented / 723 B compact; 256 B as raw points. The fast_verify differential (11 v4 fixtures +
an in-memory v3 proof, ~100 mutations each) takes ~25 s. See [[snarkjs-verify-overhead]],
[[benchmark-on-shared-host]], [[fast-verifier-shipped-and-snarkjs-gaps]].
