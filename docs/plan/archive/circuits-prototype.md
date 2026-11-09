# Archive: circuits prototype (superseded)

These tasks built a circuits prototype in `circuits/` before the team's P1 circuit arrived. On
2026-11-08 the prototype was removed in favour of the teammate's P1 v3 circuit
. The prototype is not included in this repository; it served as the reference
implementation for the P2 plan (`docs/plan/p2-plan.md`).

| Task | Owner | Branch | Evidence | Completed |
|---|---|---|---|---|
| G0-S1-CIRC-006 | `circuits` | development branch | `npm test --prefix circuits` → 24 passing (re-run by Orchestrator); `gen-vectors.js` → vectors up to date. Accepted SPEC additions C4/C5 (BabyJubJub on-curve checks for R8 and issuer key). Gateway must check `now` against its clock (SPEC §8). | 2026-11-02 |
| G1-S1-CIRC-001 | `circuits` | development branch | `npm test --prefix circuits` → 139 passing (re-run by Orchestrator); `mutate:audit` → 0 `<--`, 0 violations. Constraints (--O2): d8 7199, d16 9135, d20 10103. Safety review requested (floors 1, 2, 3, 5). | 2026-11-02 |
| G1-S1-CIRC-003 | `circuits` | development branch | setup_access.test.js → 38 passing (re-run by Orchestrator); `verify.sh` OK on alice_wiki and forged_issuer_alice_wiki. access_16 vkey + manifest committed (DEV-ONLY ptau: Hermez 403 in sandbox; single-party phase 2). Finding: a forger can prove under their own issuer key, so gateway §8.1 (pin issuer key) is load-bearing. Open: distribution of `access_16.zkey`/`.wasm` (gitignored, not reproducible across setups). | 2026-11-02 |
| G1-S1-CIRC-002 | `circuits` | development branch | `npm run mutate:access` re-run by Orchestrator → 59 mutants, 59 killed, 0 survived, all killers N-id/wiring negatives; `mutate:audit` → 0 violations. | 2026-11-02 |
| G1-S1-CIRC-004 | `circuits` | development branch | perf.test.js 13 passing (Orchestrator); reports/perf-native.md: prove d16 893/965 ms med/p95; verify 14.5 ms (snarkjs) — misses 10 ms target, fixed by CIRC-011. No circuit change recommended. | 2026-11-02 |
| G1-S1-CIRC-007 | `circuits` | development branch | docs only; numbers cross-checked; found leading-zero replay → CIRC-010 | 2026-11-02 |
| G1-S1-CIRC-008 | `circuits` | development branch | ceremony.test.js 16 passing (Orchestrator); access_16 rehearsal ~3 min. Real run is a team action (needs Hermez ptau). | 2026-11-02 |
| G1-S1-CIRC-009 | `circuits` | development branch | lib.test.js 33 passing (Orchestrator); reproduces vectors (floor 8) | 2026-11-02 |
| G1-S1-CIRC-010 | `circuits` | development branch | Orchestrator repro: leading-zero nonce now false, honest true; 147 passing. Safety review requested. | 2026-11-02 |
| G1-S1-CIRC-013 | `circuits` | development branch | gen-vectors "up to date"; generators+vectors 29 passing (Orchestrator); 9/9 regenerated fixtures verify | 2026-11-02 |
| G1-S1-CIRC-014 | `circuits` | development branch | `artifacts.sh check` OK, hashes = manifest, artifacts.test.js 11 passing (Orchestrator). Committed DEV-ONLY zkey/wasm (user decision). | 2026-11-02 |
| G1-S1-CIRC-012 | `circuits` | development branch | `ci.sh quick` PASS (Orchestrator); full PASS in agent run (10m31s); coverage ≥ 89.7% lines per file | 2026-11-02 |
| G1-S1-CIRC-011 | `circuits` | development branch | full suite 385 passing + `ci.sh quick` PASS (Orchestrator); verify median 4.86 ms / p95 6.69 ms (reports/perf-verify.md). Safety + gateway sign-off requested. | 2026-11-02 |
| G1-S1-CIRC-015 | `circuits` | development branch | docs only; link check 125 links / 0 broken (Orchestrator); SKIP_SETUP suite 299 passing | 2026-11-02 |
