# P2 ceremony: phase2.contributions must stay a number; F9.06 blocks any install

Ported in G2-S1-CIRC-040b (`circuits/scripts/ceremony.sh` + `ceremony-transcript.js`, repo-root
paths, CEREMONY_DIR default `circuits/ceremony/`, init defaults to PTAU_SOURCE=pse).

- tests/safety F9.09 guards with `m.phase2.contributions >= 2`. The prototype wrote an ARRAY there;
  `[{..},{..}] >= 2` is `NaN >= 2` = false, so F9.09 would demand DEV-ONLY + "single-party phase 2"
  text. The P2 manifest keeps `contributions` numeric and puts the chain in `phase2.contributors`.
- F9.06 asserts `status === "DEV-ONLY"` and a `/single-party phase 2/` limitation UNCONDITIONALLY
  for v3+v4, plus `/DEV-ONLY/` in fixtures TEST_ONLY. A real ceremony install fails it by design;
  safety must supersede F9.06 first (append-only suite). Also pinned to single-party wording:
  circuits/test/setup.test.js (v3), setup_v4.test.js, fixtures_v4.test.js:93, and
  access-fixtures.js TEST_ONLY text.
- Status rule in buildManifest: DEMO-ONLY only if >= 2 contributions AND public phase 1 AND
  `beacon.public`; else DEV-ONLY with status_detail naming why.
- Static test forbids `\s-e[= ]` in ceremony.sh (snarkjs entropy flag): `[ ! -e f ]` trips it; use -f.
- Toy for tests: circuits/test/circuits/challenge_binding_main.circom (262 at O2), whole e2e ~1 min
  with the cached PSE ptau. v4 rehearsal: init 27.5 s, contribute ~27-29 s, verify ~24 s,
  finalize 50.6 s, install 0.8 s; zkeys 6.1 MB.
- safety suite needs `npm ci --prefix issuer` and `npm install --prefix client --no-package-lock`
  (client has no lockfile) in a fresh worktree, else "Cannot find module 'fastify'".

See [[ceremony-multi-party-phase2]], [[ptau-pse-ppot-0080]], [[v4-proving-pair-committed]].
