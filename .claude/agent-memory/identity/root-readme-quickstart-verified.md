# Root README quick start (G1-S1-IDEN-015)

The root README quick start was run in a temp dir: v4 issuer on port 8107 with `ISSUER_ADMIN_TOKEN`, temp key/data dirs, `seed-personas.js`, a hand-made challenge JSON (File Share, resourceId 2, `now` = wall clock), `zkgate prove --challenge --out`, `circuits/scripts/verify.sh integrated_access_v4` -> OK; Bob is refused locally (exit 1).

- SR-20: `buildServer` now needs `config.insecureDev === true` in both places; test in `issuer/test/enrolment.test.js`.
- Counts at this commit: root 866, issuer 174 + 1 pending, client 87, attacks 27, safety 76 pass + 4 todo.
- Known stale doc not mine: `circuits/README.md` still describes v3 only (flagged in the root README).
- Link checker for the root README: scratchpad `linkcheck.js` (relative links only).

See [[report-numbers-provenance]] and [[enrolment-v2-design]].
