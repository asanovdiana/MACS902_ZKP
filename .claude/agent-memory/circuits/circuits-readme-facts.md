# circuits/README.md: where each number comes from

Refreshed by G1-S1-CIRC-041 (v3 + v4, layout, npm scripts, floor-1 evidence, consumers, DEV keys).
Every number in it is copied from a committed file; update it from the same sources when they move:

- v3 counts: `circuits/test/v3.test.js` (8133+15456 / 8116+1529 / 4935+0); v4 counts per depth:
  `circuits/test/v4.test.js` table ([[v4-constraint-counts]]).
- mutation 102/102, baseline 350 tests: `circuits/reports/mutation-v4.md` header (the G1 review
  still cites the older 95/95 run).
- arrow audit "26 files, 0 arrows, 0 violations": `npm run audit:arrows` output; the 26 files
  include the broken fragment `components/integrated_access.circom` (lexed, never compiled).
- verify 5.61 ms / 15.48 ms: `circuits/reports/perf-v4.md` ([[perf-v4-numbers]]).
- suite size at the time of writing+: `npm test` 866 passing (~2.5 min cold); `SKIP_SETUP=1` 825 passing, 41 pending.

Non-destructive runs of the regenerating scripts: `npm run prove:fixtures:v4 -- --out <tmp>`,
`npm run perf:v4 -- --prove-runs 2 --verify-runs 5 --warmup 1 --out-dir <tmp>`. `setup:v*`
re-keys and `mutate:v4` takes long: never run them just to check docs.
Link-check the README with a scratch script after edits ([[mocha-cli-spec-merges-with-mocharc]]
explains the `--no-config` single-file command it documents).
