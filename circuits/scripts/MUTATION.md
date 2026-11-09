# Constraint-removal mutation harness and `<--` audit (floor 1)

`circuits/scripts/mutate.js` checks floor 1 mechanically. The floor has two clauses: every circuit
constraint has a test that fails when the constraint is removed, and every `<--` is followed by an
`===` that checks it. Ported from the circuits prototype (task G1-S1-CIRC-002)
to this repository's layout by G1-S1-CIRC-036.

## Run it

From the repository root:

```sh
npm run mutate:v4       # v4 main + gate + every component it includes -> circuits/reports/mutation-v4.{md,json}
npm run audit:arrows    # every <-- / --> in project circuits is followed by an === in its template
```

`mutate:v4` expands to:

```sh
node circuits/scripts/mutate.js \
  --target circuits/integrated_access_v4.circom circuits/components/integrated_access_v4_gate.circom \
           circuits/components/{attribute_hash,issuer_key,merkle_membership_n,access_policy_v4,expiry,challenge_binding,eddsa_verifier}.circom \
  --test circuits/test/v4.test.js circuits/test/{attribute_hash,issuer_key,merkle_depth,policy_v4,expiry,challenge_binding}.test.js \
  --grep 'negatives|closed|rejected' \
  --forbid-killers 'layout|constraint count|identical R1CS|control:|hook|positives|reproduces' \
  --annotations circuits/scripts/mutate/annotations-v4.json \
  --seed-builds --jobs 4 --report circuits/reports/mutation-v4.md
```

102 mutants; see the report header for the measured wall time. Set `MUTATE_TMPDIR` to
put the per-mutant workspaces somewhere other than `os.tmpdir()`.

| Option | Meaning |
|---|---|
| `--target <glob...>` | `.circom` files to mutate. Only project sources under `circuits/` are accepted; `node_modules`/circomlib is trusted upstream and always skipped. Quote globs, or let the shell expand them: every value up to the next `--flag` is taken. |
| `--test <spec...>` | mocha spec file(s) run against each mutant |
| `--report <path>` | writes `<path>.md` and `<path>.json` |
| `--jobs N` | N mutants in parallel; each has its own workspace and build dir |
| `--grep <pattern>` | passed to mocha: only tests whose full title matches run (their suites' hooks still run). A pattern that matches no test fails the baseline (exit 2). |
| `--forbid-killers <regexp>` | a failing test whose full title matches does **not** count as a kill; a mutant whose only failures match is `survived`. Mocha then runs without `--bail`; the reporter aborts at the first non-forbidden failure. See "Static killers". |
| `--annotations <json>` | `{"annotations": [{file, statement, equivalent, note}]}`. `equivalent: true` turns a surviving mutant into `equivalent` (documented with its reason, not a kill, does not fail the run). A note without `equivalent` is shown next to a killed mutant. An entry that matches no site is a usage error, so annotations cannot go stale silently. |
| `--only <file:line>` | only the site(s) whose statement spans that line (repeatable) |
| `--timeout <sec>` | limit per mocha run (default 1800) |
| `--keep` | keep the temp workspaces (paths in the JSON) |
| `--seed-builds` | start every mutant workspace from a copy of the baseline run's `build/`. The test build caches are stamped with the hash of their sources, so builds that include the mutated file recompile and the rest (circomlib harnesses, other components) are reused. Sound for kills: a cache whose source list missed the mutated file can only make a test pass (turn a kill into a visible survivor), never invent a kill. Without it every mutant recompiles everything (~2 h for `mutate:v4` on 4 cores). |
| `--audit-arrows <glob...>` | the static audit instead of a mutation run |
| `--allow-arrow-constraint` | (audit only) a later `<==`/`==>` mentioning the signal also counts as its check; the default is the strict `===` reading of the floor |

Paths are relative to the current directory (or absolute) and must lie under `circuits/`.

**Exit codes:** `0` every mutant killed or documented equivalent (or audit clean); `1` a mutant
survived or errored (or audit violations); `2` usage error, no matching project files, or the
unmutated baseline fails.

## What it does

1. **Sites.** `mutate/parse.js` lexes each target, skips comments and strings, and splits it into
   statements. Every statement carrying `===`, `<==` or `==>` is one site, including multi-line
   statements and statements inside `for`/`if`/`else` (one site even though circom unrolls it; the
   report records the context). `<--` is not a site: it constrains nothing (the audit covers it).
2. **Mutants (M1).** `mutate/mutants.js`: `a === b;` becomes `{ /* MUTANT */ }` (a bare `;` is not
   legal circom); `s <== e;` becomes `s <-- e;` and `e ==> s;` becomes `e --> s;`, i.e. the signal
   is still assigned but unconstrained. Line numbers are preserved.
3. **Run.** `mutate/run.js` runs the specs once on an unmutated copy (the baseline must pass), then
   for each mutant: copies `circuits/` (without `build`, `reports`, `setup`, `node_modules`) plus
   the root `.mocharc.json` and `package.json` into a temp dir, symlinks the root `node_modules`,
   writes the mutated file into the copy and runs mocha there with the project's mocha settings,
   the given specs, `--grep`, and a reporter (`mutate/reporter.js`) that writes results to a file.
   Tests need no changes: `circuits/test/helpers.js` resolves the repository root, sources and
   `build/test/` from its own `__dirname`, which is now the copy.
4. **Outcomes.**

   | Outcome | Meaning |
   |---|---|
   | `killed` | a non-forbidden test failed; the report names it (`killer`) |
   | `survived` | every test passed, or only forbidden tests failed: the constraint is untested and the run fails |
   | `equivalent` | survived, and an annotation proves no new witness is admitted |
   | `compile_error` | circom rejected the mutant (e.g. `<--` on an anonymous component, `error[TAC01]`); reported, does not fail the run |
   | `timeout` | exceeded `--timeout`; flagged, counts as not surviving |
   | `error` | mocha crashed or ran no tests; inconclusive, fails the run |

## Static killers

Some tests fail on **any** source change: constraint-count tests (`<==` to `<--` drops a row),
"identical R1CS" comparisons, `.sym` layout tests, "control:" witnesses that assert a row count.
Such a kill says nothing about soundness, so `mutate:v4` runs only the soundness tests (`--grep
'negatives|closed|rejected'`) and forbids static, positive and hook titles as killers. The report's
"Killed by" column and "Kills per test" table show which test earned each kill. Test titles feed
these regexes: check them before renaming a test.

## Reading a survivor

A surviving `<==` to `<--` mutant almost always means a missing **witness-level** tamper test: the
witness generator still computes the honest value after the mutation, so every input-level negative
behaves as before. Fix it with a test that edits a valid `--O0` witness by name
(`NamedWitness` in `circuits/test/helpers.js`) so that **exactly one** R1CS row (the link) is
violated, and asserts `checkConstraints` throws. Recipes used in `circuits/test/v4.test.js`:

- single-consumer input (`binding.nonce <== nonce`): change `main.nonce` alone;
- input with two consumers (`attr.role` and `policy.role`): splice an issuer-signed variant
  credential's honest sub-witnesses (harness builds of each component) into one side only;
- issuer key / R8 (`signature.Ax` and `points.Ax`): negate the coordinate, which keeps the point on
  BabyJubJub and leaves `BabyCheck`'s `x2` unchanged, in `main` and one consumer only;
- public inputs additionally get an `--O2` public-slot tamper: a linear-only binding leaves no R1CS
  row at `--O2` even when an `--O0` tamper passes (in the circuit R1CS; snarkjs `zkey new` adds its
  own input-binding row per public signal, so this is defence in depth, SR-11).

A deleted `===` is usually caught by input-level negatives, because deleting it also removes the
witness generator's `Assert`.

Survivors are fixed, not waived. Only a mutant that provably admits no new witness may be annotated
`equivalent`, with the proof in the note.

## Files

| File | Role |
|---|---|
| `circuits/scripts/mutate.js` | CLI |
| `circuits/scripts/mutate/parse.js` | lexer, statement splitter, sites, arrow audit |
| `circuits/scripts/mutate/mutants.js` | M1 mutant generation |
| `circuits/scripts/mutate/run.js` | workspace copy, mocha run, outcome classification, job pool |
| `circuits/scripts/mutate/report.js` | markdown and JSON report |
| `circuits/scripts/mutate/reporter.js` | mocha reporter |
| `circuits/scripts/mutate/annotations-v4.json` | notes / equivalence proofs for the v4 run |
| `circuits/reports/mutation-v4.{md,json}` | the committed v4 result (pinned by `circuits/test/mutate.test.js`) |
| `circuits/test/mutate.test.js` | the harness's own tests + the committed-report checks |
| `circuits/test/fixtures/mutate/` | fixtures for those tests (`*.spec.js` never run by `npm test`) |
