# circuits — agent memory

> **2026-11-08:** the facts below were learned on the circuits prototype, removed in favour of the team's P1 v3 circuit (`circuits/integrated_access_v3.circom`). The prototype is not included in this repository; paths such as `circuits/src`, `circuits/lib`, `circuits/setup` refer to that commit. Toolchain and snarkjs facts still apply; note the v3 circuit pins circom **2.2.3**. Plan: `docs/plan/p2-plan.md`.

One fact per file in this directory; one line here per fact, newest last. Link related facts with
`[[filename-without-extension]]`. Write a fact when something cost you time to discover and would
cost the next session the same: an endpoint quirk, a tool that lied, a constraint the code does not
state.

Do not record what the repository already says — structure, history, or anything in `CLAUDE.md`.

- [circom comes from cargo](circom-compiler-via-cargo.md) — cargo install works, GitHub releases 403; circom_tester needs `circom` on PATH.
- [Public signal order = declaration order](public-signal-order-is-declaration-order.md) — not the `public [...]` list order.
- [Tests compile at --O2](constraint-counts-o2.md) — counts asserted at O2; measured block sizes.
- [Mutants need witness-tamper tests](witness-tamper-for-mutants.md) — input-level negatives miss `===`→`<--` mutations.
- [EdDSA verifier gaps](eddsa-verifier-gaps.md) — no on-curve check; `enabled` must be 1; pin the issuer key.
- [Vectors are generated](vectors-workflow.md) — regenerate via script; drift fails tests; zk-kit siblings shape.
- [O2 .sym merged = -1](o2-sym-merged-signals.md) — witness tamper needs an --O0 build + alias classes.
- [snarkjs r1cs.info hangs mocha](snarkjs-r1cs-info-hangs-mocha.md) — use r1csfile + F1Field instead.
- [Ad-hoc mutation sweep](mutation-sweep-adhoc.md) — how to run it, gotchas, wiring links are the survivors.
- [mocha CLI spec merges with .mocharc](mocha-cli-spec-merges-with-mocharc.md) — `npx mocha file` still runs the whole glob; use --no-config.
- [Mutation harness runs in a tree copy](mutation-harness-runs-in-a-tree-copy.md) — no test changes; `;` illegal so `===`→`{}`; anon `<--` = TAC01 compile_error.
- [Deleted === vs unconstrained <--](deleted-assert-vs-unconstrained-assign.md) — input negatives kill deletions; only witness tampers kill `<--`.
- [Hermez ptau 403; dev ceremony ~10 min at N=15](ptau-dev-fallback.md) — cached in setup/ptau, not shared across worktrees; download hash mismatch is fatal; entropy via stdin.
- [snarkjs verify keeps mocha alive](snarkjs-workers-hang-mocha.md) — ffjavascript workers; verify.js terminate() in a root after hook; services keep the curve cached.
- [Static tests steal mutation kills](static-killers-mask-weak-negatives.md) — source-text/constraint-count tests kill every mutant; run `--grep negatives --forbid-killers`.
- [circuits/lib is the encoding reference](reference-lib-is-the-encoding-source.md) — buildAccessInput/decodePublicSignals pinned by test/lib.test.js; generators use it; signal changes must update lib; circomlibjs is a devDep.
- [Benchmarks share the host](benchmark-on-shared-host.md) — peer mutation sweeps slow proving ~3×; check uptime and anchored pgrep before benchmarking.
- [snarkjs verify overhead](snarkjs-verify-overhead.md) — ~15 ms is multiExp worker hop + 4 pairings; fast-verify ~6 ms; pairingEq takes target last; millerLoop needs prepared points.
- [Component costs at O2](component-costs-o2.md) — Poseidon(4/5/8/16), EscalarMulAny vs Fix, 4-ary level 306, fixed-key EdDSA 2396.
- [Throwaway setups use SETUP_OUT](perf-builds-use-setup-out.md) — distinct name + `SETUP_OUT=build/perf/setup` so benchmark keys never touch `setup/`.
- [Leading-zero signals: verify.js now rejects](public-signal-leading-zeros-verify.md) — snarkjs reads "0123" as 123; verify() requires canonical decimal since G1-S1-CIRC-010; raw snarkjs callers still exposed.
- [Ceremony: snarkjs verify output is the chain of record](ceremony-multi-party-phase2.md) — verify lists contributions newest-first as 4x4 hex; contribute prompt not echoed; setup_access.test asserts contributions===1; access_16 rehearsal ~3 min.
- [access_16 proving pair is committed](access16-proving-pair-is-committed.md) — setup/access_16.{zkey,wasm} via gitignore `!`; `artifacts:install` fills build/; check-ignore -q is single-path, use --no-index.
- [CI entrypoint + c8 gate](ci-entrypoint-and-c8-gate.md) — `ci.sh quick|full`, exit 0/1/2/3; c8 covers spawned CLIs; pipeline-only scripts need synthetic tests; perf + access-fixtures excluded.
- [Fast verifier shipped; snarkjs gaps](fast-verifier-shipped-and-snarkjs-gaps.md) — verify() = scripts/fast-verify.js (ZKGATE_VERIFY_IMPL=snarkjs escape); snarkjs skips G2 subgroup, accepts O and coords+q; prepare* need Jacobian.
- [Test titles feed mutation regexes](test-titles-feed-mutation-patterns.md) — `--grep`/`--forbid-killers` match full titles; check them before renaming a test.
- [v3 counts per level](v3-constraint-counts.md) — O0 8133+15456, O1 8116+1529, O2 4935+0; root = slot 1; only O0 keeps every signal.
- [v3 tampers: exactly one violated row](v3-one-violated-row-tamper.md) — NamedWitness + second valid witness + Poseidon(2) harness splice; recipes per link kind.
- [v3 equivalent mutants](v3-equivalent-mutants.md) — main booleans on deviceCompliant/employeeActive implied by policy `=== 1`; sweep "kills" them only via a row-count change detector; other 38 mutants killed by targeted tests.
- [[p2-setup-scripts-layout]] — P2 setup scripts run from repo root; build/<name>/, PTAU_DIR ~/zkp-cache/ptau, root node_modules
- [[v3-proving-pair-committed]] — integrated_access_v3 zkey/wasm/vkey/manifest committed (DEV, 4935 constraints at --O2, [root]); re-key = one commit
- [[worktree-guard-refuses-compound-git]] — in agent worktrees run git plainly, one per call; no loops, bash -c or redirected script runs
- [v4 input signal names come from the lib](lib-v4-input-signal-names.md) — buildInputV4 key order = the circuit's declarations; check order puts BAD_SIGNATURE before LEAF_MISMATCH.
- [v3 Alice is role 2 / clearance 2](v3-fileshare-alice-is-opaque.md) — v3 FileShareAccess numbers are opaque, not D6; Bob and Carol fail v3 on purpose.
- [[linear-binding-vanishes-at-o2]] — linear-only binding of a public input survives --O0 tampers but leaves no row at --O2; tamper O2 public slots
- [[challenge-binding-costs]] — ChallengeBinding O2 262+0 (Poseidon(3) 261); no range checks on nonce/resourceId/epoch (gateway obligations); own compile, no compileCached export
- [[v4-splice-circomlib-subwitness]] — templateName harness builds give honest circomlib sub-witnesses for one-row tampers; helpers.compileCached is not exported
- [[comparator-range-gap-values]] — expiry=now+2^64, now=p-1, clearance 5, min p-1 pass circomlib comparators unranged; policy 28 / expiry 192 at O2
- [[v4-building-blocks-components]] — MerkleMembershipN(depth) in a new file (R1CS-identical to hers at depth 2), AttributeHash, SignaturePointsOnCurve; O2 counts; range-check split
- [[v4-building-blocks-sweep]] — 25/25 mutants killed by targeted tests; json reporter + `--grep "identical R1CS|layout|control:" --invert`; Poseidon(7) splice harness
- [[zero-leaf-is-a-member]] — leaf 0 at an empty/revoked index proves membership; safe only because the v4 leaf is in-circuit attrHash
- [[v4-gate-template-separate-file]] — circom won't include a file with a main; v4 template in components/integrated_access_v4_gate.circom, 3 thin mains
- [[v4-constraint-counts]] — d8/d16/d20 at O0/O1/O2 (d16 O2 9208+0); employeeActive folds to constant at O1/O2
- [[v4-gate-one-row-recipes]] — world tree of issuer-signed single-attribute variants + harness splices; point negation for key/R8 links
- [[mutation-harness-p2-layout]] — repo-root paths, MUTATE_TMPDIR, spec order, --annotations read at start, report pinned by mutate.test.js
- [[v4-proving-pair-committed]] — integrated_access_v4 zkey/wasm/vkey/manifest committed (DEV, 9208 at O2, 12 signals in contract order); fixtures bound to it
- [[v4-fixtures-and-obligations]] — access-fixtures.js uses committed pair + SETUP_OUT, exit 2 refusal, plan() reproduces public.json; shared nullifiers; stale_now has its own epoch
- [[perf-v4-numbers]] — prove ~0.94 s, fast verify ~5.6 ms, stock ~14 ms, cold ~270 ms; own proving raises load
- [[snarkjs-binds-every-public-input]] — corrects linear-binding-vanishes-at-o2: zkey new adds an input-binding row per public signal; in-circuit binding is defence in depth (SR-11)
- [[eddsa-verifier-in-mutate-v4]] — eddsa_verifier.circom is a mutate:v4 target; killed by v4 "IssuerSignatureCheck verifier.*" one-row tampers, not by gate tests (SR-18)
- [[circuits-readme-facts]] — circuits/README.md numbers and their source files; non-destructive runs of prove:fixtures/perf for doc checks
- [[ptau-pse-ppot-0080]] — phase 1 = PSE ppot 0080 (pse source, pin power 15 only); manifest status stays "DEV-ONLY" for safety F9.06, DEMO-ONLY in status_detail; re-key keeps public.json
- [[ceremony-p2-manifest-vs-floor9]] — ceremony.sh ported (G2-S1-CIRC-040b); phase2.contributions numeric for F9.09; F9.06 + single-party test assertions block an install; v4 rehearsal ~4 min
