# identity — agent memory

One fact per file in this directory; one line here per fact, newest last. Link related facts with
`[[filename-without-extension]]`. Write a fact when something cost you time to discover and would
cost the next session the same: an endpoint quirk, a tool that lied, a constraint the code does not
state.

Do not record what the repository already says — structure, history, or anything in `CLAUDE.md`.

- [Registry fails stop on persist error](issuer-registry-failstop.md) — no sync rollback possible; see [[issuer-key-dir-is-config]].
- [Issuer key dir is configuration](issuer-key-dir-is-config.md) — guard hook blocks `issuer/keys/**`; tests use temp dirs.
- [Fastify LogController](fastify-logcontroller-not-disablerequestlogging.md) — avoid FSTDEP023; issuer tests are `npm test --prefix issuer`.
<!-- Example, delete when the first real fact lands:
- [A guessed URL is not a measurement](a-guessed-url-is-not-a-measurement.md) — probe before
  asserting; see also [[fixture-provenance-rule]].
-->
- [client tests: node:test + stub issuer](client-tests-use-node-test-and-stub-issuer.md) — why not mocha, how coverage runs, v3 artefact paths
- [v3 role numbers are opaque](v3-role-numbers-are-opaque.md) — role/clearance 2 or 3 to prove on v3
- [SSE streams destroyed on preClose](sse-streams-destroyed-on-preclose.md) — else app.close() hangs; admin events design in docs/CONTRACTS.md
- [zk-kit zeroes is depth long](zk-kit-tree-has-no-root-zero.md) — root-level zero computed separately; uses private _nodes
- [Cross-check suite harness](crosscheck-suite-harness.md) — inject-backed fetch, O0 named signals, witness slots; see [[v3-role-numbers-are-opaque]]
- [client v4 e2e harness](client-v4-e2e-harness.md) — real issuer + challenge stub in-process, timings; see [[client-tests-use-node-test-and-stub-issuer]]
- [Report numbers provenance](report-numbers-provenance.md) — 263 values is printed by the issuer suite, not stored; root suite 859; see [[crosscheck-suite-harness]]
- [Attack Lab: one attack at a time](attack-lab-order-and-roots.md) — roots move on enrol/revoke; code depends on check order
- [Enrolment v2 design](enrolment-v2-design.md) — admin code flow, consume-before-insert, insecure-dev vs secure test posture
- [Safety suite assumes v1](safety-suite-v1-assumptions.md) — tests/safety breaks on v2 by design; safety must append updates
- [Root README quick start verified](root-readme-quickstart-verified.md) — commands run in a temp dir; SR-20 fix; counts; see [[report-numbers-provenance]]
- [fixed-clock-vs-real-issuer](fixed-clock-vs-real-issuer.md) pin issuer clock in fixed-NOW client tests
