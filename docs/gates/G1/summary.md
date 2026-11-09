# Gate G1 — End-to-end proof verifies (week-4 critical gate) — P2 lane

**Scope.** This gate covers the P2 lane as expanded in `docs/strategy.md` §11 (G1): the v4 circuit
built on P1's v3, the shared encoder, the issuer/registry and the client prover. The gateway (P3),
UI and devops lanes are owned by other team members and are not in this repository; obligations they
own are listed under Floors and Verdict as not covered by this gate.

**Gated revision.** The development branch as of 2026-11-08 (plus the gate bundle itself).
**Date.** 2026-11-08. **Run by.** Orchestrator.

## Functional

Every G1 task in `docs/strategy.md` §11, with the handoff evidence recorded in `docs/plan/README.md`
(Completed). "Re-run" means the Orchestrator re-ran the named tests before merging.

| Task | Outcome | Acceptance evidence |
|---|---|---|
| G1-S1-ARCH-011 | met | `credential v4`, `access.public_signals v4` recorded before code (`docs/CONTRACTS.md`, ADRs 0006–0007); `issuer.api v2` / `issuer.admin v1.1` added contract-first by G1-S1-IDEN-014 |
| G1-S1-CIRC-030 | met | `MerkleMembershipN(depth)` beside her file; depth 2 compiles to the identical R1CS of her `MerkleMembership()` at O0/O1/O2; her files unchanged |
| G1-S1-CIRC-031 | met | `AttributeHash` = signed message = leaf; each of 7 tampered attributes under the original signature rejected — closes gap G-1 |
| G1-S1-CIRC-032 | met | issuer key public; on-curve checks; self-signed credential rejected under the pinned key — closes G-2 (gateway pin is obligation 2) |
| G1-S1-CIRC-033 | met | generic `AccessPolicyV4`; 9 persona × policy verdicts match the contract; exhaustive mask/clearance tables |
| G1-S1-CIRC-034 | met | `ExpiryCheck`, 64-bit range checks; `expiry == now`, `< now`, wrap-arounds rejected |
| G1-S1-CIRC-035 | met | `ChallengeBinding`: nonce/resourceId/epoch bound; nullifier = Poseidon(3)(secret, resourceId, epoch), stable across nonces, unlinkable across resources |
| G1-S1-CIRC-036 | met | `integrated_access_v4.circom` (d16; d8/d20 for benchmarks), 9208 constraints at O2; 12 public signals in contract order (`.sym` test); mutation 95/95 → 102/102 after G1-S1-CIRC-039; arrow audit 0 |
| G1-S1-CIRC-037 | met | committed v4 proving pair + vkey + manifest; 11 fixtures (5 valid, attack set); fast verifier identical to snarkjs on a differential set; re-keyed on PSE ppot 0080 phase 1 by G2-S1-CIRC-040a, `artifacts:check` 8/8 |
| G1-S1-CIRC-038 | met | `circuits/lib` v4 profile; reproduces vectors; built input accepted by the v4 witness calculator |
| G1-S1-IDEN-010 | met | issuer signs attrHash with expiry; enums enforced; issuer receives only the commitment |
| G1-S1-IDEN-011 | met | registry depth 16, revoke = zero leaf, 30 s staleness rule never re-admits across a revoke |
| G1-S1-IDEN-012 | met | client v4 e2e against the real issuer and committed keys: 5 admitted combinations prove and verify, 3 denied refused locally, revoked/expired/bad-epoch refused; client suite 87/87 (re-run) |
| G1-S1-IDEN-013 | met | cross-component check: 263 values agree across client, issuer, `circuits/lib` and the compiled circuits (floor 8) |
| G1-S1-SAFETY-020 | met | floor review + floor tier; Floors APPROVE with follow-ups; follow-ups SR-03/04/09/10/11/13/18/20 closed (G1-S1-IDEN-014, -015, G1-S1-CIRC-039, G1-S1-SAFETY-021) |

**End-to-end runs by the Orchestrator (real services, not stubs):**
- G0 (v3): real issuer + client CLI → Groth16 proof → `verify.sh` OK; revoke → client refused (410).
- G1 (v4): exercised by the client e2e suite against the real in-process issuer and committed v4
  keys (re-run green at the gated revision), and by the README quick start (issue → seed personas → prove →
  verify OK; Bob refused) run end to end by G1-S1-IDEN-015.

Functional: **PASS**. No task missed.

## Tests

Produced by the `qa` role at the gated revision (read-only review; raw logs kept outside the repo).

**Suites (all exit 0):**

| Command | Result |
|---|---|
| `npm test` (root mocha, circuits) | 874 passing, 0 failing |
| `npm test --prefix issuer` | 174 passing, 1 pending (`tree_full` v3-only case), 0 failing |
| `npm test --prefix client` | 87 tests, 87 pass, 0 fail |
| `npm test --prefix client/attacks` | 27 tests, 27 pass, 0 fail |
| `npm test --prefix tests/safety` | 80 tests, 76 pass, 0 fail, 4 todo (F3.09, F4.06, F5.07, F7.05 — gateway P3) |

**Coverage against `test_tiers` (unit 80, integration 70, floor 95):**

| Tier | Scope | Lines | Threshold |
|---|---|---|---|
| unit | `circuits/lib` + `circuits/scripts` | 95.04% (lib 99.12%, scripts 92.82%; lowest file `access-fixtures.js` 80.62%) | ≥ 80 ✔ |
| unit | `issuer/src` | 99.11% | ≥ 80 ✔ |
| unit | `client/src` | 97.28% | ≥ 80 ✔ |
| unit | `client/attacks/src` | 97.98% | ≥ 80 ✔ |
| integration | issuer + client e2e/cli + attacks + safety, shared coverage | 89.76% overall (client 88.13%, attacks 97.98%, lib 95.73%) | ≥ 70 ✔ |
| floor | `tests/safety` MANIFEST | 76/80 = 95.0% (76/76 = 100% of non-todo) | ≥ 95 ✔ (no margin) |
| circuits | `circuits/reports/mutation-v4.md` | 102/102 killed, 0 survived; report current; `audit:arrows` 0 violations | floor 1 ✔ |

Caveats: unit runs include real-circuit tests, so tiers are not cleanly separated; `tests/integration/**`
and `tests/e2e/**` (qa-owned) are empty — the integration tier is carried by package suites.

**Pipeline.** `.github/` does not exist; `gh run list` returns nothing. **No pipeline exists (SR-17,
`devops`).** Every result above is a local run; nothing is CI-verified. This is a finding, not a pass.

**Drift.** `node circuits/scripts/gen-vectors.js --check` → `vectors up to date`; `npm run -s
artifacts:check` → v3 and v4 zkey/wasm/vkey hashes match the manifests and each vkey re-exported from
its zkey equals the committed file.

**qa verdict: CONDITIONAL** — (1) `devops`: create the pipeline running the suites and the
artefact/vector checks (SR-17); (2) `gateway` + `safety`: the 4 todo floor IDs must go green when P3
lands (the floor ratio has no margin until then); (3) `qa`: add a qa-owned integration entry point
once the gateway exists; (4) minor, `circuits`: `access-fixtures.js` is just above the unit threshold.

## Floors

Verdict from [`floors.md`](floors.md), written and signed by `safety` (not restated here):
**Floors (G1, P2 lane): APPROVE.** The gateway half of floors 2–5 and 7 is explicitly not signed by
this gate and is carried to the P3 gate (SR-05, SR-07).

## Operational

- **Metrics and logs for new things.** Issuer: one structured JSON log line per request (route,
  status, latency, error code — no commitment, attributes, enrolment code, employeeId or key
  material; asserted by tests F7.01–F7.04); `GET /metrics` with issued, revoked, root changes,
  enrolments created/redeemed/pending, SSE clients/events, per-route counts and latency. Client: CLI
  and library, stable machine error codes, no secrets in output (tested). Circuits: perf reports
  `circuits/reports/perf-v4.md`, mutation report `circuits/reports/mutation-v4.md`.
- **Runbook.** Start/seed/prove/verify in the root `README.md` quick start (verified end to end);
  issuer configuration in `issuer/README.md` (fail-closed without `ISSUER_ADMIN_TOKEN`; key dir 0700);
  re-keying checklist in `circuits/setup/ARTIFACTS.md`; ceremony steps in `docs/plan/p2-plan.md`
  G2-S1-CIRC-040.
- **Rollback path.** Verifier: `ZKGATE_VERIFY_IMPL=snarkjs` falls back to stock snarkjs. Keys:
  every key set is committed together with its vkey, manifest and fixtures, so a revert of one commit
  restores a consistent set. Issuer: state is a JSON file in `ISSUER_DATA_DIR`; fail-stop on a failed
  write, restart from the last persisted state.
- **Backup coverage.** The registry/enrolment state (`ISSUER_DATA_DIR`) and the issuer key
  (`ISSUER_KEY_DIR`) are the only state; both are outside the repo by design (floor 9). Backing them
  up is a deployment concern for `devops` (compose volumes) — not yet in this repo (SR-17).

## Milestone additions

From `docs/strategy.md` §11 G1 gate additions:

| Addition | Status | Evidence |
|---|---|---|
| an end-to-end v4 Groth16 proof from an issued credential verifies | met | client e2e (`client/test/e2e.v4.test.js`), README quick start run |
| every v4 constraint has a killing negative test (0 mutation survivors) | met | `circuits/reports/mutation-v4.md`: 102/102 killed, 0 survived; `audit:arrows` 0 violations |
| a revoked credential is denied | met (circuit, registry, client); gateway half P3 | F3.x safety tests; issuer `/path` 410; client refuses |
| the tampered-attribute and self-signed attacks fail | met | v4 negatives; Attack Lab `tamper`, `forged` against the model gateway |

## Verdict

**CONDITIONAL** (G1, P2 lane).

Functional PASS · Tests CONDITIONAL (`qa`) · Floors APPROVE (`safety`) · Operational PASS with the
backup/compose gap carried by condition 1 · Milestone additions all met.

| # | Condition | Owner | Deadline task |
|---|---|---|---|
| 1 | CI pipeline running every suite + `artifacts:check` + `gen-vectors --check`, read by job name; `make test` (SR-17, R-007) | `devops` | G2-S1-DEVOPS-010 (before the G2 gate) |
| 2 | Keys stay DEMO-ONLY until the multi-party phase-2 ceremony; run the full phase-1 verify alongside it and record it in the manifests (SR-06, SR-21, R-009) | `circuits` with the team | G2-S1-CIRC-040 |
| 3 | Gateway obligations 1–8; floor tests F3.09, F4.06, F5.07, F7.05 real and green; production issuer key pinned, never the TEST-ONLY fixture key (SR-05, SR-07, R-008) | `gateway` (P3), `safety` | P3 gate (G2) |
| 4 | qa-owned integration entry point under `tests/integration/` once the gateway exists | `qa` | G2 |

**Carried conditions.** None of these has yet survived two milestones. SR-17 (condition 1) was first
raised at G1-S1-SAFETY-020 within G1; if it is still open at the G2 gate it must be raised to the
user as a carried condition (strategy §5).

**Signers.** Orchestrator — CONDITIONAL. `safety` — APPROVE (`floors.md`). `architect` — contracts
changed in G1 (`credential v4`, `access.public_signals v4`, `issuer.api v2`, `issuer.admin v1.1`), each
recorded contract-first with a change-log row (G1-S1-ARCH-011, G1-S1-IDEN-014); architect sign-off
pending P1/P3 review of those contracts.
