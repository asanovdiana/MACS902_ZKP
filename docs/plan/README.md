# Dispatch State

**Owner.** Orchestrator. **Updated.** After every task completion and every gate.

Source of truth for "what is next". Subagents never edit this file; they emit handoff notes and the
Orchestrator updates here.

---

## Current milestone

**G2 — Integration and hand-in readiness** (all lanes now in this repository: P1 circuits, P2
identity, P3 gateway + demo under `p3/`). Plan of record for P2: [`p2-plan.md`](p2-plan.md).

## Next task

No engineering task open. G1's four conditions are met (see Open gates). What remains is human work
that no agent can do: the demo video, presentation slides, two rehearsals of the live demo script,
P1's own sign-off on the v4 second review, and — before any real use — a phase-2 ceremony with the
team members contributing on their own machines (the one run here was simulated).

## Active

| Task | Owner | Dispatched | Worktree |
|---|---|---|---|

## Completed

_Rows for the milestone just closed are moved to `docs/plan/archive/<id>.md`
at its gate, leaving one pointer line here. This file is read **in full** at the start of every session
(`load_order`), so an unarchived plan is a cost paid on every prompt for work that finished months ago._

- Circuits prototype (superseded, removed 2026-11-08): [`archive/circuits-prototype.md`](archive/circuits-prototype.md).

| Task | Owner | Branch | Evidence | Completed |
|---|---|---|---|---|
| G2-S1-CIRC-040 | `circuits` (P1/P2/P3 roles played by separate agents) | `task/G2-S1-FINAL-001-submission-readiness` | v4 phase 2 re-keyed: 3 contributions + drand mainnet round 6667474 beacon announced in advance (`docs/ceremony/v4-ceremony-log.md`); each hand-off verified, both final checks OK; manifest `DEMO-ONLY`. **Simulated on one machine**: the multi-party trust guarantee does not hold. Installed in `9d516a9` after fix `7b4248b` (`buildManifest` idempotent); safety F9.12 superseded by F9.13 (`efa64ce`). After install: circuits 907 passing, `artifacts:check` 8/8, vectors up to date, issuer 174 + 1 pending, client 87/87, attacks 27/27, p3 131 pass / 15 skipped, safety 83 pass / 0 fail / 2 todo (agent + Orchestrator). | 2026-11-23 |
| G2-S1-SAFETY-023 | `safety` | same | F3.09, F4.06, F5.07, F7.05 todo → real against the real v4 gateway (`GET /challenge`, `POST /access`, built-in `integrated-access-v4` profile); safety tier 84/84, 0 todo at merge; after the ceremony 85 tests, 83 pass, 0 fail, 2 todo = F9.06/F9.12 superseded by F9.12/F9.13 (Orchestrator) | 2026-11-23 |
| G2-S1-DEVOPS-010 | `devops` | same | root `Makefile` (`make test`/`lint`/`types`/`demo`/`ci`), `.github/workflows/ci.yml` (jobs circuits, identity, safety, p3); `make test` exit 0 locally (agent). <!-- CI-RUN --> | 2026-11-23 |
| G2-S1-GW-030 | `gateway` | same | `replay_expired` 125 s step now runs against the real gateway (offset clock, real proofs, no skips): team e2e 9/9 (Orchestrator). Live Keycloak login inside Docker: `p3/scripts/sso-live-check.sh` all steps pass (Orchestrator) | 2026-11-23 |
| G2-S1-CIRC-042 | `circuits` | same | second review of v4: APPROVE WITH NITS, no soundness bug (`docs/reviews/v4-circuit-review.md`; P1 sign-off pending). Broken `integrated_access.circom` fragment removed; arrow audit 25 files, 0 violations | 2026-11-23 |
| G2-S1-ARCH-020 | `architect` | same | report: front page, gateway and demo chapter, privacy comparison (`docs/report/README.md`) | 2026-11-23 |
| P3 lane (M5–M7) | P3 (mrcyber-ops) | PR #1, PR #3 | gateway, services, demo UI, Keycloak baseline, Docker; p3 checks + 131 tests pass (Orchestrator, PR #3 review) | 2026-11-18 |
| G2-S1-CIRC-040a | `circuits` | development branch | re-keyed v3+v4 on PSE ppot (prepared from 0080; Hermez no longer downloadable); `artifacts:check` 8/8, setup/fixtures/verifier 111 passing (Orchestrator); `zkey verify` OK (safety) | 2026-11-08 |
| G1-S1-IDEN-016 | `identity` | development branch | fixed-clock time bomb removed; `test:all` exit 0 (Orchestrator) | 2026-11-08 |
| G1-S1-CIRC-041 | `circuits` | development branch | circuits README refreshed; 44 links / 0 broken (Orchestrator) | 2026-11-08 |
| G1-S1-IDEN-015 | `identity` | development branch | SR-20 fixed; issuer 174 passing (Orchestrator); root README rewritten, quick start run end to end by the agent (issue → seed → prove → verify OK; Bob refused) | 2026-11-08 |
| G1-S1-IDEN-014 + G1-S1-SAFETY-021 (merged together) | `identity`, `safety` | development branch | SR-03 (HIGH) closed: admin-approved enrolment, `issuer.api v2`; SR-04/09/10 closed. Integrated `test:all` exit 0 (Orchestrator): circuits 866, issuer 173+1 pending, client 87/87, attacks 27/27, safety 76 pass / 0 fail / 4 todo (gateway-pending). **Floors: APPROVE (re-signed).** | 2026-11-08 |
| G1-S1-CIRC-039 | `circuits` | development branch | SR-11/13/18 closed; mutation 102/102; R1CS hashes unchanged; v4 + harness 177 passing (Orchestrator) | 2026-11-08 |
| G1-S1-SAFETY-020 | `safety` | development branch | `tests/safety` 74 tests: 68 pass, 6 todo, 0 fail (Orchestrator). **Floors: APPROVE with follow-ups** (SR-03 before G2; SR-04; SR-05/SR-07 at P3). Review `docs/security/review-G1-P2.md`. | 2026-11-08 |
| G2-S1-IDEN-021 | `identity` | development branch | attack suite 26/26 (Orchestrator); reason codes proposed for P3 | 2026-11-08 |
| G3-S1-IDEN-031 | `identity` | development branch | docs; numbers sourced; 0 broken links | 2026-11-08 |
| G1-S1-IDEN-012 | `identity` | development branch | client 79/79 (Orchestrator), v4 e2e against real issuer | 2026-11-08 |
| G1-S1-IDEN-013 | `identity` | development branch | cross-check suite 8 passing, 263 values (Orchestrator) — floor 8 | 2026-11-08 |
| G1-S1-CIRC-037 | `circuits` | development branch | `artifacts:check:v4` OK; setup_v4 + fixtures_v4 + fast_verify 87 passing (Orchestrator); root suite 859 (agent). Prove 942 ms median, fast verify 5.61 ms median. | 2026-11-08 |
| G1-S1-CIRC-036 | `circuits` | development branch | v4 + harness 170 passing (Orchestrator); report 95/95 killed, 0 survived; `audit:arrows` 0 violations; d16 O2 9208 constraints; root suite 772 (agent). Safety: 7 redundant-but-killed mutants to confirm. | 2026-11-08 |
| G2-S1-IDEN-020 + 022 (issuer side) | `identity` | development branch | issuer suite 115 passing, 1 pending (Orchestrator); `issuer.admin v1` + `issuer.api v1.1` contracts | 2026-11-08 |
| G0-S1-IDEN-003 (G1-S1-IDEN-012 partial) | `identity` | development branch | `npm test --prefix client` 57 pass + 1 todo (v4 proving awaits CIRC-037) (Orchestrator); c8 94% lines. Safety review requested (floors 2, 3, 6). | 2026-11-08 |
| G0-S1-CIRC-021 + G1-S1-CIRC-038 | `circuits` | development branch | lib.test.js 115 passing; root suite 263 (Orchestrator); vectors up to date; c8 lib 99% lines | 2026-11-08 |
| G1-S1-CIRC-035 | `circuits` | development branch | challenge_binding.test.js 28 passing (Orchestrator); sweep 10/10 | 2026-11-08 |
| G1-S1-CIRC-033 + 034 | `circuits` | development branch | policy_v4 + expiry 104 passing (Orchestrator); sweep 25/25 | 2026-11-08 |
| G0-S1-IDEN-001 + 002 + 004, G1-S1-IDEN-010 + 011 | `identity` | development branch | `npm test --prefix issuer` 94 passing, 1 pending (Orchestrator); c8 99% lines; v3 witness from API-issued credential OK. Safety review requested (floors 3, 6, 8, 9). | 2026-11-08 |
| G1-S1-CIRC-030 + 031 + 032 | `circuits` | development branch | root suite 602 passing (Orchestrator); sweep 25/25; MerkleMembershipN(2) R1CS-identical to her template | 2026-11-08 |
| G0-S1-ARCH-010 + G1-S1-ARCH-011 | `architect` | development branch | ADRs 0002–0009; contracts credential v3/v4, access.public_signals v3/v4, issuer.api v1, credential.file v1; zk-kit 1.1.0 pathIndices convention matches v3 (checked). P1/P3 review pending. | 2026-11-08 |
| G0-S1-CIRC-022 | `circuits` | development branch | setup.test.js 16 passing, `artifacts:check` OK (Orchestrator). v3 DEV keys committed (4935 constraints at --O2). | 2026-11-08 |
| G0-S1-CIRC-020 | `circuits` | development branch | root `npm test` 148 passing incl. setup (Orchestrator). 2 equivalent mutants (redundant booleans in her main) → safety/P1. GAP G-1/G-2 asserted as current behaviour. | 2026-11-08 |

## Blocked

| Task | Owner | Blocked on | Since |
|---|---|---|---|

## Gate evidence

**G0, P2 lane — met 2026-11-08** (Orchestrator run, real services, a throwaway script not kept in the repo): v3 issuer started;
client `keygen → request → prove`; `circuits/scripts/verify.sh` → OK; revoke leaf 0 → root changes; client
`prove` refused with `revoked (HTTP 410)`; `/path` for the revoked leaf → 410; the old proof still verifies
cryptographically but carries the superseded root (gateway root check, floor 3); issuer log has 0 secret/attribute
matches. Formal G0 gate check (all lanes, `safety` floors) not run: other lanes are not in this repo.

**Integrated run (Orchestrator):** `npm run test:all` exit 0 — circuits 859 passing; issuer 123 + 1 pending;
client 79/79; attacks 26/26. Safety tier 74 (68 pass, 6 todo) added after.

## Open gates

- **G1 (P2 lane): CONDITIONAL**, 2026-11-08 — [`docs/gates/G1/summary.md`](../gates/G1/summary.md).
  Floors APPROVE ([`floors.md`](../gates/G1/floors.md)). Conditions, as of 2026-11-23:
  G2-S1-DEVOPS-010 (CI) — done, see Completed; G2-S1-CIRC-040 (ceremony) — done as a **simulated**
  ceremony (keys DEMO-ONLY); P3 gateway obligations — implemented, gateway floor tests real and green;
  `qa` integration entry point — `make test`. A formal `/gate-check` with `safety` sign-off has not been
  run; that is the step that would close G1.
- Second-reviewer sign-off on v4 by P1 (the review in `docs/reviews/v4-circuit-review.md` was done by
  an agent on P1's behalf).
