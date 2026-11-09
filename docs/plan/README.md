# Dispatch State

**Owner.** Orchestrator. **Updated.** After every task completion and every gate.

Source of truth for "what is next". Subagents never edit this file; they emit handoff notes and the
Orchestrator updates here.

---

## Current milestone

**G0 — Foundations**, P2 lane (identity, on top of the team's P1 v3 circuit). Other lanes belong to
other team members. Plan of record: [`p2-plan.md`](p2-plan.md).

## Next task

P2 G1 work complete; **G1 gate (P2 lane) CONDITIONAL** — see Open gates. Remaining P2 work needs the team or other lanes: G2-S1-CIRC-040 multi-party phase-2 ceremony; P3 gateway; devops CI/Makefile/compose.

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
  Floors APPROVE ([`floors.md`](../gates/G1/floors.md)). Conditions: G2-S1-DEVOPS-010 (CI, `devops`),
  G2-S1-CIRC-040 (ceremony, team), P3 gate (gateway obligations), `qa` integration entry point.
