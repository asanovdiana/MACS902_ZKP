# ZK Access Gate — Strategy

The operating model. `docs/plan/README.md` holds current state; this file holds the rules and the
task graph.

## 1. Roles

The Orchestrator plans and dispatches and writes no implementation code. Each role below owns file
paths, exclusively.

## 2. Ownership map

| Role | Owns | Handoff extras |
|---|---|---|
| `architect` | `docs/adr/**` | — |
| `circuits` | `circuits/**` | `CONSTRAINTS:`, `PUBLIC INPUTS:`, `NEGATIVE TESTS:` |
| `identity` | `issuer/**`, `client/**` | `POSEIDON PARAMS:` |
| `gateway` | `gateway/**`, `services/**` | `GATEWAY LOG FIELDS:` |
| `frontend` | `ui/**` | — |
| `devops` | `docker/**`, `keycloak/**`, `.github/**`, `scripts/**`, `compose.yaml`, `Makefile` | `SERVICES:`, `RUNBOOK:` |
| `qa` | `tests/integration/**`, `tests/e2e/**`, `bench/**` | `COVERAGE DELTA:`, `BENCH DELTA:` |
| `safety` | `tests/safety/**`, `docs/security/**` | `FLOOR DELTA:`, `VETO:` |

A task crossing a boundary is split, or routed through `architect`. Ownership globs do not overlap;
`kitgen verify` enforces that.

## 3. Test tiers

| Tier | Floor |
|---|---|
| unit | 80% |
| integration | 70% |
| floor | 95% |

Pragmatic TDD: test-first for logic, contracts, the data layer and anything under a floor;
test-after with fixtures for adapters and glue; e2e for UI. `test(red):` prefixes a failing-test
commit.

## 4. Branching

Trunk-based, one task per branch `task/<TASK-ID>-<slug>`, Conventional Commits. Commits use
`git commit --only <path>`. Parallel dispatch uses worktree isolation.

## 5. Gates

A gate is checked across five dimensions: **Functional**, **Tests**, **Floors**, **Operational**,
and the milestone's own additions. Verdicts: **PASS**, **CONDITIONAL** (each condition carries an
owner and a deadline task ID), **BLOCK**. A failed dimension blocks; no dimension is averaged away.

`safety` produces the Floors dimension and signs it APPROVE or VETO. A VETO is not
overridable by the Orchestrator.

A CONDITIONAL that survives two milestones is itself a finding and must be raised to the user, not
carried silently.

## 6. Floors — never regress

1. every circuit constraint has a negative test that fails when the constraint is removed; every <-- is followed by an === that checks it
2. no valid proof exists for an unsatisfied policy, a tampered attribute, a forged issuer signature, or an expired credential
3. a revoked credential is denied against the current root
4. a replayed proof (used or expired nonce) is denied
5. the same nullifier twice in one epoch is rate-limited; nullifiers from one user to different services are unlinkable
6. private inputs (attributes, issuer signature, Merkle path, user secret) never leave the client; the issuer sees only secret_commitment
7. the gateway log and gateway state hold no username, email, role, department or clearance
8. circuit, issuer and client use identical Poseidon parameters (cross-check test)
9. no plaintext credentials or issuer private keys in the tree
10. tests/safety/** is append-only

Floors are append-only. Removing or weakening one requires an ADR and the user's explicit agreement.

## 7. Observability

Every stage lands with counters, latency metrics and structured logs in the same task that
implements it — never as a follow-up — in paths that task's own role holds per §2. A shared metric
registry or log schema is an interface: record it in `docs/CONTRACTS.md` and ask its owner for
the field, rather than reaching into their tree.

## 8. Contracts

New or changed interfaces are recorded in `docs/CONTRACTS.md` **before** implementation,
with a version and a diff entry.

`docs/CONTRACTS.md` is owned by **no role** in §2, deliberately: contract-first means the
implementing role records the contract before building against it, and the ownership guard allows an
unowned path to any role. "Do not write what you do not own" in `/handoff` means *what another role
owns* — an unowned path crosses nobody's boundary.

## 9. Handoffs

Every task ends with a `/handoff` note. Evidence over prose: the test command and its last line. A
note without a pasted run is not evidence and the Orchestrator re-runs the tests itself.

## 10. Milestones

| ID | Name | Status |
|---|---|---|
| G0 | Foundations: interface contract, toy circuit, Poseidon cross-check | open |
| G1 | End-to-end proof verifies (week-4 critical gate) | open (P2 lane planned) |
| G2 | Full demo runs on make demo | not started |
| G3 | Evaluation, report and delivery | not started |

## 11. Task graph

Task IDs follow `{milestone}-S{sprint}-{OWNER}-{nnn}`. **Only the open milestone is expanded here.** The
Orchestrator expands the next milestone's tasks at gate time; a graph written further ahead than the
work is invented work.

To expand a milestone: copy the `### G0` block's three parts (Entry conditions, Tasks, Gate
additions) above the Later-milestones list, remove its line from that list, and set its §10 Status
to `open`. §10 Status is derived from `docs/plan/README.md`, which is authoritative.

### G0 — Foundations: interface contract, toy circuit, Poseidon cross-check

**Entry conditions**

- [ ] The user has reviewed `docs/project-scope.md`, `docs/technology-explained.md` and this file.
- [ ] The role roster in §2 is accepted.
- [ ] The floors in §6 are accepted.
- [ ] Each M0 row's assigned role owns somewhere its output sensibly belongs. Every row routes its
  write into a path that role already owns, so the ownership guard blocks nothing — but check the
  result reads sensibly: a role whose only paths are documentation has nowhere natural to put a test,
  and that is a sign the ownership map needs adjusting before dispatch rather than after.
- [ ] The team's shared repository is reachable and `gh` is authenticated.

**Tasks**

| ID | Owner | Outputs | Tests | Acceptance |
|---|---|---|---|---|
| G0-S1-ARCH-001 | `architect` | `docs/CONTRACTS.md` first entry; ADR for the module boundaries | contract test skeleton in a path `architect` owns per §2 | Every entry in `docs/CONTRACTS.md` names its consumers and the boundaries match §2. The user's acceptance of the boundaries is a gate question (§5, Functional), not a condition this task can satisfy on its own |
| G0-S1-DEVOPS-002 | `devops` | dev environment reproducible from a clean clone; `make test` runs | one trivial smoke test, in a path `devops` owns per §2 or an unowned path, so the suite is wired | A clean clone reaches a green run in one documented command; exit code 5 from an empty collection is a failure, not a pass |
| G0-S1-SAFETY-003 | `safety` | the floor test tier, in a path `safety` owns per §2, one test per floor in §6; a handoff line asking `devops` to wire it into CI | floor tier green | Each floor in §6 has at least one test that fails when it is violated |
| G0-S1-QA-004 | `qa` | tier thresholds from §3 as config in a path `qa` owns per §2 or an unowned path; a handoff line asking `devops` to enforce them in CI | coverage gate fails below floor | A deliberate coverage drop fails `make test` locally and, once G0-S1-DEVOPS-005 lands, in the pipeline |
| G0-S1-DEVOPS-005 | `devops` | the floor tier (G0-S1-SAFETY-003) and the coverage thresholds (G0-S1-QA-004) wired into `None` | a pipeline run shows both stages | A deliberate floor violation and a deliberate coverage drop each redden the pipeline |
| G0-S1-ARCH-010 | `architect` | ADRs for P2 decisions D1–D3, D6, D7; `credential v3`, `access.public_signals v3`, `issuer.api v1` in `docs/CONTRACTS.md` | n/a | P1 and P3 have seen the contracts |
| G0-S1-CIRC-020 | `circuits` | root `npm test` (mocha + circom_tester) and `circuits/test/v3.test.js` for the imported P1 v3 circuit; circom 2.2.3 toolchain note | positives + negatives for every v3 constraint; tampered-attribute and self-signed-key cases as pending (documented gaps) | negatives fail, positives pass, gaps visible |
| G0-S1-CIRC-021 | `circuits` | `circuits/lib/` v3 profile (commitment, signature over commitment, her `pathIndices` semantics, input builder) + TEST-ONLY vectors | lib reproduces vectors; input accepted by the v3 witness calculator | one encoder for issuer and client (floor 8) |
| G0-S1-CIRC-022 | `circuits` | v3 trusted setup (Hermez ptau, DEV fallback), vkey, manifest, prove/verify scripts | prove + verify on the v3 vector; tampered `root` fails | client can produce a Groth16 proof for v3 |
| G0-S1-IDEN-001 | `identity` | M1 issuer core: persistent issuer key (`issuer/keys/`, gitignored), signs the commitment (v3), credential file format | signature verifies in a script; key stable across restarts; issuer never sees secret/salt | M1 done criterion |
| G0-S1-IDEN-002 | `identity` | M2 registry: `@zk-kit` tree at profile depth, insert on issue, revoke = leaf 0, root/history/path endpoints | root parity with lib/circuit (floor 8); revoked path fails against new root (floor 3) | M2 done criterion (v3) |
| G0-S1-IDEN-003 | `identity` | M4 client CLI v3: keygen (local secret + salt), request, prove | keygen → request → prove → verify against the v3 vkey | M4 done criterion (v3) |
| G0-S1-IDEN-004 | `identity` | HTTP layer for issuer/registry (`issuer.api v1`), logs without secrets, counters | API tests for every route and error case | `issuer.api v1` implemented |

**Gate additions:** the floor tier must be non-empty and green, and every floor in §6 must map to a
named test. P2 lane: issue → register → prove → verify works end to end on the P1 v3 circuit, and a
revoked credential's proof fails against the new root.

### G1 — End-to-end proof verifies (week-4 critical gate)

_P2 lane expanded (identity, plus the circuit features the scope needs on top of the P1 v3 circuit).
Full plan, decisions and gap list: [`docs/plan/p2-plan.md`](plan/p2-plan.md). The earlier circuits-prototype
tasks (G0-S1-CIRC-006, G1-S1-CIRC-001…015) are superseded: the prototype was removed in favour of the
team's P1 circuit (it was the reference implementation and is not included in this repository)._

**Entry conditions**

- [ ] G0 P2-lane gate additions met (end to end on v3).
- [ ] `credential v4` and `access.public_signals v4` recorded in `docs/CONTRACTS.md` and agreed by P1 and P3.

**Tasks**

| ID | Owner | Outputs | Tests | Acceptance |
|---|---|---|---|---|
| G1-S1-ARCH-011 | `architect` | `credential v4` (attrHash = Poseidon(role, dept, clearance, deviceCompliant, employeeActive, expiry, commitment)) and `access.public_signals v4` (12 signals) in CONTRACTS | n/a | P1 and P3 agree |
| G1-S1-CIRC-030 | `circuits` | `MerkleMembership(depth)` parameterised; v3 main still depth 2 | v3 tests stay green; depth 4/16 tests | no behaviour change for v3 |
| G1-S1-CIRC-031 | `circuits` | `components/attribute_hash.circom`: attrHash is the signed message and the leaf; `dept` added | tampered attribute with original signature rejected | closes gap G-1 (floor 2) |
| G1-S1-CIRC-032 | `circuits` | issuer key public; on-curve checks for `R8` and the issuer key | self-signed credential rejected under the pinned key; off-curve rejected | closes G-2 (floor 2) |
| G1-S1-CIRC-033 | `circuits` | generic `AccessPolicy` with public masks/min clearance/require device, range checks, `employeeActive === 1` | one negative per constraint; three demo policies as positives | closes G-3, G-8 (floor 2) |
| G1-S1-CIRC-034 | `circuits` | `expiry` attribute, public `now`, 64-bit range-checked `expiry > now` | equal/older/out-of-range rejected | closes G-4 (floor 2) |
| G1-S1-CIRC-035 | `circuits` | public `nonce`, `resourceId`, `epoch`; `nullifier = Poseidon(credentialSecret, resourceId, epoch)` | binding and unlinkability tests | closes G-6 (floors 4, 5 circuit side) |
| G1-S1-CIRC-036 | `circuits` | `circuits/integrated_access_v4.circom` (depth 16; 8/20 for benchmarks); signal-order test; mutation harness + `<--` audit | negative per constraint; 0 mutation survivors | floor 1; closes G-5 |
| G1-S1-CIRC-037 | `circuits` | v4 setup, committed depth-16 zkey/wasm + vkey + manifest; valid and attack fixtures; `verify.js` with canonical-signal check | fixtures verify; tampered signal fails | P3 can test the gateway against fixtures |
| G1-S1-CIRC-038 | `circuits` | `circuits/lib` v4 profile: attrHash, enums, policies, input builder, 12-signal codec, local policy pre-check | reproduces v4 vectors; input accepted by the v4 witness calculator | one encoder for v4 (floor 8) |
| G1-S1-IDEN-010 | `identity` | issuer v4: signs attrHash with expiry; attributes validated against enums | signature verifies; issuer receives only the commitment (floor 6) | M1 on v4 |
| G1-S1-IDEN-011 | `identity` | registry v4: depth 16, v4 leaves, revocation, root history | root parity; revoked denied against the current root (floor 3) | M2 on v4 |
| G1-S1-IDEN-012 | `identity` | client v4: challenge fetch, local policy pre-check with reason, prove, submit; library API for the UI | e2e v4 proof verifies; Bob → Admin Panel refused locally | M4 on v4 |
| G1-S1-IDEN-013 | `identity` | Poseidon cross-check suite across issuer, registry, client and circuit | one test per shared value | floor 8 |
| G1-S1-SAFETY-020 | `safety` | review of v4 circuit, lib and identity code against floors 1–8 | floor tier green | APPROVE or VETO recorded |

**Gate additions:** an end-to-end v4 Groth16 proof from an issued credential verifies; every v4
constraint has a killing negative test (0 mutation survivors); a revoked credential is denied; the
tampered-attribute and self-signed attacks fail.

### Later milestones (outline only, not yet scoped)

- G2 — Full demo runs on make demo
- G3 — Evaluation, report and delivery
