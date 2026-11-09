# P2 plan: identity on top of the team's P1 circuit

**Owner.** P2 (identity). **Status.** Planned 2026-11-08, not started. **Base.** The P1 circuit
imported from the teammate's branch `feature/p1-circuits-hamsa`.

P2 is the scope's **M1 issuer, M2 registry + revocation, M4 client prover**. By team decision, P2
also builds the circuit features the scope needs that P1's v3 does not have yet, **on top of her
code and in her style**, using the earlier circuits prototype as the reference implementation
(removed; not included in this repository).

This file is the plan of record for P2. Task rows also appear in `docs/strategy.md` §11, and
progress is tracked in `docs/plan/README.md`.

---

## 1. Starting point: what P1 v3 does today

Measured on 2026-11-08 with circom 2.2.3 against the imported files.

| | v3 (as imported) |
|---|---|
| Main | `circuits/integrated_access_v3.circom`, template `IntegratedAccessGate()` |
| Size | 8116 non-linear + 1529 linear constraints (circom default `--O1`) |
| Commitment | `credentialCommitment = Poseidon(credentialSecret, credentialSalt)` |
| Signature | circomlib `EdDSAPoseidonVerifier` over `M`, with `M === credentialCommitment` |
| Merkle | binary Poseidon(2) tree, **depth 2**; `leaf === credentialCommitment`; `pathIndices[i] = 1` means the current node is the **right** child; indices are boolean-constrained |
| Policy | `FileShareAccess` hard-coded: `role ∈ {2,3}`, `clearance ∈ {2,3}`, `deviceCompliant = 1`, `employeeActive = 1` |
| Public signals | `[root]` only |
| Private inputs | `credentialSecret, credentialSalt, role, clearance, deviceCompliant, employeeActive, Ax, Ay, R8x, R8y, S, M, leaf, pathElements[2], pathIndices[2]` |
| Input generator | `scripts/generate_integrated_v3.js`: random secret/salt, **random issuer key per run**, 2-level tree with fixed siblings, writes `tests/integrated_v3_valid.json` (gitignored, mode 0600) |
| Tests | none |
| Toolchain | `pragma circom 2.2.3` (does not compile on 2.2.2); includes via `../node_modules/circomlib`, so `npm ci` at the repo root is required |

Verified behaviour (scratch run, nothing committed):

- her generated input produces a witness;
- `role = 1` is rejected by `FileShareAccess` (assert failed);
- **changing `role`/`clearance` while keeping the same signature still produces a witness.**

### Gaps against the scope (each one is a P2 task below)

| # | Gap | Consequence | Scope ref | Fixed by |
|---|---|---|---|---|
| G-1 | Attributes are not in the signed message or the leaf | Any credential holder can claim any role/clearance (floor 2 fails) | M1, M3.2 | G1-S1-CIRC-031 |
| G-2 | Issuer key `Ax, Ay` is a private input | A self-signed credential verifies; the gateway cannot pin the issuer | M3.2 | G1-S1-CIRC-032 |
| G-3 | Policy hard-coded to File Share | One circuit and key set per service instead of one generic circuit | M3.4, M5 | G1-S1-CIRC-033 |
| G-4 | No `expiry` / `now` | Expired credentials keep working (floor 2) | M1, M3.4 | G1-S1-CIRC-034 |
| G-5 | Depth 2 | 4 users maximum | Core concepts (depth 16) | G1-S1-CIRC-035 |
| G-6 | No `nonce`, `resource_id`, `epoch`, nullifier | Replay possible, no rate limiting (floors 4, 5) | M3.5–6 | G1-S1-CIRC-036 |
| G-7 | No `dept` attribute | Scope policies can't use department | M1 | G1-S1-CIRC-031 |
| G-8 | No range checks on attributes | Out-of-range values could satisfy a future comparator | M3.4 | G1-S1-CIRC-033/034 |
| G-9 | No tests, broken fragment `components/integrated_access.circom` | Floor 1 unprovable; fragment fails to compile | Testing row | G0-S1-CIRC-020 |
| G-10 | Random issuer key per generator run | No stable issuer identity for the registry/gateway | M1 | G0-S1-IDEN-001 |

---

## 2. Principles

1. **Her code stays the base.** Imported files are not rewritten in place. New behaviour goes in new
   components next to hers (`circuits/components/*.circom`) and a new main
   `circuits/integrated_access_v4.circom`. v3 stays compilable until v4 passes its gate, so the
   team can compare. Changes to her files (for example making `MerkleMembership` take a depth) are
   small and reviewed by her. (Which branch the work lands on does not matter; it is integrated
   here.)
2. **Contract first.** Every interface change is a versioned entry in `docs/CONTRACTS.md` before
   code: `credential v3` → `v4`, `access.public_signals v3` → `v4`.
3. **One encoder.** Issuer, registry and client import the same JS encoding library, so Poseidon
   parameters, field encoding and signal order cannot drift (floor 8, scope risk "Poseidon
   mismatch").
4. **Profiles, not forks.** Identity code takes a *circuit profile* (`v3` or `v4`: depth,
   message layout, public-signal order, artefact paths). Moving from v3 to v4 is a profile switch
   plus tests, not a rewrite.
5. **Reference, not copy-paste.** The removed prototype shows a working design for each gap
   (tests, mutation harness, setup, verifier). Port the ideas into her structure; every ported
   piece gets its own tests here.
6. **Test-first, negative-heavy.** Every new constraint lands with a negative test; floor 1 is
   enforced by a mutation run before G1 closes.

---

## 3. Decisions (to record as ADRs before G0 work starts)

| ID | Decision | Recommendation | Why |
|---|---|---|---|
| D1 | Runtime for issuer + registry | **Decided (team accepted 2026-11-08): Node (CommonJS, like P1)**, small HTTP service (Fastify or Express) | EdDSA-Poseidon signing and the Poseidon tree only exist reliably in `circomlibjs` / `@zk-kit`; a Python issuer would need a second Poseidon/BabyJubJub implementation (scope risk: Poseidon mismatch). The gateway (P3) can stay FastAPI. |
| D2 | Where the shared encoder lives | `circuits/lib/` (P2 builds it; P1 reviews) | Issuer, client and gateway decoding all need it; it describes the circuit's interface. |
| D3 | Commitment | Keep hers: `Poseidon(credentialSecret, credentialSalt)` | No reason to change; the salt is harmless and her tests/inputs keep working. Nullifier uses `credentialSecret`. |
| D4 | v4 attribute hash | `attrHash = Poseidon(role, dept, clearance, deviceCompliant, employeeActive, expiry, credentialCommitment)` (7 inputs); signed message `M` and Merkle leaf are both `attrHash` | Closes G-1/G-7; keeps her `employeeActive` attribute. |
| D5 | v4 public signals (order) | `[nullifier, root, issuerAx, issuerAy, roleMask, deptMask, minClearance, requireDevice, now, nonce, resourceId, epoch]` | Same order the prototype used, so the gateway's design (P3) carries over. **Decided 2026-11-08:** `employeeActive` stays an always-required attribute (`employeeActive === 1`), as in her policy, not a policy field. |
| D6 | Role / dept encoding | **Decided:** `role` engineer 0, admin 1, contractor 2, finance 3 (scope order); `dept` 0–3 (engineering, it, operations, finance); one enum table in `circuits/lib` and the contract | v3's hard-coded File Share values (`role ∈ {2,3}`) are ignored: v4 replaces that template with the generic policy (G1-S1-CIRC-033). |
| D7 | Proving artefacts | Commit the v4 depth-16 `.zkey`/`.wasm` with matching vkey/manifest (DEV keys until the team ceremony) | Offline `make demo`; the client can prove from a clone. |

---

## 4. Target architecture for P2

```
client/  (P2, Node)                     issuer/  (P2, Node)
  cli.js        keygen | request |        server.js    POST /credentials   (commitment + attributes)
                prove | submit                         POST /revoke/:id
  lib/          wallet (secret, salt,                  GET  /root, /root/history
                credential file),                      GET  /path/:leafIndex
                challenge client,         registry.js  @zk-kit tree, depth from profile,
                prover (snarkjs)                       revoke = update(index, 0)
                                          keys/        issuer EdDSA key (gitignored, generated)
            \                             /
             circuits/lib  (shared encoder: commitment, attrHash, enums,
                            input builder, public-signal codec, profiles v3/v4)
             circuits/     (P1 v3 + P2's v4 components and main)
```

Data that leaves the user's machine: `credentialCommitment` + attributes to the issuer at
enrolment (the scope's model: the issuer assigns attributes), then only the proof and public
signals to the gateway. **Never** `credentialSecret`, `credentialSalt`, the signature or the Merkle
path (floor 6).

**Issuer API (contract `issuer.api v1`, recorded in G0-S1-ARCH-010):**

| Method | Path | Body / result |
|---|---|---|
| POST | `/credentials` | `{commitment, attributes}` → `{credential: {attributes, signature:{R8x,R8y,S}, issuer:{Ax,Ay}, leafIndex, profile}}` |
| POST | `/credentials/:leafIndex/revoke` | → `{root}` |
| GET | `/root` | `{root, updatedAt}` |
| GET | `/root/history?since=` | recent roots (for the 30 s staleness window) |
| GET | `/path/:leafIndex` | `{pathElements, pathIndices, root}` |

**Credential file (client side, `client/` wallet, never committed):** profile, attributes, issuer
key, signature, leafIndex, plus `credentialSecret`/`credentialSalt` kept locally with mode 0600.

---

## 5. Task graph

Owners are kit roles (path owners): `circuits` = `circuits/**`, `identity` = `issuer/**`,
`client/**`, `architect` = `docs/adr/**`, `safety` = `tests/safety/**`, `docs/security/**`,
`devops` = `scripts/**` and packaging. All P2 work is done by P2 regardless of role, except the
review asks marked **P1** (her) and **P3** (gateway).

### G0: Foundations on v3 (end to end on her circuit)

| ID | Owner | Outputs | Tests | Acceptance | Depends |
|---|---|---|---|---|---|
| G0-S1-ARCH-010 | `architect` | ADRs for D1–D3, D6, D7; `docs/CONTRACTS.md`: `credential v3`, `access.public_signals v3` (current, describing her circuit), `issuer.api v1` | n/a | P1 and P3 have seen the contracts | — |
| G0-S1-CIRC-020 | `circuits` | Root `npm test` (mocha + circom_tester); `circuits/test/v3.test.js`; toolchain note (circom 2.2.3); fragment excluded from builds, removal requested from P1 | positives from a fixed TEST-ONLY input; negatives: wrong secret/salt, tampered `S`/`R8`, wrong root, non-boolean `pathIndices`, role outside {2,3}, clearance outside {2,3}, device 0, inactive 0; **documented-gap tests** marked pending: tampered attribute, self-signed key | every negative fails, every positive passes; gaps G-1/G-2 visible as pending tests | — |
| G0-S1-CIRC-021 | `circuits` | `circuits/lib/` v3 profile: commitment, signature over commitment, tree helpers matching her `pathIndices` semantics, input builder, `[root]` codec; reference vectors `circuits/test/vectors/v3/` from fixed TEST-ONLY seeds | lib reproduces vectors; built input accepted by the v3 witness calculator | issuer and client can build inputs without guessing (floor 8 base) | 020 |
| G0-S1-CIRC-022 | `circuits` | v3 setup: Powers of Tau (Hermez, DEV fallback), `groth16 setup`, vkey, manifest; prove/verify scripts | full prove + verify on the v3 vector; tampered `root` fails verify | client can produce a Groth16 proof for v3 | 020 |
| G0-S1-IDEN-001 | `identity` | **M1** issuer core: persistent issuer key (generated once into `issuer/keys/`, gitignored), sign commitment (v3), credential file format | signature verifies in a script (M1 done); same key across restarts; issuer never receives secret/salt | M1 done criterion | 021 |
| G0-S1-IDEN-002 | `identity` | **M2** registry: `@zk-kit` tree with profile depth (2 for v3), insert on issue, revoke = set leaf 0, `GET /root`, `/root/history`, `/path/:i` | root equals the lib/circuit root for the same leaves (floor 8); revoked leaf's old path fails against new root (floor 3) | M2 done criterion (on v3) | 021 |
| G0-S1-IDEN-003 | `identity` | **M4** client CLI v3: `keygen` (secret + salt, local, 0600), `request` (sends commitment + attributes), `prove` (fetch path, build input, snarkjs `fullProve`) | e2e: keygen → request → prove → verify against v3 vkey | M4 done criterion (on v3) | 001, 002, 022 |
| G0-S1-IDEN-004 | `identity` | HTTP layer for issuer/registry (D1), config, structured logs (no secrets), counters | API tests for every route; error cases (bad commitment, unknown index, double revoke) | `issuer.api v1` implemented | 001, 002 |

**G0 gate additions:** issue → register → prove → verify works on v3; revoke → proof against the new
root fails; documented gaps G-1/G-2 visible as pending tests.

### G1: Circuit to scope (v4) and identity on v4 (week-4 critical gate)

| ID | Owner | Outputs | Tests | Acceptance | Depends |
|---|---|---|---|---|---|
| G1-S1-ARCH-011 | `architect` | `credential v4` (D4) and `access.public_signals v4` (D5) in CONTRACTS, before code | n/a | P1 and P3 agree | G0 |
| G1-S1-CIRC-030 | `circuits` | `MerkleMembership(depth)` parameterised in her component, v3 main still instantiates depth 2 | existing v3 tests stay green; depth 4/16 tests | no behaviour change for v3 | 011 |
| G1-S1-CIRC-031 | `circuits` | `components/attribute_hash.circom` (D4): `attrHash` = signed `M` = leaf; `dept` added | tampered attribute with original signature rejected (closes G-1); vector parity with lib | floor 2 (tampered attribute) | 030 |
| G1-S1-CIRC-032 | `circuits` | issuer key as public input; on-curve checks for `R8` and issuer key | forged self-signed credential rejected under the pinned key; off-curve points rejected (closes G-2) | floor 2 (forged signature) | 031 |
| G1-S1-CIRC-033 | `circuits` | `components/access_policy.circom`: generic `AccessPolicy` with public `roleMask`, `deptMask`, `minClearance`, `requireDevice`; range checks; `employeeActive === 1`; her `FileShareAccess` kept for v3 | one negative per constraint; the three demo policies as positives | floor 2 (unsatisfied policy), closes G-3, G-8 | 031 |
| G1-S1-CIRC-034 | `circuits` | `expiry` attribute + public `now`, 64-bit range-checked `expiry > now` | `expiry == now`, `expiry < now`, out-of-range rejected | floor 2 (expired), closes G-4 | 031 |
| G1-S1-CIRC-035 | `circuits` | `components/challenge_binding.circom`: public `nonce`, `resourceId`, `epoch`; output `nullifier = Poseidon(credentialSecret, resourceId, epoch)` | binding tests; unlinkability (different resource → different nullifier) | floors 4, 5 (circuit side), closes G-6 | 031 |
| G1-S1-CIRC-036 | `circuits` | `circuits/integrated_access_v4.circom` (depth 16; 8/20 mains for benchmarks); public-signal order test; mutation harness + `<--` audit ported from the prototype | negative per constraint; mutation run: 0 survivors | floor 1; G-5 closed | 032–035 |
| G1-S1-CIRC-037 | `circuits` | v4 setup, committed depth-16 `.zkey`/`.wasm` + vkey + manifest (D7); fixtures (4 valid + attack set: stale root, forged issuer, old `now`, same-epoch nullifier, replay); `verify.js` with canonical-signal check | fixtures verify; tampered public signal fails | gateway (P3) can test against fixtures | 036 |
| G1-S1-CIRC-038 | `circuits` | `circuits/lib` v4 profile (attrHash, enums from D6, policies, input builder, 12-signal codec, local policy pre-check) | reproduces v4 vectors; input accepted by v4 witness calculator | one encoder for v4 (floor 8) | 031–035 |
| G1-S1-IDEN-010 | `identity` | issuer v4: signs `attrHash` with expiry; admin-assigned attributes validated against enums | signature verifies under v4; issuer receives only the commitment (floor 6) | M1 on v4 | 038 |
| G1-S1-IDEN-011 | `identity` | registry v4: depth 16, v4 leaves, revocation, root history | root parity with lib/circuit; revoked denied against current root (floor 3) | M2 on v4 | 038 |
| G1-S1-IDEN-012 | `identity` | client v4: challenge fetch (nonce, resourceId, epoch, policy, `now`), local policy pre-check with reason, prove, submit; library API reused by the UI | e2e v4 proof verifies with `verify.js`; Bob → Admin Panel refused locally with reason | M4 on v4 | 037, 010, 011 |
| G1-S1-IDEN-013 | `identity` | Poseidon cross-check suite: issuer, registry, client and circuit agree on commitment, attrHash, root, nullifier | one test per value | floor 8 | 010–012 |
| G1-S1-SAFETY-020 | `safety` | review of v4 circuit, lib and identity code against floors 1–8; floor tests for the identity side | floor tier green | VETO or APPROVE recorded | 036, 013 |

**G1 gate additions:** an end-to-end v4 Groth16 proof from an issued credential verifies; every v4
constraint has a killing negative test (0 mutation survivors); a revoked credential is denied; the
tampered-attribute and self-signed attacks fail.

### G2: Demo support

| ID | Owner | Outputs | Acceptance |
|---|---|---|---|
| G2-S1-IDEN-020 | `identity` | Admin API for the Admin Console: list (issuer side), issue, revoke, root-change events (WebSocket or SSE contract for `frontend`) | Admin Console can issue/revoke live and see the root change |
| G2-S1-IDEN-021 | `identity` | Attack scripts for the Attack Lab (scope: P2 "also helps with"): replay, revoked user, tampered attribute, forged credential, wrong service, spam, expired | each produces the request the gateway must deny, with the expected reason |
| G2-S1-IDEN-022 | `identity` | Personas Alice/Bob/Carol seeded by a script; Dockerfiles for issuer and client (packaging owned by `devops`) | `make demo` (devops) can start issuer with personas |
| G2-S1-CIRC-040 | `circuits` | Multi-party phase-2 ceremony with P1 and P3; commit ceremony keys + regenerated fixtures in one commit | DEV-ONLY keys replaced |

### G3: Evaluation and report

| ID | Owner | Outputs |
|---|---|---|
| G3-S1-IDEN-030 | `identity` | Client-side measurements for M8 (witness, prove time per depth 8/16/20) handed to `qa`'s `bench/` |
| G3-S1-IDEN-031 | `identity` | Report sections: issuer, registry and revocation, client prover; threat-model input for malicious issuer and malicious user |

---

## 6. Order of work and critical path

```
ARCH-010 ─┬─ CIRC-020 ─┬─ CIRC-021 ─┬─ IDEN-001 ─┬─ IDEN-004
          │            │            ├─ IDEN-002 ─┤
          │            └─ CIRC-022 ─┴────────────┴─ IDEN-003   (G0 gate: e2e on v3)
          └─ ARCH-011 ─ CIRC-030 ─ CIRC-031 ─┬─ 032 ─┐
                                             ├─ 033 ─┼─ CIRC-036 ─ CIRC-037 ─┐
                                             ├─ 034 ─┤                       ├─ IDEN-012 ─ IDEN-013 ─ SAFETY-020
                                             └─ 035 ─┘   CIRC-038 ─ IDEN-010/011 ─┘         (G1 gate)
```

The **critical path** is CIRC-031 → 036 → 037 → IDEN-012: the scope's week-4 gate needs an
end-to-end proof. If it slips, the scope's fallback applies: cut nullifier and expiry
(CIRC-034/035) and keep signature + membership + policy.

Parallelism: CIRC-032/033/034/035 are independent components after 031; IDEN-001/002 run
alongside CIRC-022; IDEN-010/011 start as soon as CIRC-038 lands.

---

## 7. Coordination

| With | What | When |
|---|---|---|
| P1 (her) | removing the broken fragment; reviewing every circuit change (the scope requires a second reviewer) | before G0-S1-CIRC-020, then per change |
| P3 (gateway) | `access.public_signals v4` order and gateway checks (pin issuer key, `now` vs clock, root freshness, nonce, nullifier per epoch, canonical integers for state keys); fixtures | at G1-S1-ARCH-011 and CIRC-037 |
| Frontend / demo | Admin API + events; client library API for the User Portal | G2 |
| DevOps | root `npm test` in CI; Docker images; `make demo` | G0 end, G2 |

---

## 8. Risks

| Risk | Sign | Mitigation |
|---|---|---|
| v4 changes collide with P1's ongoing work | conflicting edits to her files | new files beside hers; small, separate commits for edits to hers; she reviews |
| Poseidon / encoding drift between issuer, client, circuit | valid credential fails to prove | single encoder (D2), cross-check suite (IDEN-013), vectors |
| Circuit not end to end by week 4 | CIRC-036 not green | scope fallback (cut nullifier + expiry); v3 e2e from G0 remains as a demoable baseline |
| Issuer key leaks into the repo | secret scanner / review | `issuer/keys/**` is gitignored and on the kit's secrets deny list (floor 9) |
| Toolchain version skew (circom 2.2.3) | compile errors on teammates' machines | pin in README and CI; check `circom --version` in the test setup |

---

## 9. Open questions

None. Resolved 2026-11-08:

- Role/dept encoding is ours to set (D6); v3's File Share values are ignored.
- The target branch does not matter; work is integrated here.
- `employeeActive` stays an always-required attribute (D5).
- Issuer and registry run on Node (D1), accepted by the team; the gateway may stay FastAPI.
