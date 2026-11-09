# Safety review G1 — P2 lane (circuit v4, shared lib, issuer/registry, client)

**Task.** G1-S1-SAFETY-020. **Reviewer.** `safety`. **Date.** 2026-11-08.
**Base.** the development branch after G1-S1-CIRC-037 (includes the IDEN-013 cross-check).
**Scope.** Floors 1-9 against `circuits/integrated_access_v4.circom` and `circuits/components/**`,
`circuits/lib/**`, `circuits/scripts/{verify,fast-verify,setup,prove,artifacts,access-fixtures,mutate}`,
`circuits/reports/mutation-v4.md`, `circuits/fixtures/v4/**`, `circuits/setup/*.manifest.json`,
`issuer/src/**`, `client/src/**`, `.gitignore` files. Floor 10 is the new tier itself.
**Out of scope / not in the repository.** The gateway (P3): obligations 1-8 of
`access.public_signals v4`. Every floor whose enforcement point is the gateway is reviewed here
only for its circuit, issuer and client half, and the gateway half is marked **P3-pending**.

**Floor tier.** `tests/safety/` (74 tests: 68 pass, 6 todo = 4 gateway-pending + 2 for SR-03),
run with `npm test --prefix tests/safety`. Test IDs `F<floor>.<nn>`, registry `MANIFEST.json`.

---

## 1. Verdict per floor

| # | Floor | Evidence | Gaps | Verdict |
|---|---|---|---|---|
| 1 | every constraint has a killing negative test; every `<--` checked by `===` | `mutation-v4.json`: 95/95 killed, 0 survived, baseline 343 pass; report is current and complete for every constraint line in its 8 targets (F1.01-F1.03); `eddsa_verifier.circom` covered by `v3.test.js` wiring tests (F1.04); arrow audit 26 files, 0 arrows, 0 violations, plus an independent audit (F1.05, F1.06) | `eddsa_verifier.circom` not in the `mutate:v4` targets (SR-18, info) | **MET** |
| 2 | no valid proof for unsatisfied policy, tampered attribute, forged signature, expired credential | committed v4 wasm refuses: each tampered attribute, engineer-claims-admin, forged signature under the pinned key, off-curve key/R8, each policy clause, `expiry <= now`, 2^64 / p-1 wrap-arounds, out-of-range attributes even when issuer-signed (F2.01-F2.10); issuer refuses expired/out-of-range (F2.11); any tampered public signal fails verify (F2.13); v3 proofs fail under the v4 key (F2.12) | circuit accepts a self-signed credential under the forger's own key by design: the **gateway pin** (obligation 2) is the only defence (F2.04), as is the policy/`resourceId` match (obligation 4, F2.07) and `now` = challenge (obligation 5): **P3-pending**. DEV-ONLY keys (SR-06). Open enrolment (SR-03) | **MET** (circuit/issuer/client); gateway half P3-pending |
| 3 | revoked credential denied against the current root | real issuer + client: `/path` 410, client refuses (F3.02); old path vs current root and current siblings at the revoked index: no witness (F3.03, F3.04); the circuit has no `leaf`/`M` input (F3.05); staleness rule never re-admits across a revocation (F3.07); fixture `stale_root_bob_wiki` consistent (F3.08) | gateway root check (obligation 3) P3-pending (F3.09 todo); revoked user can re-enrol (SR-03, F3.10 todo) | **MET** (registry/circuit); gateway half P3-pending |
| 4 | replayed proof (used/expired nonce) denied | nonce bound (F4.01), non-canonical spellings rejected by `verify()` (F4.02), `now`/`epoch` bound (F4.05), stale-`now` fixture carries the property (F4.04); malleability documented (F4.03) | nonce store, TTL: gateway (F4.06 todo) | circuit half **MET**; gateway half P3-pending |
| 5 | same nullifier twice per epoch rate-limited; cross-service unlinkable | nullifier = Poseidon(3)(secret, resourceId, epoch): lib == fixture == witness (F5.01); equal in-epoch across nonces (F5.02, F5.03); different per resource and epoch (F5.04, F5.06); only the nullifier differs between two users on one service (F5.05) | rate-limit store: gateway (F5.07 todo); per-credential, not per-person, while enrolment is open (SR-03) | circuit half **MET**; gateway half P3-pending |
| 6 | private inputs never leave the client; issuer sees only the commitment | issuer `forbidden_field` at any depth/spelling, never echoed or logged (F6.01); client body allow-list (F6.02); a full enrol+prepare session sends no secret/salt/signature/path (F6.03); gateway body is `{resource, nonce, proof, publicSignals}` (F6.04); fixtures hold no private value (F6.05); issuer state holds no attribute (F6.06); wallet 0600/0700, refuses readable files (F6.07); prover writes no files (F6.08) | the issuer necessarily sees the attributes at enrolment (it assigns them; CONTRACTS Floor 6) | **MET** |
| 7 | gateway log/state hold no username, email, role, dept, clearance | by extension to P2: issuer log has no secret/commitment/attrHash/signature/token and only allow-listed fields (F7.01, F7.02); admin/metrics output has no attribute or commitment (F7.03); client errors echo nothing (F7.04) | the gateway itself: P3-pending (F7.05 todo) | issuer/client **MET**; gateway P3-pending |
| 8 | identical Poseidon in circuit, issuer, client | published Poseidon anchors (F8.01); issuer leaf == lib attrHash == registry leaf, signature verifies (F8.02); committed wasm recomputes the registry root and the lib nullifier from the client-built input (F8.03); one encoder (F8.04); IDEN-013 suite passes (F8.05) | — | **MET** |
| 9 | no plaintext credentials or issuer private keys in the tree | no tracked key/env/wallet names (F9.01); no PEM or bare 64-hex file (F9.02); credential-bearing JSON only TEST-ONLY vectors (F9.03); secret locations ignored (F9.04); issuer key 0600, refused when readable, not the TEST-ONLY seed, not served (F9.05); artefacts labelled DEV-ONLY (F9.06) | TEST-ONLY vector keys are public by construction (SR-07); key dir mode not enforced when pre-existing (SR-10) | **MET** |
| 10 | `tests/safety/**` append-only | `MANIFEST.json` + F10.01-F10.04 (manifest subset, HEAD subset, no deletions/renames in history) | weakening a test body is a review rule, not machine-checked | **MET** (new) |

---

## 2. Rulings on the items the plan asked safety to decide

1. **7 "redundant but killed" mutants (S1, S7, S13, S21, S22, S23, S25).** **Accepted.** Each is a
   range check duplicated between `AttributeHash` and `AccessPolicyV4` (or `employeeActive`
   booleanity implied by `=== 1`). Each copy is killed by its own component's negative test, so floor
   1 holds per component; the duplication is defence in depth that keeps each component sound on its
   own. Removing both copies of a clearance/role/dept range would still leave the value bound by the
   issuer-signed `attrHash` (the issuer signs only 0..3), but the circuit would then rely on the issuer
   for soundness: keep both. F1.07 locks the kill-by-own-spec property.
2. **2 equivalent mutants in P1's v3 main** (`deviceCompliant`/`employeeActive * (x - 1) === 0`).
   **Accepted.** Genuinely equivalent: `FileShareAccess` forces `x === 1`, which implies booleanity;
   no new witness exists. v3 is not admissible at a gateway anyway. F1.08 keeps the condition true.
3. **Fast verifier vs stock snarkjs.** **Accepted.** Same pairing equation
   `e(-A,B)·e(vk_x,γ)·e(C,δ) = e(α,β)^-1` on the same ffjavascript wasm; strictly stronger input
   rules: canonical public signals `< r`, canonical proof coordinates `< q`, A and C on curve and not
   at infinity (G1 cofactor 1), B on the twist, not at infinity and `[r]B = O` (snarkjs 0.7.6 does
   not check the G2 subgroup), vkey G2 points validated once. Verifier cache keyed by sha256 of the
   verification-relevant vkey fields (a mutated vkey object gets its own verifier), bounded to 16,
   failed builds evicted. The `ZKGATE_VERIFY_IMPL=snarkjs` escape hatch keeps the same point checks.
   Differential test exists (`circuits/test/fast_verify.test.js`). Gateway notes: `verify()` returns
   `false` and never throws, so treat anything but `true` as deny; never let request data reach the
   environment variable.
4. **Issuer staleness rule and `forbidden_field`.** **Accepted.** `isRootAcceptable` accepts a
   superseded root only within 30 s and only if every later transition is an insert, so a revocation
   is never undone by the window (F3.07). A root value can recur (insert A, insert B, revoke B gives
   the root of `[A, 0]` again); that is sound because an equal root means an equal leaf set.
   `forbidden_field` matches keys at any depth, case/underscore/hyphen-insensitive, and never echoes
   the value; it inspects keys, not values, so the client's allow-list is the primary control (SR-16).
5. **Client wallet.** **Accepted with SR-09.** Files 0600 via `open(wx, 0600)` + `fchmod` + fsync +
   rename (or `link` for exclusive create, so a second `keygen` never overwrites a secret); dirs 0700
   with an explicit chmod past the umask; refuses group/other-readable credential files; request
   bodies built from allow-lists; enrolment verifies key, attributes, signature and the registry's
   leaf before storing; issuer key pinned per issuer URL (explicit key > pin > TOFU). Weakness: a
   corrupt `pins.json` silently falls back to TOFU.
6. **Logs.** Issuer logs carry route, method, status, latency, leafIndex and error code only; no
   request logging, no error objects. Client errors carry codes, never bodies or issuer free text.
   Accepted (F7.01-F7.04).
7. **Zero leaf is a member.** **Accepted, conditionally on the design staying as it is.** Revocation
   writes `0`, and `0` with the current siblings reaches the current root. v4 is safe only because the
   leaf is the in-circuit `attrHash` (a Poseidon(7) output; a preimage of 0 is infeasible) and the
   circuit has no `leaf` or `M` input (F3.05 asserts the committed wasm rejects both). Any future main
   that takes the leaf as an input must add `leaf != 0` (SR-13).
8. **`/path/:leafIndex` privacy leak.** **Accepted as LOW, recorded (SR-08).** The registry learns
   which leaf index is active after each root change (the client refreshes once per root, not per
   gateway request), and anyone can enumerate revocation status and leaf hashes by index. Leaf
   hashes reveal nothing (the commitment carries a 248-bit salt). Fix: let clients download the
   path-compressed tree and compute their own path.
9. **DEV-ONLY keys.** **Accepted for G1 and the demo only (SR-06).** Manifests say `DEV-ONLY`, phase 1
   is a local ptau, phase 2 single-party: the setup operator could forge any proof. Must be replaced
   by G2-S1-CIRC-040 before any use beyond the demo.
10. **v3 not admissible at a gateway.** **Confirmed.** `access.public_signals v3` says "The gateway must
    not admit on v3 proofs"; the v3 vkey has `nPublic = 1`, so a v3 proof cannot verify under the v4
    key (F2.12).

---

## 3. Findings

Severity: HIGH (exploitable now in the intended deployment), MEDIUM (exploitable under a stated
condition or deferred by decision), LOW (hardening), INFO (no action required, or documentation).

| ID | Severity | Floor | Location | Finding | Recommendation | Owner |
|---|---|---|---|---|---|---|
| SR-03 | ~~HIGH~~ **CLOSED** (§5) | 2, 3, 5 (system level) | `issuer/src/server.js` `POST /credentials`; contract `issuer.api v1` | Enrolment is unauthenticated: whoever reaches the issuer chooses their own attributes (engineer self-enrols as admin, clearance 3), a revoked user re-enrols with a fresh commitment, and one person can hold N credentials (N nullifiers, N admissions per epoch). No floor is violated by the letter (the credentials are genuinely issuer-signed), but the protections of floors 2, 3 and 5 are void against anyone with network access to the issuer. Documented as out of scope for v1 (localhost / compose network). | Before the G2 demo and Attack Lab: admin-approved enrolment (client submits a commitment, the admin assigns attributes under the bearer token) or a per-employee one-time enrolment token; at most one live credential per employee; compose network keeps the issuer off the user network. Contract change `issuer.api v2`. Tests F2.14, F3.10 (todo) become real then. | `identity` + `architect` |
| SR-05 | HIGH (open, P3) | 2, 3, 4, 5, 7 | gateway (not in repo) | Gateway obligations 1-8 are the enforcement point for the pinned issuer key, policy/`resourceId`, `now`/challenge, current root, nonce single-use, nullifier rate-limit and log hygiene. None exists yet. | P3 implements obligations 1-8 against `circuits/fixtures/v4`; safety adds gateway tests at that gate (F3.09, F4.06, F5.07, F7.05 become real). | `gateway` (P3) |
| SR-04 | ~~MEDIUM~~ **CLOSED** (§5) | 3 | `issuer/src/config.js`, `server.js` `adminAuth` | With `ISSUER_ADMIN_TOKEN` unset (the default) revoke and `/admin/*` are open: any peer can revoke every credential (denial of service) or list the leaves. | Fail closed: refuse to start the v4 profile without a token unless an explicit `ISSUER_INSECURE_DEV=1`. | `identity`, `devops` |
| SR-06 | MEDIUM (accepted) | 2 | `circuits/setup/*.manifest.json` | DEV-ONLY keys: single-party phase 2 and a local phase 1; whoever ran setup can forge proofs. Correctly labelled. | Multi-party ceremony G2-S1-CIRC-040 before anything beyond the demo. | `circuits` |
| SR-07 | MEDIUM | 2, 9 | `circuits/test/vectors/v4/credentials.json`, `circuits/fixtures/v4/fixtures.json` `context.pinned_issuer` | The fixtures' pinned issuer is the TEST-ONLY vector key, whose private key is sha256 of a public label. A gateway configured from `fixtures.json` instead of the real issuer key would accept anyone's self-signed credential. | Gateway refuses to start with the vector key outside its test mode (deny-list `Ax 15616845...7649`); demo config takes the key from `GET /issuer` at deploy time. | `gateway` (P3), `circuits` |
| SR-08 | LOW (privacy) | 6 (spirit) | `issuer/src/registry.js` `path()`, `client/src/issuerClient.js` | The registry learns which leaf index is in use after each root change; `/path/:i` is unauthenticated and reveals revocation status per index. | Serve the public path-compressed tree and let the client compute its path locally (no index on the wire). | `identity` |
| SR-09 | ~~LOW~~ **CLOSED** (§5) | 6 | `client/src/wallet.js` `#readPins` | An unreadable or corrupt `pins.json` is treated as "no pins" and the client re-pins on first use. | Fail closed when the file exists but cannot be parsed; document `--issuer-key` for deployments. | `identity` |
| SR-10 | ~~LOW~~ **CLOSED** (§5) | 9 | `issuer/src/keys.js` `loadOrCreateKey`, `store.js` | The key file mode is enforced (0600, refused otherwise) but the key directory's mode is not when it already exists (`mkdirSync` with `recursive` is a no-op). | `chmod 0700` or refuse a group/other-accessible key directory. | `identity` |
| SR-17 | LOW | 10 | repository root | No `Makefile` (`make test` fails), CI is `None`, and the root `npm test` does not run `tests/safety`. | Root script `test:safety` and a `make test` target that runs root, issuer, client and safety suites; CI job by name. | `devops` |
| SR-11 | ~~INFO~~ **CLOSED** (§5) | 4 | `circuits/components/challenge_binding.circom` header | The comment says that without `nonceSquared` a proof would verify for any nonce. snarkjs `zkey new` adds an input-binding row per public signal, so public inputs are bound regardless; the constraint is harmless and toolchain-independent. | Keep the constraint; correct the comment after a one-off check. | `circuits` |
| SR-13 | ~~INFO~~ **CLOSED** (§5) | 3 | `circuits/components/merkle_membership_n.circom` | Zero leaf is a member of every tree; safe because v4's leaf is the in-circuit `attrHash` (F3.05). | One comment line in the component; any future main taking `leaf` as input adds `leaf != 0`. | `circuits` |
| SR-16 | INFO | 6 | `issuer/src/server.js` `hasForbiddenKey` | Keys only, exact normalised names; a secret sent as a value is not detectable. The client allow-list is the primary control (F6.02). | None. | — |
| SR-18 | ~~INFO~~ **CLOSED** (§5) | 1 | `package.json` `mutate:v4` | `eddsa_verifier.circom` is compiled into v4 but mutated only through the v3 tests. | Add it to the `mutate:v4` targets so one report covers the whole v4 closure. | `circuits` |
| SR-19 | INFO | 4, 5 | `challenge_binding.circom` | The circuit proves neither `epoch = floor(now/600)` nor ranges of `nonce`/`resourceId`/`epoch` (F4.05: `epoch + 1` still has a witness). By contract these are gateway equality checks against the stored challenge. | None (gateway obligation 5). | `gateway` (P3) |
| SR-01 | INFO | 1 | `circuits/reports/mutation-v4.md` annotations | 7 redundant-but-killed mutants: accepted (section 2.1). | Optional: a paired mutant per duplicated range check. | `circuits` |
| SR-02 | INFO | 1 | `circuits/integrated_access_v3.circom` | 2 equivalent mutants: accepted (section 2.2). | None. | — |
| SR-12 | INFO | 2, 4 | `circuits/scripts/{verify,fast-verify}.js` | Fast verifier accepted (section 2.3). Groth16 malleability (`(-A,-B,C)` verifies, F4.03): key state on canonical signals only, as the contract says. | None. | — |
| SR-14 | INFO | 3 | `issuer/src/registry.js` `isRootAcceptable` | Staleness rule accepted (section 2.4). | None. | — |
| SR-15 | INFO | 2 | `circuits/lib/inputs.js` | The client pre-check (policy, expiry, signature, root) runs before proving and is not a security boundary; the circuit is (F2.*). | None. | — |

Counts: HIGH 2 (SR-03; SR-05 is P3 and open by construction), MEDIUM 3, LOW 4, INFO 10.

---

## 4. Verdict

The P2 lane's circuit, shared library, issuer/registry and client violate no floor. The gateway half
of floors 2-5 and 7 cannot be signed because the gateway does not exist in this repository; it is
not approved by this verdict and is tracked as SR-05 for the P3 gate. SR-03 (open enrolment) does
not break a floor as written but empties floors 2, 3 and 5 against anyone who can reach the issuer;
it must be closed before the G2 demo and the Attack Lab, and is listed as a follow-up with an owner.

**Floors dimension, G1 (P2 lane): APPROVE** — with follow-ups SR-03 (`identity` + `architect`,
before G2), SR-04 (`identity`/`devops`), SR-07 (`gateway`, at P3), SR-05 (`gateway`, P3 gate), and the
LOW items above. The Orchestrator decides whether the follow-ups make the gate CONDITIONAL.

Signed: `safety`, 2026-11-08, G1-S1-SAFETY-020.

---

## 5. Follow-up re-review (G1-S1-SAFETY-021)

**Date.** 2026-11-08. **Base.** the identity branch for G1-S1-IDEN-014 (on the development branch
after G1-S1-CIRC-039), plus the G1-S1-SAFETY-021 safety tier change. **Scope.** The follow-ups of §3 that were dispatched: SR-03, SR-04, SR-09, SR-10 (identity),
SR-11, SR-13, SR-18 (circuits). Contracts read: `issuer.api v2`, `issuer.admin v1.1`.

**Floor tier.** 80 tests: 76 pass, 4 todo (F3.09, F4.06, F5.07, F7.05: the gateway half, P3). The
SR-03 todos F2.14 and F3.10 are real tests now. Bodies of tests that drove the v1 enrolment path were
moved to the v2 path under the same IDs (API version change, not weakening; every one asserts at
least what it did before): changelog in `tests/safety/README.md`.

### 5.1 Closed findings

| ID | Was | Fix (commits) | Evidence (tests) | Status |
|---|---|---|---|---|
| SR-03 | HIGH | Admin-approved enrolment: the admin assigns attributes under the bearer token and gets a one-time 192-bit code (stored as SHA-256, single use, TTL); the user sends `{commitment, enrolmentCode}`; `attributes` in the body is `400 attributes_not_accepted`; one live credential per employee (`enrolment_pending`, `employee_has_credential`); no implicit re-enrolment; v4 has no open enrolment in any mode. G1-S1-IDEN-014 (contract, red tests, issuer, client, Attack Lab world) | F2.14 (self-chosen attributes refused with and without a code; no/unknown/malformed code 403; admin route 401 without/with wrong bearer and with a token in the URL; credential carries the admin's attributes; v4 insecure-dev still refuses attributes), F2.11 (bad attributes refused at the admin route; expiry passing before redemption is 410, nothing signed), F3.10 (revoked holder: spent code 409 `enrolment_used`, no/guessed code 403, registry size unchanged; admin cannot re-enrol a live holder, re-enrols a revoked one only with the bearer; old leaf stays revoked), F5.08 (one person, one live credential, case-insensitive, survives restart; concurrent redemption of one code issues one leaf); issuer `test/enrolment.test.js` | **CLOSED** |
| SR-04 | MEDIUM | The issuer refuses to start without `ISSUER_ADMIN_TOKEN` unless `ISSUER_INSECURE_DEV=1` (exact string), both profiles, checked before any key is created. G1-S1-IDEN-014 | F9.08 (v4 and v3, token unset/null/empty: start refused, no key file, no state written; `loadConfig` turns insecure-dev on only for `"1"`; every admin route and revoke 401 without/with a wrong bearer), F2.14 (e) | **CLOSED** |
| SR-09 | LOW | `pins.json` that exists but is unreadable, unparsable or holds a non-canonical key is `PINS_CORRUPT`; never overwritten; `--issuer-key` is the documented way through. G1-S1-IDEN-014 | F6.09 (four corrupt forms: refused before the POST, so the code is not spent and nothing is inserted; file left untouched; the same code then redeems with an explicit expected key) | **CLOSED** |
| SR-10 | LOW | Key directory created 0700 past the umask (parents too); a pre-existing directory with any group/other bit is refused before a key is written. G1-S1-IDEN-014 | F9.07 (umask 000 -> 0700 dir, 0600 key; 0755/0750/0711/0701/0770/0777 refused with an empty directory; a key directory opened up later is refused too; the issuer does not start on it), F9.05 | **CLOSED** |
| SR-11 | INFO | Comment in `challenge_binding.circom` corrected after the one-off check (a public input in no circuit row still fails verify for value + 1 under snarkjs 0.7.6, which adds an input-binding row per public signal); `nonceSquared` kept as toolchain-independent. G1-S1-CIRC-039 | F4.01 (nonce bound), F2.13 (every public signal bound); mutation sites for CB1 still killed (F1.01-F1.03) | **CLOSED** |
| SR-13 | INFO | `merkle_membership_n.circom` states that leaf 0 is a member of every tree and that any main taking `leaf` as input must add `leaf != 0`. G1-S1-CIRC-039 | F3.05 (the committed v4 wasm rejects a `leaf`/`M` input; `0` at a revoked index reaches the current root) | **CLOSED** |
| SR-18 | INFO | `eddsa_verifier.circom` added to the `mutate:v4` targets; report 102/102 killed, 0 survived. G1-S1-CIRC-039 (red, then green) | F1.01 (tightened to `total >= 102`), F1.09 (new: every file of the v4 include closure is a target, no exceptions; 7 eddsa sites, all killed; `npm run mutate:v4` names the file); F1.04 kept (exception branch now unreachable) | **CLOSED** |

### 5.2 Residual risk and new observations

- **Insecure-dev mode is still an open admin surface.** With `ISSUER_INSECURE_DEV=1` and no token,
  `/admin/*` and revoke are open and the v3 baseline keeps open enrolment. Accepted: local
  development only, loud start-up warning, never set in compose (devops to confirm when compose
  lands); v4 has no open enrolment in any mode (F2.14).
- **Issuer-side identity.** `enrolments.json` (0600) links `employeeId` to `leafIndex`; pending
  attributes are erased at redemption (F6.10) and ids and codes never reach logs, metrics or the
  identity-free admin routes (F7.01, F7.03 now check email-shaped ids and every code). This is the
  issuer knowing who it enrolled, which floor 6 permits; the gateway never sees it. Accepted.
- **SR-20 (INFO, new, `identity`).** `buildServer` tests `!config.insecureDev` (truthy) at the
  fail-closed check but `config.insecureDev === true` for the v3 legacy route. Only `loadConfig`
  produces the config in production and it yields a boolean, so this is not reachable from the
  environment; a programmatic caller passing `"0"` would get an open admin surface. Recommendation:
  `config.insecureDev === true` in both places. Not a floor issue.
- SR-05 (gateway), SR-06, SR-07, SR-08, SR-17 and the INFO items not listed above are unchanged.

Counts after this re-review: HIGH 1 open (SR-05, P3 by construction), MEDIUM 2 (SR-06 accepted,
SR-07), LOW 2 (SR-08, SR-17), INFO 7 open + SR-20 new; closed 7 (SR-03, SR-04, SR-09, SR-10, SR-11,
SR-13, SR-18).

### 5.3 Verdict (re-signed)

Floors 1, 6, 8, 9, 10: **MET**, and floor 1 now covers the whole v4 closure in one report. Floors 2,
3, 5 at the system level: the SR-03 hole that emptied them against anyone reaching the issuer is
closed and tested (F2.14, F3.10, F5.08). Floors 2-5 and 7, gateway half: **not signed**, P3-pending
(SR-05). The combined tree (identity G1-S1-IDEN-014 + this tier) is green: tier 76 pass / 4 todo,
issuer 173 passing (1 profile-conditional pending), client 87/87, Attack Lab 27/27.

**Floors dimension, G1 (P2 lane, including G1-S1-IDEN-014): APPROVE** — G1-S1-IDEN-014 may merge
together with the G1-S1-SAFETY-021 tier change (the tier must land with it: on the identity branch alone the tier is red).
Open follow-ups: SR-05 (`gateway`, P3 gate), SR-07 (`gateway`, P3), SR-17 (`devops`: no `Makefile`,
CI `None`), SR-20 (`identity`, INFO), SR-08 (`identity`, LOW).

Signed: `safety`, 2026-11-08, G1-S1-SAFETY-021.
