# G1 gate — Floors dimension (P2 lane)

**Reviewer.** `safety` (veto holder). **Date.** 2026-11-08. **Mode.** review.
**Base.** the development branch after the client clock-pin fix (below), plus the safety change that
appends F9.09-F9.11 and the change that adds this file.
**Scope.** Floors 1-10 for the P2 lane: circuit v4 and its include closure, `circuits/lib`, the
committed proving artefacts and fixtures, issuer/registry (`issuer.api v2`, `issuer.admin v1.1`),
client prover. The gateway (P3) is not in this repository; the gateway half of floors 2-5 and 7 is
**not signed** here (SR-05).
**Previous verdicts.** `docs/security/review-G1-P2.md` §4 (G1-S1-SAFETY-020) and §5.3
(G1-S1-SAFETY-021, re-signed after SR-03 closed). This file covers what landed after them:

| Change | What | Floors touched |
|---|---|---|
| G1-S1-IDEN-015 | SR-20: `buildServer` enables insecure-dev only for boolean `true` | 3, 9 (admin surface) |
| G1-S1-IDEN-015 | root `README.md` rewrite | none (one stale sentence, SR-22) |
| G1-S1-CIRC-041 | `circuits/README.md` refresh | none |
| G2-S1-CIRC-040a | re-key of v3 and v4 on PSE ppot 0080 phase 1; new zkey/vkey/wasm, regenerated `circuits/fixtures/v4` | 1, 2, 9 |
| G2-S1-CIRC-040a | circuits memory note | none |
| client test fix | client tests pin the issuer clock (wall-clock time bomb removed) | none (test hygiene) |

---

## 1. Floor tier run

```
$ npm test --prefix tests/safety

> zk-access-gate-safety@1.0.0 test
> node --test --test-concurrency=1 "*.test.js"
...
ok 1 - floor 1: constraints and arrows
ok 2 - floor 2: no valid proof for tampered / forged / unsatisfied / expired
ok 3 - floor 3: revoked credential vs current root
ok 4 - floor 4: replay (circuit and fixture half)
ok 5 - floor 5: nullifier (circuit and fixture half)
ok 6 - floor 6: private inputs stay on the client
ok 7 - floor 7: logs and state hold no identity attributes
ok 8 - floor 8: one Poseidon across circuit, issuer, client
ok 9 - floor 9: no plaintext credentials or issuer private keys in the tree
ok 10 - floor 10: tests/safety is append-only
1..10
# tests 83
# suites 10
# pass 79
# fail 0
# cancelled 0
# skipped 0
# todo 4
# duration_ms 37135.750601
```

The 4 todo are the gateway half: F3.09, F4.06, F5.07, F7.05 (P3). Before the three tests appended
in this review the same tree gave 80 tests, 76 pass, 0 fail, 4 todo (unchanged from SAFETY-021).

Other suites on the same tree (for the Tests dimension; run by `safety`, not a substitute for it):

| Command | Last line |
|---|---|
| `npm test` (root, circuits) | `874 passing (3m)` |
| `npm test --prefix issuer` | `174 passing (19s)`, `1 pending` |
| `npm test --prefix client` | `# pass 87`, `# fail 0` |
| `make test` | `make: *** No rule to make target 'test'.  Stop.` (no `Makefile`, SR-17) |

### 1.1 Independent checks of the re-key (not in the tier: they need the 37 MB ptau from the cache)

Run by `safety` on this tree, with circom 2.2.3 and snarkjs 0.7.6, outputs in a temp dir:

| Check | Result |
|---|---|
| `b2sum ~/zkp-cache/ptau/ppot_0080_15.ptau` vs `ptau.sh` `PSE_B2[15]` and both manifests | equal (`a6dd3adc…7f24`) |
| ptau header (section 1) | n8 32, power 15, ceremonyPower 28 |
| section table | 11 sections: 1-7 and 12-15 (prepared for phase 2) |
| section 7 contribution count | 62 |
| published `challenge_0080` prefix `d9ec6fad…7171622` | at byte 12,673,301 = section 7 data start 12,583,116 + **90,185** (the manifest's offsets are section-relative; confirmed) |
| published `challenge_0081` prefix `4bf672f3…88359612` | at byte 12,674,822 = section 7 start + **91,706** |
| recompile v4 and v3 at `--O2` from source | `r1cs_sha256` equal to both manifests (v4 `652dae08…`, v3 `60328a4f…`; R1CS unchanged by the re-key); v4 wasm `b6651dd5…` equal to the committed wasm and the manifest (the wasm hash changed in the G2-S1-CIRC-040a re-key but the new one is reproducible from source) |
| `snarkjs zkey verify <r1cs> ppot_0080_15.ptau <committed zkey>` | `ZKey Ok!` for v4 and for v3: the committed proving keys descend from this phase 1 |
| `zkey export verificationkey` of the committed v4 zkey | identical to `circuits/setup/integrated_access_v4.verification_key.json` and to `circuits/fixtures/v4/verification_key.json` |
| pre-re-key v4 vkey (before G2-S1-CIRC-040a) vs `alice_wiki` | old proof / old key true; old proof / **new** key false; new proof / **old** key false; new / new true |

Not checked, by anyone: a full `snarkjs powersoftau verify` of the 0080 file (2^28-point initial
hash). The "linkage" check is that two published hashes appear in the transcript section; it shows
the file claims the 0080 lineage, not that its points are the output of that lineage (SR-21).

A note on wording: the plan and the request describe phase 1 as "PSE's public 80-contribution
ceremony". The file is PSE's Perpetual Powers of Tau prepared from **contribution 0080** with a
beacon; its snarkjs transcript (section 7) records **62** contributions. The manifests and
`circuits/setup/README.md` say exactly that; gate documents should too.

---

## 2. Floors 1-10

| # | Floor | Status | Evidence | What the re-key changed |
|---|---|---|---|---|
| 1 | every constraint has a killing negative test; every `<--` checked by `===` | **MET** | `circuits/reports/mutation-v4.json`: 102/102 killed, 0 survived, whole v4 include closure (F1.01, F1.02 not stale, F1.03 complete, F1.09 no exceptions); arrow audits 0 violations (F1.05, F1.06); redundant/equivalent mutant rulings locked (F1.07, F1.08) | nothing: R1CS hashes unchanged (recompiled, §1.1); the mutation report still reads every site as recorded (F1.02) |
| 2 | no valid proof for unsatisfied policy, tampered attribute, forged signature, expired credential | **MET circuit-issuer-client side; gateway half P3-pending** | no witness from the committed wasm for each tampered attribute, engineer-claims-admin, forged signature under the pinned key, off-curve key/R8, each policy clause, `expiry <= now`, wrap-arounds, out-of-range signed attributes (F2.01-F2.10); issuer refuses bad attributes (F2.11); every public signal bound (F2.13); v3 not admissible (F2.12); only authenticated enrolment (F2.14); new: keys built on a public phase 1 with recorded provenance, DEV-ONLY while phase 2 is single-party (F9.09), fixtures verify under the current key only (F9.10) | **soundness trust narrowed to one party**: phase 1 is no longer this machine's local ceremony but PSE ppot 0080 (`zkey verify` OK against it, §1.1). Phase 2 is still one contribution, so the setup operator can still forge any proof: SR-06 stays open (MEDIUM, accepted for the demo). The pre-re-key keys are superseded: no current fixture verifies under them and no old proof under the new key, so a gateway holding a cached old vkey denies everything rather than admitting anything. Gateway half (pinned issuer, policy, `now`) unchanged: SR-05, SR-07 |
| 3 | revoked credential denied against the current root | **MET circuit-issuer-client side; gateway half P3-pending** | `/path` 410 and client refusal (F3.02); old path / current siblings vs current root: no witness (F3.03, F3.04); no `leaf`/`M` input (F3.05); staleness rule never crosses a revocation (F3.07); stale-root fixture consistent (F3.08); revoked holder cannot re-enrol without the admin (F3.10); admin surface fail-closed (F9.08) incl. SR-20 (F9.11, new) | fixture `stale_root_bob_wiki` regenerated under the new key, same public signals (`public.json` unchanged), still verifies (F9.10) so it remains a valid P3 deny input. Gateway root check: F3.09 todo |
| 4 | replayed proof (used/expired nonce) denied | **MET circuit side; gateway half P3-pending** | nonce bound (F4.01); non-canonical spellings fail (F4.02); malleability documented, state keys on canonical signals (F4.03); stale-`now` fixture (F4.04); `now`/epoch bound (F4.05) | fixtures regenerated, signals unchanged. Nonce store and TTL: F4.06 todo |
| 5 | same nullifier twice per epoch rate-limited; cross-service unlinkable | **MET circuit-issuer-client side; gateway half P3-pending** | nullifier = Poseidon(3)(secret, resourceId, epoch), lib == fixture == witness (F5.01); equal in-epoch (F5.02, F5.03); differs per service and epoch (F5.04, F5.06); only the nullifier differs between users on one service (F5.05); one live credential per person (F5.08) | none (nullifier is a circuit output, independent of the key). Rate-limit store: F5.07 todo |
| 6 | private inputs never leave the client; issuer sees only the commitment | **MET** | issuer `forbidden_field` (F6.01); allow-listed client bodies (F6.02, F6.03); gateway body `{resource, nonce, proof, publicSignals}` (F6.04); fixtures hold no private value (F6.05, re-run on the regenerated fixtures); issuer state (F6.06, F6.10); wallet modes (F6.07); prover writes no files (F6.08); corrupt pins fail closed (F6.09) | regenerated fixtures still hold no private value (F6.05). The issuer necessarily assigns the attributes at admin enrolment (as in SAFETY-021) |
| 7 | gateway log/state hold no username, email, role, dept, clearance | **MET issuer-client side; gateway half P3-pending** | issuer log has no secret/commitment/leaf/signature/token, no employee id or code, only allow-listed fields (F7.01, F7.02); admin/metrics output identity-free (F7.03); client errors echo nothing (F7.04) | none. The gateway itself: F7.05 todo |
| 8 | identical Poseidon in circuit, issuer, client | **MET** | published anchors (F8.01); issuer leaf == lib attrHash == registry leaf, signature verifies (F8.02); committed wasm recomputes root and nullifier from the client-built input (F8.03, now on the re-keyed wasm); one encoder (F8.04); IDEN-013 cross-check passes (F8.05) | the new wasm is rebuilt from the same source and reproduces bit-exactly (§1.1); F8.03 passes on it |
| 9 | no plaintext credentials or issuer private keys in the tree | **MET** | tracked-file scans (F9.01-F9.03); secret locations ignored (F9.04); issuer key 0600 in a 0700 dir, refused when readable, never the TEST-ONLY seed (F9.05, F9.07); DEV-ONLY labels (F9.06); fail-closed start (F9.08); new F9.09-F9.11 | the 37 MB ptau stays outside the tree (`~/zkp-cache/ptau`, not tracked: F9.01/F9.02 green). Manifests now record `ptau.source = "pse-ppot-0080"`, the pinned blake2b, provenance and the TOFU limitation (F9.09 locks this and forbids a `dev`/`external` phase 1 for committed keys from now on). The TEST-ONLY vector issuer key is still the fixtures' pinned key (SR-07, by construction) |
| 10 | `tests/safety/**` append-only | **MET** | `MANIFEST.json` superset of HEAD (F10.03); every ID present (F10.01, F10.02); no deletion/rename in history (F10.04). This review appended F9.09-F9.11 and a changelog paragraph; no existing body or entry changed | — |

**Summary.** Floors 1, 6, 8, 9, 10: MET. Floors 2, 3, 4, 5, 7: MET on the circuit, issuer and client
side; the gateway half is P3-pending and is not signed by this verdict (SR-05).

---

## 3. Threat-model delta since `review-G1-P2.md`

Additions to `docs/security/threat-model.md` P2 section (that file is not rewritten; this is the
delta for the gate bundle).

**Trusted setup (insider: "whoever ran the trusted setup").**
- Before (G1-S1-CIRC-037 up to the G2-S1-CIRC-040a re-key): phase 1 was a local two-contribution ceremony on this machine and
  phase 2 a single contribution, both by the setup operator. Whoever ran setup could forge any proof.
- Now (since G2-S1-CIRC-040a): phase 1 is PSE ppot 0080 (public, many contributors, beacon); the committed
  zkeys provably descend from that file (`zkey verify` OK). Phase 2 is still one contribution plus a
  local (not publicly verifiable) beacon. **Whoever ran phase 2 can still forge any proof**, for any
  attributes, issuer key and policy: floors 2, 3 and 5 hold only against parties other than the
  setup operator. The attack surface moved from "phase 1 or phase 2 operator" to "phase 2 operator".
  SR-06 open, narrowed.
- New residual (SR-21): the phase-1 file's integrity rests on HTTPS from PSE's bucket, a hash
  pinned on first download (PSE publishes none for prepared files) and the presence of two published
  transcript hashes; no full `powersoftau verify`. A substituted file is undetectable by these checks
  but is dominated by SR-06 today (the phase-2 operator can already forge).
- Old keys: the pre-re-key DEV keys are superseded; proofs under them do not verify under the new
  key and vice versa (§1.1). Anyone who kept the old local phase-1/phase-2 toxic waste can forge only
  under the old vkey, which no consumer should load (F9.10 locks the fixtures to the current key).

**Malicious user / insider (enrolment v2, SR-03 closed at SAFETY-021).**
- Row "Self-enrol with chosen attributes, re-enrol after revocation, hold several credentials":
  was "Nothing today"; now stopped by admin-approved enrolment with a one-time 192-bit code, one
  live credential per employee, no implicit re-enrolment, v4 has no open path in any mode (F2.14,
  F3.10, F5.08). Residual: the issuer admin is trusted to assign attributes (inherent, M1).
- Row "Revoke other users (DoS)": was "only if `ISSUER_ADMIN_TOKEN` is set"; now the issuer refuses
  to start without a token unless insecure-dev is on (F9.08), and since G1-S1-IDEN-015 insecure-dev is on
  only for the boolean `true` from `loadConfig("1")` (SR-20 closed; F9.11 + issuer test).
- Issuer now holds `employeeId -> leafIndex` in `enrolments.json` (0600): the issuer knows whom it
  enrolled, which floor 6 permits; never reaches logs, metrics or the gateway (F7.01, F7.03).

**Network attacker.** Unchanged: no TLS between client and issuer (localhost/compose); the
one-time enrolment code travels in that channel, so non-local deployment needs TLS before it carries
codes (already noted in the threat model; recorded here because v2 added a bearer-equivalent secret).

**Compromised gateway / gateway operator.** Unchanged, P3-pending (SR-05, SR-07). One addition: the
gateway must load the vkey from `circuits/setup/integrated_access_v4.verification_key.json` at
deploy (sha256 equal to the manifest, F9.10) and must not ship a cached pre-re-key copy.

---

## 4. Open findings

| ID | Severity | Floor | Owner | Status | Gate condition? |
|---|---|---|---|---|---|
| SR-05 | HIGH (open by construction) | 2, 3, 4, 5, 7 | `gateway` | gateway obligations 1-8 do not exist yet; F3.09, F4.06, F5.07, F7.05 are todo | **Not a G1 (P2-lane) condition**: P2 has no gateway. It is a hard precondition of the P3 gate: `safety` will not sign floors 2-5 and 7 there until those four tests are real and green against `circuits/fixtures/v4` |
| SR-06 | MEDIUM (accepted for the demo; narrowed by G2-S1-CIRC-040a) | 2 | `circuits` (+ team contributors) | phase 1 public (PSE ppot 0080), phase 2 single-party: the setup operator can forge proofs | **Yes, as a scope condition**: the keys are DEMO-ONLY; no use beyond the demo before the multi-party phase 2 (G2-S1-CIRC-040). Does not block G1 |
| SR-07 | MEDIUM | 2, 9 | `gateway` (P3), `circuits` | fixtures' pinned issuer is the derivable TEST-ONLY key | P3 gate condition (deny-list the vector key outside test mode; take the key from `GET /issuer` at deploy). Not G1 |
| SR-08 | LOW (privacy) | 6 (spirit) | `identity` | `/path/:i` reveals the active leaf index and revocation status | No; track to G2 |
| SR-17 | LOW | 10, tests | `devops` | no `Makefile` (`make test` fails), CI `None`, root `npm test` does not run `tests/safety` | **Yes, propose CONDITIONAL with owner `devops`, deadline before the G2 gate**: open since SAFETY-020; the project's named test command does not exist, so the floor tier only runs when someone remembers it. Per strategy §5 a condition carried past two milestones must go to the user |
| SR-21 (new) | LOW | 2 | `circuits` | phase-1 pin is trust-on-first-download; linkage is hash presence in section 7; no full `powersoftau verify` | No (dominated by SR-06). Before or with G2-S1-CIRC-040: run `PTAU_FULL_VERIFY=1` (or verify the 0080 response chain) on a machine that can, and record the result in the manifests' provenance |
| SR-22 (new) | INFO | — | Orchestrator (root `README.md` has no owning role; `identity` wrote it in IDEN-015) | `README.md` lines 181-182 still say "single-party with a local phase 1"; since G2-S1-CIRC-040a phase 1 is PSE ppot 0080 | No. One-line doc fix |
| SR-16, SR-19, SR-01, SR-02, SR-12, SR-14, SR-15 | INFO | — | as in `review-G1-P2.md` | unchanged | No |

Closed since `review-G1-P2.md` §5: **SR-20** (G1-S1-IDEN-015; issuer test + F9.11). Previously closed:
SR-03, SR-04, SR-09, SR-10, SR-11, SR-13, SR-18.

Counts: HIGH 1 open (SR-05, P3 by construction); MEDIUM 2 (SR-06 accepted and narrowed, SR-07 P3);
LOW 3 (SR-08, SR-17, SR-21 new); INFO 8 (SR-22 new); closed 8.

Proposed conditions for the G1 gate bundle (the Orchestrator decides CONDITIONAL vs PASS):

1. **SR-17**, owner `devops`: `Makefile` with `make test` running root, issuer, client and
   `tests/safety`; CI job by name. Deadline: before the G2 gate.
2. **SR-06**, owner `circuits`: keys remain DEMO-ONLY; multi-party phase 2 (G2-S1-CIRC-040) before
   any use beyond the demo; fold SR-21 into that task.
3. Carried to P3 (not G1 conditions): SR-05 and SR-07, owner `gateway`.

---

## 5. Verdict

No floor is red. The re-key moved phase 1 to a public ceremony without changing the circuit, the
R1CS or any public signal; the committed keys descend from the pinned PSE file; every fixture
verifies under the new key and none under the old one. The gateway half of floors 2-5 and 7 is not
signed here and stays with SR-05 at the P3 gate.

Floors (G1, P2 lane): APPROVE

— safety
