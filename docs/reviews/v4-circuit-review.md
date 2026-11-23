# v4 access circuit — second review

**Reviewer:** Independent review by an agent on behalf of P1; P1 sign-off pending.
**Date:** 2026-11-23
**Commit reviewed:** `f475615` (HEAD); the circuit sources were last changed in `c8a0ace`.

**Files reviewed:**

- `circuits/integrated_access_v4.circom` (plus the `_d8` / `_d20` benchmark mains, `public` lists only)
- `circuits/components/integrated_access_v4_gate.circom`
- `circuits/components/attribute_hash.circom`, `issuer_key.circom`, `access_policy_v4.circom`,
  `expiry.circom`, `challenge_binding.circom`, `merkle_membership_n.circom`, `eddsa_verifier.circom`
- circomlib 2.0.5 as used: `EdDSAPoseidonVerifier`, `BabyCheck`, `LessThan`, `GreaterEqThan`,
  `Mux2`, `Num2Bits`, `Poseidon`
- `circuits/reports/mutation-v4.md` / `.json`, `circuits/scripts/mutate/annotations-v4.json`
- Tests: `circuits/test/v4.test.js`, `policy_v4.test.js`, `mutate.test.js` (read; see "Not verified")
- Against: `docs/CONTRACTS.md` (`credential v4`, `access.public_signals v4`), ADR 0005–0008,
  `docs/notes/next-steps-for-p1-and-p3.md`

## Verdict: APPROVE WITH NITS

I found no soundness bug. Every statement in the contract is enforced by a constraint, and the
public-signal order matches the contract. The findings below are about wording, defence in depth
and one design choice worth deciding before the key ceremony. None of them blocks the circuit.

## What was checked and holds

| Property | Where | Result |
|---|---|---|
| No `<--` in any v4 file | all targets | None found (grep). Every assignment is `<==` or `===`. |
| Commitment, attributes and signature are bound | gate:78–101, attribute_hash:45–54 | `M = attrHash = Poseidon(7)(6 attributes, Poseidon(2)(secret, salt))`. Changing any attribute or the salt or secret changes `M`. |
| Issuer key is public and the same signals reach the verifier and the curve checks | gate:95–108 | Yes. `issuerAx/Ay` are public inputs wired to `IssuerSignatureCheck` and `BabyCheck`. |
| EdDSA verifier | circomlib `eddsaposeidon.circom` | `S < l` (`Num2Bits(253)` + `CompConstant(l-1)`), `h` decomposed with `Num2Bits_strict`, rejects small-order `A` (`x(8A) != 0`). `R8` off-curve is closed by `BabyCheck`. `R8` outside the subgroup cannot pass, because `S·B8` and `8hA` are in the subgroup. |
| Merkle | merkle_membership_n:40–59 | `pathIndices[i]` boolean, left/right selection correct, depth fixed at 16, `hashes[depth] === root` with `root` public. The leaf is the in-circuit `attrHash` (a Poseidon(7) output), so the "leaf 0" problem (SR-13) and leaf/internal-node confusion do not apply. |
| Policy | access_policy_v4:36–81 | Masks are `Num2Bits(4)`. The `Mux2` selectors are `Num2Bits(2)` outputs, so they are boolean, and the index is `s0 + 2·s1`, which equals bit `role`. `requireDevice` is boolean and P11 is correct. `employeeActive === 1`. |
| Clearance comparator | access_policy_v4:65–73 | Correct for all 16 pairs. See F-1 for a precondition the contract wording misses. |
| Expiry | expiry:17–26 | `expiry` and the public `now` both pass `Num2Bits(64)`. Then `LessThan(64)`, whose `Num2Bits(65)` cannot wrap. Strict `now < expiry`. |
| Nullifier | challenge_binding:60–64, gate:137–142 | `Poseidon(3)(credentialSecret, resourceId, epoch)`. `credentialSecret` is fixed by the signed commitment, so the nullifier is deterministic per (credential, resource, epoch). The salt is not used. Without the secret, nullifiers for different services or epochs are unlinkable (Poseidon used as a PRF). |
| Challenge fields | gate:66–71 | `now`, `nonce`, `resourceId` and `epoch` are public inputs. `now` enters the expiry check, `resourceId` and `epoch` enter the nullifier, and `nonce` enters `nonceSquared` (see F-2). |
| Public-signal order | gate:61–74, main:9 | Declaration order is root, issuerAx, issuerAy, roleMask, deptMask, minClearance, requireDevice, now, nonce, resourceId, epoch. With `nullifier` as the only output, this matches `access.public_signals v4` exactly. The `_d8` and `_d20` mains use the same list. `v4.test.js` asserts the `.sym` slots. |
| Groth16 binding of every public slot | committed vk | **Run in this review:** snarkjs `groth16.verify` with `setup/integrated_access_v4.verification_key.json` (`nPublic: 12`) on `fixtures/v4/alice_wiki`. The original signals verify `true`. Each of the 12 slots +1 verifies `false`. |
| Mutation report not stale | mutate.test.js:248 | **Run in this review:** I re-ran the comparison logic of `parseSites` against the current sources. All 102 sites match the committed report (file, line, text). |

## Findings

| ID | Severity | File:line | Issue | Recommendation |
|---|---|---|---|---|
| F-1 | Nit | `circuits/components/access_policy_v4.circom:70-73`; `docs/CONTRACTS.md:172-173` | `GreaterEqThan(2)` passes `clearance + 1` to `LessThan(2)`. When `clearance = 3` that is 4 = 2^2, which breaks `LessThan(2)`'s precondition (inputs < 2^n). The result is still correct: `minClearance + 4 - (clearance + 1)` lies in [0, 6] and fits `Num2Bits(3)`. The exhaustive 4×4 test in `policy_v4.test.js:220` also covers it. The issue is that the contract sentence "every comparator input is range-checked to the comparator's width" is not literally true here. | Either add a comment with the [0, 6] bound argument, or use `GreaterEqThan(3)`, which costs one more constraint but needs a new setup. A comment is enough. |
| F-2 | Info | `challenge_binding.circom:18-26,57`; gate header `:19` and `:136` | `nonceSquared` is an internal signal that nothing else constrains, so `nonceSquared <== nonce*nonce` holds for every `nonce`. It puts `nonce` in an R1CS row but does not restrict its value. The binding that matters comes from the Groth16 IC term (confirmed above: nonce+1 fails verify). The line comments call it "nonce bound by nonce^2", which overstates it. The file's long comment states it correctly. | Keep the constraint. Reword "nonce bound" to "nonce referenced in R1CS; bound by the verifier's IC term". The S34 kill comes from overwriting `nonceSquared` in the witness, which tests the row and not a soundness property. That is fine, as long as nobody reads it as more. |
| F-3 | Low | `integrated_access_v4_gate.circom:66-71,137-142`; `challenge_binding.circom:34-36` | The circuit does not tie `epoch` to `now` (`epoch = floor(now/600)`) and does not range-check `resourceId`. A prover can therefore pick any epoch and get a fresh nullifier. Floor 5 (rate limit) rests entirely on gateway obligation 5: proof `epoch` = challenge epoch. This is documented and sound if the gateway complies, but it is a single point of failure for a floor. | Accepting it as a gateway obligation is defensible. If the setup is going to be redone anyway for the multi-party ceremony, that is the cheap moment to add `600·epoch <= now < 600·epoch + 600`: `Num2Bits(64)` on `epoch` plus two `LessThan(64)`, about 200 constraints. Either way, `tests/safety` should keep a gateway test with a mismatched epoch. |
| F-4 | Info | `annotations-v4.json`; `mutation-v4.md` §Annotated | I checked the 7 "redundant" notes (S1, S7, S13, S21–S23, S25). Each named partner constraint does exist in the composed circuit: `Num2Bits(2)` on role/dept/clearance appears in both AttributeHash and AccessPolicyV4, and `employeeActive === 1` subsumes the boolean check. None is claimed equivalent (0 equivalent, 102/102 killed by non-forbidden tests). **No annotation hides a gap.** S24 (`deviceCompliant` boolean in AttributeHash) is *not* redundant: when `requireDevice = 0` it is the only range check on that attribute, and it is correctly left unannotated. All attribute range checks are defence in depth against an issuer bug, because the signature fixes the values. | No change. Keep the duplicate checks: about 10 constraints, and each component stays self-contained. |
| F-5 | Info | `circuits/scripts/mutate/*` (operator set) | The mutation harness applies only M1 (delete `===`, weaken `<==` to `<--`). It does not mutate widths (`Num2Bits(64)`, `LessThan(64)`, `Num2Bits(2/4)`), constants (`=== 1`), Poseidon input order or arity, or the `public [...]` list. I checked these classes by hand and found them covered by explicit tests: `now+2^64`, `now = p-1`, `now >= 2^64`, policy fields 16 / 4 / 2 / p-1, attributes 4 / p-1, lib-parity tests for `attrHash` and the nullifier, and the `.sym` slot test. "102/102" means "every constraint is needed". It does not mean "every parameter is right". | No change needed for G1. If the harness is extended, add a width-mutation operator (n → n+1, n → 252). |
| F-6 | Nit | `circuits/components/issuer_key.circom` | The file name (`issuer_key`) does not match its template (`SignaturePointsOnCurve`). The test harness already calls it `signature_points`. | Optional rename to `signature_points.circom`. It does not change the R1CS, so no new setup is needed, but it touches the mutate targets, the report and the tests. |

## Answers to P1's questions

1. **Naming.** Keep. The public-signal names are contract (ADR 0007) and match P1's camelCase v3
   style. Template names are descriptive. The only mismatch is F-6 (file vs template), which is
   cosmetic.
2. **Structure.** Keep. The main is thin. The gate template only wires: it has no `<--` and no `===`
   of its own. Each component has one concern and its own tests, and P1's
   `IssuerSignatureCheck` and v3 files are unchanged. Keeping the duplicate range checks is the
   right call (F-4). Separately: delete the non-compiling fragment
   `circuits/components/integrated_access.circom` (P1 item 3). It is not used, and it sits in the
   `audit:arrows` glob.
3. **Attribute set.** Keep the six attributes and the 2-bit enums for the demo. Any widening (a
   fifth role or department, wider clearance) is a new contract version and a new setup, so decide
   it **before** the multi-party ceremony, not after. One observation: `employeeActive` adds
   little over revocation. Flipping it needs a new leaf, and a credential with `employeeActive = 0`
   can never prove, which is the same effect as revoking it. It costs about 2 constraints, so it
   is not worth a contract change.
4. **`employeeActive` always required.** Agree with ADR 0007: keep it a hard `=== 1`, not a policy
   field. A field that is always 1 is only another way to misconfigure a policy. Docs should say
   plainly that deactivating an employee means **revoking the leaf**. The attribute is defence in
   depth against a mis-issued credential, not the off switch.

## Not verified (circom not installed)

- Compilation, constraint counts (`v4.test.js` `EXPECTED_COUNTS`), and every `circom_tester`
  test, positive and negative. I read the tests but did not run them. The mutation results
  (102/102, baseline 350 passing) are taken from the committed report. I checked that the report
  matches the current sources (above) but did not re-run it.
- That the committed `.zkey` / verification key were produced from this exact source. I checked
  that the vk binds 12 public signals and rejects every tampered slot on a committed fixture, but
  not that it corresponds to this R1CS.
- `--O2` behaviour of `nonceSquared` (that it is kept as a non-linear row). This relies on the
  report's `--O2` public-slot tests.
- circomlib was read from a sibling checkout's `node_modules` (`circomlib` 2.0.5 per
  `package-lock.json`). This worktree has no `node_modules`.
