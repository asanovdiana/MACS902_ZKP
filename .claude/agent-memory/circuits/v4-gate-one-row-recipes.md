# One-violated-row recipes for the v4 gate wiring

`circuits/test/v4.test.js` "v4 negatives, witness level" kills all 40 gate `<==` links:
- single-consumer input (policy masks, now, nonce, resourceId, epoch, root, S, path, salt,
  nullifier output): `W.clone().add("main.x")`.
- attribute X (two consumers attr + policy, expiry also expiryCheck): build a TEST-ONLY world tree
  = vector personas at 0..2 (reproduces vector root) + issuer-signed Alice variants differing in one
  attribute (issuer prv = sha256(vec.issuer.seedLabel)); `spliceCredential` overwrites attr,
  signature, points, merkle sub-witnesses from O0 harness builds (`main.X` -> `main.<comp>.X`) plus
  R8/S/path inputs. attr link: main.X honest; policy/expiryCheck link: also set main.X to the variant.
  Works for employeeActive 0 and EXPIRED variants that no full witness can produce.
- issuer key / R8 (signature + points consumers): negate x (or y); still on BabyJubJub and BabyCheck's
  x2/y2 unchanged, so set main + points chain only (signature link) or points chain only.
- secret (commitmentHasher + binding): copy `main.binding.` + `main.nullifier` from Bob's witness.
- commitment links: Poseidon(2) harness (`compilePoseidon2`) over (secret, salt+1).
See [[v3-one-violated-row-tamper]], [[v4-splice-circomlib-subwitness]], [[linear-binding-vanishes-at-o2]].
