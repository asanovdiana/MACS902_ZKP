# Threat model — ZK Access Gate

**Owner.** `safety`. Sections are added per lane and gate; earlier sections are not rewritten.
Scope requirement (`docs/project-scope.md`, Threat model): malicious user, compromised gateway,
malicious issuer, network attacker, insider abuse; for each, what they can do, what stops them,
what is out of scope.

Assets: the issuer's signing key; each user's `credentialSecret`/`credentialSalt`; the user's
attributes (role, dept, clearance, device, active, expiry); the registry root; the gateway's nonce
and nullifier state; the proving/verification keys.

---

## P2 section (G1): circuit v4, shared lib, issuer/registry, client

Reviewed after G1-S1-CIRC-037; findings `SR-xx` refer to `docs/security/review-G1-P2.md`; tests `F<n>.<nn>`
to `tests/safety/`. Parts whose control is the gateway are marked **[P3-pending]**: the gateway is
not in this repository yet.

### 1. Malicious user (holds a valid credential, or none)

| Can try | What stops it | Evidence |
|---|---|---|
| Change role/dept/clearance/device/active/expiry after issuance | `attrHash` over all six attributes + commitment is both the signed message and the leaf; any change breaks the EdDSA check and the membership | F2.01, F2.02 |
| Sign their own credential | Issuer key is a public signal; the circuit accepts any key, so a self-signed proof carries the forger's key **[P3-pending: gateway pins `issuerAx/Ay`]**; under the pinned key no witness exists | F2.03, F2.04 |
| Prove a policy they do not meet | Generic policy in-circuit (mask mux, range-checked comparator, device, active); the policy fields are public **[P3-pending: gateway requires its own policy and `resourceId`]** | F2.06, F2.07 |
| Use an expired credential | `now < expiry`, both 64-bit ranged; `now` is public **[P3-pending: gateway requires `now` = its challenge, TTL 120 s]** | F2.08, F2.09, F4.04 |
| Feed out-of-range values (role 4, `expiry + 2^64`, `now = p-1`, off-curve points, `S + l`) | Num2Bits range checks before every comparator/mux, BabyCheck on key and R8, circomlib's `S < l` check | F2.05, F2.09, F2.10, F2.03 |
| Replay a proof, or respell its signals | nonce, `now`, epoch, `resourceId` are bound public inputs; `verify()` rejects non-canonical spellings; Groth16 proofs are malleable so state keys on canonical signals **[P3-pending: nonce single-use]** | F4.01-F4.05 |
| Spam one service | nullifier = Poseidon(secret, resourceId, epoch) is stable within an epoch **[P3-pending: one admission per (nullifier, epoch)]** | F5.02, F5.03 |
| Keep using a revoked credential | revoke sets the leaf to 0; `/path` answers 410; old paths fail against the current root; staleness window never crosses a revocation **[P3-pending: gateway root check]** | F3.02-F3.07 |
| Prove the zero leaf of a revoked slot | the v4 circuit has no `leaf` input; the leaf is the in-circuit `attrHash` | F3.05 (SR-13) |
| **Self-enrol with chosen attributes, re-enrol after revocation, hold several credentials** | **Nothing today**: `POST /credentials` is unauthenticated (issuer.api v1, localhost-only by contract) | **SR-03 (HIGH, open)**; F2.14, F3.10 todo |
| Revoke other users (DoS) | admin bearer token, **only if `ISSUER_ADMIN_TOKEN` is set** | SR-04 |

Out of scope: a user who shares their own wallet file and secret with another person (credential
lending); side channels on the user's own machine.

### 2. Malicious issuer

| Can do | Bound | Evidence / note |
|---|---|---|
| Issue any attributes to anyone, including itself | Inherent: the issuer is the root of trust for attributes (scope M1). | — |
| Learn who enrols and their attributes | Inherent at enrolment. It never receives the secret or salt: the API rejects them and the client never sends them. | F6.01-F6.03 |
| Link a user to gateway accesses | It never sees proofs. It sees `/path/:leafIndex` once per root change and can correlate timing with a colluding gateway. | SR-08 (LOW) |
| Learn attributes from the tree | No: leaves are `attrHash` with a 248-bit-salted commitment inside. | F6.06 |
| Equivocate (different roots to different users/gateways) | The client checks its own leaf and root on enrolment; the gateway's root view is its own fetch. A split view lets the issuer partition users into small anonymity sets. **[P3-pending: gateway root source]** | out of scope for P2 |
| Hand the client a credential under another key | The client pins the issuer key (explicit > pin > TOFU) and verifies the signature before storing. | `client/src/enrol.js`; SR-09 |
| Leak its signing key | Key generated once, 0600, refused if readable, never served or logged, gitignored. | F9.01, F9.04, F9.05; SR-10 |

### 3. Compromised gateway [P3-pending]

What the circuit and client already bound: the gateway receives only `{resource, nonce, proof,
publicSignals}` (F6.04); the public signals carry no attribute, commitment, secret or path, and only
the nullifier differs between two users on the same service (F5.05); nullifiers differ across
services and epochs (F5.04, F5.06), so a breached gateway log links requests only within one service
and epoch (scope privacy table). A compromised gateway can admit anyone (it is the policy enforcement
point) and can choose policies and challenges; it cannot learn identities from proofs or forge
credentials. Log and state hygiene (floor 7) is a P3 test.

### 4. Network attacker

| Can try | What stops it |
|---|---|
| Read enrolment traffic | Sees commitment + attributes, never the secret. **Transport security (TLS) between client and issuer is not implemented in P2** (localhost/compose); required before any non-local deployment. |
| Replay a captured proof | nonce single-use **[P3-pending]**; proofs are bound to nonce, `now`, epoch, resource (F4.01, F4.05). |
| Tamper public signals in flight | Any change fails verify (F2.13). |
| Swap the issuer key the client sees | Pinning on enrolment; TOFU on first contact unless `expectedIssuer` is configured (SR-09). |

### 5. Insider abuse

| Insider | Can do | Bound |
|---|---|---|
| Issuer operator | revoke or issue arbitrarily; read the enrolment log | admin token (SR-04); logs hold no attributes or commitments (F7.01, F7.02) |
| Whoever ran the trusted setup | forge any proof under the DEV-ONLY keys | SR-06: multi-party ceremony G2-S1-CIRC-040 before any real use |
| Developer | commit a key or a wallet | `.gitignore` + floor 9 scan (F9.01-F9.04) |
| Gateway operator | read gateway logs | **[P3-pending]** floor 7 |
| Test-fixture user | configure a gateway with the TEST-ONLY pinned key | SR-07 |
