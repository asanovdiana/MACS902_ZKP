# ADR 0006 — v4 attribute hash is the signed message and the leaf (D4)

**Status** Accepted · **Date** 2026-11-08 · **Task** G1-S1-ARCH-011

## Context

In v3 the signed message `M` and the Merkle leaf are both `credentialCommitment`; the attributes
`role, clearance, deviceCompliant, employeeActive` are free private inputs. Changing them while
keeping the signature still produces a witness (verified 2026-11-08): any credential holder can
claim any attributes, violating floor 2 (tampered attribute). v3 also has no `dept` and no
`expiry` (gaps G-1, G-4, G-7).

## Decision

v4 binds every attribute and the commitment into one hash:

```
attrHash = Poseidon(7)(role, dept, clearance, deviceCompliant, employeeActive, expiry, credentialCommitment)
M        = attrHash        (EdDSA-Poseidon signed message)
leaf     = attrHash        (Merkle leaf)
```

- Input order is normative (as written). Poseidon(7) is circomlib `Poseidon(7)` / circomlibjs
  `buildPoseidon` with 7 inputs.
- `M` and `leaf` are computed in-circuit from the attributes and the commitment; they are **not**
  inputs of the v4 circuit.
- Ranges are enforced in-circuit (`credential v4`): role, dept, clearance 0..3; deviceCompliant,
  employeeActive 0/1; expiry < 2^64.
- `employeeActive` stays an attribute (P1's) and is required to be 1 (ADR 0007).

## Consequences

- Tampering any attribute changes `attrHash`, so the original signature fails and the leaf is not
  in the tree (closes G-1, G-7 with `dept`, part of G-4 with `expiry`).
- Revocation removes the `attrHash` leaf; re-issuing different attributes is a new leaf.
- The issuer learns the attributes (it assigns them, scope M1) and the commitment, never the
  secret or salt.
- Six attributes plus commitment = 7 inputs, within circomlib's Poseidon width (≤ 16).

## Alternatives considered

- **Prototype layout `Poseidon(6)(…, secret_commitment)` without `employeeActive`.** Rejected:
  drops P1's attribute.
- **Sign the attributes, leaf = commitment.** Rejected: a revoked-then-reissued user would keep
  one leaf for two attribute sets, and the tree would not attest attributes.
