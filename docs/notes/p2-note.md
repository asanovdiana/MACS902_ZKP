# P2 note — how my part was built on P1's circuit

**From:** P2 (identity: M1 issuer, M2 registry and revocation, M4 client prover)
**Date:** 2026-11-08

## What I received

I received P1's circuit from the `feature/p1-circuits-hamsa` branch: `integrated_access_v3.circom`, its
three components and the input generator. Thank you — it gave the project a working base: it compiles,
the commitment, the issuer signature check and the Merkle membership all work, and the File Share rule
is enforced.

## What I checked

Before building on it I imported it unchanged and tested it:

- it compiles with circom 2.2.3 and produces a valid witness for its own generated input;
- a role outside the File Share rule is correctly rejected;
- I then wrote a full test suite for it (each constraint has a test that fails when the constraint is
  removed).

The tests also showed what v3 does not cover yet, compared with the project scope:

- the attributes (role, clearance, …) are not part of what the issuer signs, so changing them with the
  same signature still passes;
- the issuer's key is a private input, so a self-made key is accepted;
- the policy is fixed to File Share; there is no expiry, no replay protection (nonce), no nullifier for
  rate limiting, and the tree holds 4 users.

These are normal for a first version — they are just the next steps the scope asks for.

## Why I had to finish it further

My part (P2) is the issuer, the registry and the client prover. All three depend directly on the
circuit's interface:

- the issuer has to know **what to sign** — and that only makes sense once the attributes are bound to
  the signature;
- the registry has to match the circuit's **tree** (depth, hashing, path format);
- the client has to build exactly the **inputs and public signals** the circuit expects, including the
  challenge (nonce, resource, epoch) from the gateway.

With v3's interface my components could not meet their own done criteria from the scope (for example,
"a revoked user's proof against the new root fails" and "end-to-end proof generation from a credential
file"), and they would have had to be rewritten once the circuit changed. So, as agreed, I completed the
circuit to the scope **on top of P1's work**:

- **P1's files were not changed.** v3 stays in the repository exactly as received, with its tests.
- The new parts are separate components next to hers, reusing her signature check, commitment and
  Merkle logic, and a new main circuit `integrated_access_v4.circom`.
- Every addition is documented as a decision (ADRs 0002–0009) and recorded as a contract in
  `docs/CONTRACTS.md` before it was built.

## What I built for P2

- **Issuer (M1):** admin-approved enrolment with one-time codes; the issuer signs the admin's
  attributes and only ever sees the user's commitment.
- **Registry and revocation (M2):** depth-16 tree, revocation by zeroing the leaf, current root and
  history for the gateway, admin API with live root updates.
- **Client prover (M4):** local wallet, issuer-key pinning, local policy check, proof in about 1 s,
  `zkgate` command line.
- Supporting work: the shared encoder library, trusted-setup keys, ready-made test proofs for the
  gateway, Attack Lab scripts and a security test suite.

Everything is described in [`../p2-work.md`](../p2-work.md); the checkpoint result (G1: conditional,
nothing failed) is in [`../gates/G1/summary.md`](../gates/G1/summary.md).

## What I would like from P1

A review of the v4 additions (the scope asks for a second reviewer on every circuit change), and any
corrections — if something should be done differently in the circuit, I will adapt my parts to it.
Details in [`next-steps-for-p1-and-p3.md`](next-steps-for-p1-and-p3.md).
