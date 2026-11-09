# ADR 0002 — Adopt the team's P1 v3 circuit as the base; remove the circuits prototype

**Status** Accepted · **Date** 2026-11-08 · **Task** G0-S1-ARCH-010

## Context

Two circuit lines existed. A circuits prototype (`AccessGate(16)`, `circuits/SPEC.md`, mutation
harness, committed depth-16 artefacts, contracts `credential.leaf v1` and
`access.public_signals v1.1`) was built in this repository first. In parallel the
team member who owns the circuit (P1) wrote `IntegratedAccessGate()` v3 on branch
`feature/p1-circuits-hamsa`. The team decided that the circuit is P1's and that
P2 (identity) builds the missing scope features on top of her code, in her style.

v3 as imported (measured 2026-11-08, circom 2.2.3, default `--O1`): 8116 non-linear + 1529 linear
constraints, 1 public input (`root`), 17 private inputs, no outputs. It proves knowledge of
`credentialSecret, credentialSalt` behind `credentialCommitment`, an EdDSA-Poseidon signature over
that commitment, depth-2 Merkle membership of the commitment, and the hard-coded `FileShareAccess`
policy. Gaps G-1…G-10 against the scope are listed in `docs/plan/p2-plan.md` §1.

## Decision

- `circuits/integrated_access_v3.circom` and `circuits/components/*.circom` are the base of the M3
  circuit. They are not rewritten in place; new behaviour lands in new components beside them and
  a new main `circuits/integrated_access_v4.circom` (ADR 0006, 0007).
- The prototype is removed and is not included in this repository. It was the **reference
  design** for the v4 work: ideas,
  tests and harnesses are ported into P1's structure, each with its own tests here, never copied
  wholesale.
- The prototype's contracts move to the Superseded section of `docs/CONTRACTS.md`. The current
  contracts are `credential v3` / `access.public_signals v3` (describing v3 exactly) and, for G1,
  `credential v4` / `access.public_signals v4`.
- v3 stays compilable until v4 passes the G1 gate, so the team can compare.

## Consequences

- G0 runs end to end on v3, which has **known floor gaps** (attributes unsigned, issuer key
  private, no expiry, no nonce/nullifier, depth 2). v3 is a pipeline baseline, never an admission
  path the gateway may rely on for floors 2, 4, 5.
- Floor 1 has to be re-established for P1's code: G0-S1-CIRC-020 adds the first tests; the
  mutation harness is ported in G1-S1-CIRC-036.
- Changes to P1's own files are small, separate commits reviewed by her (scope: second reviewer).
- The broken fragment `circuits/components/integrated_access.circom` is excluded from builds and
  its removal requested from P1 (G0-S1-CIRC-020).

## Alternatives considered

- **Keep the prototype as the circuit.** Rejected by the team: the circuit is P1's deliverable.
- **Rewrite v3 to the prototype's design.** Rejected: loses her authorship and review history.
