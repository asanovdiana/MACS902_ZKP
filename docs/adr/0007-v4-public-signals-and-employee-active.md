# ADR 0007 — v4 public-signal order; `employeeActive` always required (D5)

**Status** Accepted (team, 2026-11-08) · **Date** 2026-11-08 · **Task** G1-S1-ARCH-011

## Context

v3 exposes only `[root]`: the gateway cannot pin the issuer, select a policy, check freshness,
prevent replay or rate-limit (gaps G-2, G-3, G-4, G-6). The gateway (P3) was designed against the
prototype's 12-signal order (`access.public_signals v1.1`). P1's policy requires
`employeeActive === 1`; the question was whether that becomes a policy field.

## Decision

- v4 public signals, in this exact snarkjs `publicSignals` order:

  ```
  [nullifier, root, issuerAx, issuerAy, roleMask, deptMask, minClearance, requireDevice,
   now, nonce, resourceId, epoch]
  ```

  `nullifier` is the only output (snarkjs puts outputs first); the 11 public inputs follow in
  **template declaration order** (circom orders public inputs by their `signal input` lines, not by
  the `public [...]` list), so the v4 main must declare them in this order and a test reads the
  `.sym` to assert it.
- Same order as the prototype, so P3's gateway design carries over; names are camelCase to match
  P1's style.
- `employeeActive === 1` is enforced for every proof and is **not** a policy field: an inactive
  employee is never admitted anywhere. To cut off an employee, the issuer also revokes the leaf.
- Every public input appears in at least one constraint; `nonce` gets a dummy square
  (`nonceSquared <== nonce * nonce`), so tampering any public signal fails Groth16 verify.
- Encoding is canonical decimal (contract `access.public_signals v4`); gateway state is keyed on
  canonical integers, never on proof bytes.

## Consequences

- One circuit and one key set serve every service; policies are public inputs (scope M3).
- Adding a policy field later is a new contract version and a new trusted setup.
- The gateway's obligations (pin issuer key, root freshness, policy match, `now` freshness, nonce,
  nullifier per epoch) are listed in the contract; without them the circuit's guarantees do not
  reach floors 2–5.

## Alternatives considered

- **`requireActive` as a public policy field.** Rejected: no demo policy admits inactive
  employees, and a field that is always 1 is an extra way to misconfigure a policy.
- **A new order grouping policy fields last.** Rejected: breaks P3's existing design for no gain.
