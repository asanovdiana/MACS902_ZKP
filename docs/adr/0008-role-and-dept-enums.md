# ADR 0008 — Role and department enums (D6)

**Status** Accepted · **Date** 2026-11-08 · **Task** G0-S1-ARCH-010

## Context

The scope lists roles "engineer / admin / contractor / finance" and "dept (4 values)" without
numbers. P1's v3 `FileShareAccess` hard-codes `role ∈ {2,3}` and `clearance ∈ {2,3}` with no
stated meaning for the numbers. The policies are bitmasks over these values (v4), so the numbers
must be fixed once for issuer, client, circuit lib and gateway.

## Decision

| Value | `role` | `dept` |
|---|---|---|
| 0 | engineer | engineering |
| 1 | admin | it |
| 2 | contractor | operations |
| 3 | finance | finance |

- Role order is the scope's order. `clearance` is the integer 0..3 (no names).
- Mask bit `i` (value `2^i`) allows enum value `i`: `roleMask`, `deptMask` ∈ 0..15.
- The table lives once in `circuits/lib` (ADR 0004) and in the contracts; issuer and client
  import it.
- v3's `FileShareAccess` values are **not** given role names. In the v3 profile, `role` and
  `clearance` are opaque integers that must lie in {2,3} for a proof to exist; v4 replaces that
  template with the generic `AccessPolicy` (G1-S1-CIRC-033).

## Consequences

- Demo policies: Wiki `roleMask 0b1111`, File Share engineer|admin `0b0011`, Admin Panel admin
  `0b0010` (`access.public_signals v4`).
- A v3 credential issued for the G0 end-to-end run uses role/clearance in {2,3}; that says nothing
  about the person's real role under D6.
- Adding a fifth role or department means widening the masks: a new contract version and setup.

## Alternatives considered

- **Re-map v3 values (2 = engineer, 3 = admin).** Rejected: v3 is retired by v4; reinterpreting it
  would leave two meanings for the same number.
