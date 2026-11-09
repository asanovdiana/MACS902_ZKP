# Concrete values that beat circomlib comparators without range checks

`LessThan(n)` only bit-decomposes `in[0] + 2^n - in[1]` into n+1 bits, so out-of-range inputs pass:
- `LessThan(64)(now, expiry)`: `expiry = now + 2^64` (diff 0 -> out 1) and `now = p - 1`
  (wraps to 2^64 - 1 - expiry) both give out = 1.
- `GreaterEqThan(2)(clearance, min)`: `clearance = 5, min = 3` and `clearance = 0, min = p - 1`
  give out = 1.
These are the witness tampers that kill a `Num2Bits.in <-- x` mutant in a one-row test
([[v4-splice-circomlib-subwitness]]). Measured costs (circom 2.2.3): AccessPolicyV4 28 at --O2
(29 + 54 at O0); ExpiryCheck 192 at --O2 (193 + 10 at O0). See [[component-costs-o2]].
