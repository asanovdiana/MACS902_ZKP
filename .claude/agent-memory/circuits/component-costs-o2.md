# Building-block costs at --O2 (beyond constraint-counts-o2)

Measured in isolation by `perf/components.js` (reports/perf-components.json): Poseidon(4) 297,
(5) 321, (8) 402, (16) 609; EscalarMulAny(254) 2310 vs EscalarMulFix(253/254) 523/524;
Num2Bits_strict 515 (254 + 261 alias check); CompConstant(l) 262; BabyCheck 3; BabyDbl/BabyAdd 6;
MaskContains 10; GreaterThan(64) 65; policy block C8-C23 222. EdDSAPoseidonVerifier 4207 is mostly
the 2310 variable-base mul — a compile-time issuer key (EscalarMulFix) makes it 2396. A 4-ary
Poseidon(4) Merkle level costs 306 (= 153 per binary level vs 242). The AccessGate block sum
reproduces 9135 exactly, so the per-block table in circuits/OPTIMISATION.md is trustworthy.
Builds on [[constraint-counts-o2]].
