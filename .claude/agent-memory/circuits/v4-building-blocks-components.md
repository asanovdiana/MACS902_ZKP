# v4 building blocks: MerkleMembershipN, AttributeHash, SignaturePointsOnCurve

G1-S1-CIRC-030/031/032 (2026-11-08). Her files untouched: `MerkleMembershipN(depth)` lives in
`components/merkle_membership_n.circom` (option (a)), a copy of her body with the same signal
names; `MerkleMembershipN(2)` gives a constraint-for-constraint identical R1CS and identical .sym
to her `MerkleMembership()` at O0/O1/O2 (asserted), so it can replace hers in v4 with no doubt.
Counts at O2: Merkle 243 non-linear per level (depth 16 = 3888); AttributeHash 389 (Poseidon(7) 381
+ 3×Num2Bits(2) = 6 + 2 booleans); SignaturePointsOnCurve 6. Range split: AttributeHash owns
role/dept/clearance Num2Bits(2) + flag booleans; expiry Num2Bits(64) and `employeeActive === 1`
are for the expiry/policy components, so the v4 main must wire them. Policy components that also
Num2Bits(2) role/dept duplicate rows harmlessly. Test mains in `circuits/test/circuits/`.
See [[v4-building-blocks-sweep]], [[zero-leaf-is-a-member]], [[v3-one-violated-row-tamper]].
