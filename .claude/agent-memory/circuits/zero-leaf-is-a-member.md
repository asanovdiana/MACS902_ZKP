# Zero leaf at an empty (or revoked) index is a provable member

With the Common-rules tree (zero leaf 0, zk-kit style), `MerkleMembershipN` accepts leaf 0 at any
empty index, and revocation sets a leaf to 0, so a revoked slot is also "member 0". This is safe
only because the v4 leaf is `attrHash` (a Poseidon(7) output, never 0 in practice) and the leaf is
computed in-circuit, not an input. Do not make the leaf a free input again. Pinned as a
documentation test in `circuits/test/merkle_depth.test.js` ("documented property").
See [[v4-building-blocks-components]].

Addendum (G1-S1-CIRC-039, SR-13): the rule is also a comment in
`circuits/components/merkle_membership_n.circom`: any main taking `leaf` as an input adds `leaf != 0`.
