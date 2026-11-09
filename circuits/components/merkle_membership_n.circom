pragma circom 2.2.3;

// MerkleMembershipN(depth) — G1-S1-CIRC-030.
//
// Her MerkleMembership() (components/merkle_membership.circom) with the depth as a template
// parameter. The body is hers, line for line, with 2 -> depth and 3 -> depth + 1; signal and
// component names are unchanged, so witness-tamper recipes written for v3 carry over.
// MerkleMembershipN(2) compiles to the same R1CS as MerkleMembership() (asserted by
// test/merkle_depth.test.js), which is why her file and her v3 main stay untouched
// (p2-plan §2.1: her code stays the base; option (a) of the task).
//
// Tree: Common rules (docs/CONTRACTS.md). node = Poseidon(2)(left, right); level 0 = leaf level;
// pathIndices[i] = 1 means the current node is the RIGHT child, i.e. the zk-kit convention
// pathIndices[i] = (leafIndex >> i) & 1, pathElements[i] = proof.siblings[i][0].
//
// Constraints per level i: pathIndices[i] boolean; left[i], right[i] the selected pair;
// hashers[i] = Poseidon(2)(left[i], right[i]); hashes[i+1] = its output. Then hashes[depth] === root.
// No `<--` anywhere.
//
// SR-13: leaf 0 is a member of every tree (empty and revoked slots hold 0). v4 is safe because
// its leaf is the in-circuit attrHash; any main that takes `leaf` as an input must add `leaf != 0`.
include "../../node_modules/circomlib/circuits/poseidon.circom";

template MerkleMembershipN(depth) {
    assert(depth >= 1);

    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input root;

    signal hashes[depth + 1];
    signal left[depth];
    signal right[depth];

    component hashers[depth];

    hashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        left[i] <==
            hashes[i] + pathIndices[i] *
            (pathElements[i] - hashes[i]);

        right[i] <==
            pathElements[i] + pathIndices[i] *
            (hashes[i] - pathElements[i]);

        hashers[i] = Poseidon(2);

        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== right[i];

        hashes[i + 1] <== hashers[i].out;
    }

    hashes[depth] === root;
}
