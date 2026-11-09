# zk-kit 1.1.0 pathIndices = v3 convention (verified, not assumed)

`@zk-kit/incremental-merkle-tree` 1.1.0 `createProof` sets `pathIndices[level] = index % arity`
(1 = current node is the right child), same as P1's `MerkleMembership`. `siblings` is an array of
arrays: `pathElements[i] = siblings[i][0]`. The hash fn receives an array: wrap circomlibjs as
`xs => F.toObject(poseidon(xs))`. `delete(i)` writes `zeroes[0]` (= zeroValue 0).

zk-kit is NOT in root package.json; verified by `npm pack` into the scratchpad and a scratch run
(leaves [11,c,33,44], depth 2 → pathIndices [1,0], root equals v3's computation). Recorded in
`docs/CONTRACTS.md` Common rules. Related: [[gitignore-vs-d7-and-keys]].
