# zk-kit zeroes has depth entries, not depth+1

`tree.zeroes` lists levels 0..depth-1; the empty-tree root is one more Poseidon(zeroes[d-1], zeroes[d-1]). Inner level arrays are only reachable via private `tree._nodes` (used by `registry.adminTree`; recheck on a zk-kit upgrade). `tree.delete(i)` keeps `_nodes[0]` length.
