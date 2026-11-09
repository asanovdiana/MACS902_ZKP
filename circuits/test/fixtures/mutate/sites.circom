pragma circom 2.1.6;
// Parser fixture for circuits/scripts/mutate (never compiled; from the removed circuits prototype).
// Decoys in comments must NOT become sites: a === b; x <== y; y ==> z;
include "circomlib/circuits/poseidon.circom";

/* block comment decoy:
   out <== in * in;
   in === 0;
*/
template Sites(n) {
    signal input in[n];
    signal input s;
    signal output out;
    signal acc[n + 1];
    signal inv;

    acc[0] <== 0;                       // line 17: plain <==
    for (var i = 0; i < n; i++) {
        acc[i + 1] <==                  // line 19: multi-line <== inside a loop
            acc[i]
            + in[i] * in[i];
    }
    for (var j = 0; j < n; j++) in[j] * (in[j] - 1) === 0;   // line 23: unbraced loop body
    if (n > 1) {
        s * s ==> out;                  // line 25: ==> inside a conditional
    } else {
        out <== s; /* trailing */       // line 27: else branch
    }
    inv <-- s != 0 ? 1 / s : 0;         // line 29: <-- is not a mutation site
    s * inv === 1;                      // line 30: checks inv
    log("x === y <== z");               // string decoy, not a site
}

component main {public [s]} = Sites(2);
