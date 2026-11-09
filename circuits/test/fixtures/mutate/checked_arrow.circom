pragma circom 2.1.6;
// Arrow-audit fixture: every <-- / --> is followed, in the same template, by an === on the signal.
template CheckedArrow(n) {
    signal input x[n];
    signal output y;
    signal inv[n];
    signal sq;
    for (var i = 0; i < n; i++) {
        inv[i] <-- x[i] != 0 ? 1 / x[i] : 0;
        x[i] * inv[i] === 1;
    }
    x[0] * x[0] --> sq;
    sq
      === x[0] * x[0];   // multi-line check
    y <== sq;
}
