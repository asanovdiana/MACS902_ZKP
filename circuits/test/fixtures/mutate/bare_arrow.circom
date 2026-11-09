pragma circom 2.1.6;
// Arrow-audit fixture: `inv` is assigned with <-- and never checked by an ===  (must be flagged).
template BareArrow() {
    signal input x;
    signal output y;
    signal inv;
    inv <-- x != 0 ? 1 / x : 0;
    y <== x + 1;
}

// `t` is checked, but only by an === in a DIFFERENT template that happens to share the name.
template Other() {
    signal input a;
    signal t;
    t <-- a * a;
}

template Third() {
    signal input a;
    signal t;
    t <== a;
    t === a;
}
