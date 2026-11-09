# Public signal order = template declaration order

snarkjs `publicSignals` = outputs first, then public inputs in the order their `signal input` lines
appear in the template — NOT the order in `component main {public [...]}`. Verified with circom
2.2.2 by declaring `b` before `a` with `public [a, b]`: the .sym file put `b` first.
`AccessGate` must declare public inputs in the contract order (`access.public_signals v1.1`; order unchanged from v1), and a
test should read the .sym to assert it.
