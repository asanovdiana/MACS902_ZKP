# v4 circuit must use the lib's input signal names

`circuits/lib` `buildInputV4` (G1-S1-CIRC-038) emits, in this key order: private
`credentialSecret, credentialSalt, role, dept, clearance, deviceCompliant, employeeActive, expiry,
R8x, R8y, S, pathElements[16], pathIndices[16]`, then public `root, issuerAx, issuerAy, roleMask,
deptMask, minClearance, requireDevice, now, nonce, resourceId, epoch`; output `nullifier`. No `M`,
`leaf`, `Ax`, `Ay`. The v4 main (CIRC-031..036) must declare exactly these, public inputs in this
order (see [[public-signal-order-is-declaration-order]]); CIRC-036 adds the v4 witness test to
`circuits/test/lib.test.js` using `vectors/v4/input.alice.wiki.json`.
Builder check order: schema -> precheck -> secret/commitment -> signature -> leaf -> root, so a
tampered attribute reports BAD_SIGNATURE, not LEAF_MISMATCH. Related: [[v3-fileshare-alice-is-opaque]].
