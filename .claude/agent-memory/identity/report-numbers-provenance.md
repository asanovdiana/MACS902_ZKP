# Where the report numbers come from

The "263 checked values" of the cross-check suite is in no committed file: it is the last table line the suite prints (`total checked values: 263`) in `npm test --prefix issuer`. The plan row "root suite 263" is an older, different count. Root `npm test` at the time of writing = 859 passing (3 min; needs `npm ci` at root and circom in ~/.cargo/bin). Re-run before quoting again. See [[crosscheck-suite-harness]].
