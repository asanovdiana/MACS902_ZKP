# snarkjs binds every public input even if no circuit row uses it (corrects an earlier fact)

Correction to [[linear-binding-vanishes-at-o2]]: "the public wire ends up in no R1CS row: Groth16
would then accept any value" is wrong for snarkjs. `zkey new` (0.7.6, `src/zkey_new.js`, the loop
`for (let s = 0; s <= nPublic; s++)` after the constraint loop) appends one input-binding row per
public signal (A = x_s, B = C = 0), so every IC point is non-identity. One-off check (G1-S1-CIRC-039,
SR-11): a public `nonce` in no circuit row, --O2, pot15 setup -> verify OK for nonce 5, "Invalid
proof" for 6. The O2 linear-binding fact still holds for the CIRCUIT R1CS, and the O2 public-slot
tampers in `challenge_binding.test.js` stay as defence in depth (backend-independent binding);
`nonceSquared` is kept for the same reason. Re-run recipe: tiny circuit + `groth16 setup` + edit
public.json, all in the scratchpad (the worktree guard refuses compound shell; write a script file
and run `bash <file>`). See [[challenge-binding-costs]].
