# eddsa_verifier.circom is a mutate:v4 target (SR-18)

`mutate:v4` also mutates her `components/eddsa_verifier.circom` (7 sites: `verifier.enabled <== 1`
and `verifier.X <== X` for Ax, Ay, R8x, R8y, S, M). Gate-side tests (`signature.X <== X`) do NOT
kill them: the link row is one level deeper. Kills are the v4 witness-level tests
"negatives gate: IssuerSignatureCheck verifier.*" in `circuits/test/v4.test.js`: move main, the
on-curve copy and `signature.X` together (negate x/y; `add` for S), verifier honest; for M splice
Bob's signature into `main.signature.` then put Alice's attrHash back in `signature.M`; for enabled
zero `verifier.enabled` and both `eqCheck*.enabled`. Mirrors the v3 recipes. `mutate.test.js`
asserts the target is listed. See [[v4-gate-one-row-recipes]], [[mutation-harness-p2-layout]].
