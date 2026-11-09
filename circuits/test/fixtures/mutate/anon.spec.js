"use strict";
// Spec for anon.circom (see there). Positive case only; never run by `npm test` directly.
const path = require("path");
const { buildPoseidon } = require("circomlibjs");
const { compileCached } = require("../../helpers");

const FILE = path.join(__dirname, "anon.circom");

describe("anon fixture", function () {
  it("computes Poseidon(a)", async function () {
    const poseidon = await buildPoseidon();
    const t = await compileCached("mutate-anon-O0", FILE, [FILE], { O: 0 });
    const w = await t.calculateWitness({ a: 7n }, true);
    await t.assertOut(w, { o: poseidon.F.toObject(poseidon([7n])) });
  });
});
