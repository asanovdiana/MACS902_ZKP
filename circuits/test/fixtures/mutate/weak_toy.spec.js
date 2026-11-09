"use strict";
// DELIBERATELY WEAK spec for circuits/test/mutate.test.js: only the positive case of toy.circom,
// so the harness must report surviving mutants with it. Never run by `npm test` directly.
const path = require("path");
const { buildPoseidon } = require("circomlibjs");
const { compileCached } = require("../../helpers");

const FILE = path.join(__dirname, "toy.circom");

describe("weak toy spec (positive only)", function () {
  it("accepts the correct secret", async function () {
    const poseidon = await buildPoseidon();
    const t = await compileCached("mutate-toy-weak-O0", FILE, [FILE], { O: 0 });
    await t.checkConstraints(await t.calculateWitness({ secret: 42n, h: poseidon.F.toObject(poseidon([42n])) }, true));
  });
});
