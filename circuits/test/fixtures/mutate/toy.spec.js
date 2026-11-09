"use strict";
// Spec for toy.circom (harness self-test in circuits/test/mutate.test.js). Named *.spec.js so the
// default mocha glob (circuits/test/**/*.test.js) never runs it directly. TEST-ONLY values.
const path = require("path");
const { buildPoseidon } = require("circomlibjs");
const { compileCached, expectReject, NamedWitness } = require("../../helpers");

const FILE = path.join(__dirname, "toy.circom");
const compileToy = () => compileCached("mutate-toy-O0", FILE, [FILE], { O: 0 });

describe("toy", function () {
  let h;
  before(async function () {
    const poseidon = await buildPoseidon();
    h = poseidon.F.toObject(poseidon([42n]));
  });

  it("positives: accepts the correct secret", async function () {
    const t = await compileToy();
    await t.checkConstraints(await t.calculateWitness({ secret: 42n, h }, true));
  });

  it("C-TOY-1 negatives: a wrong secret fails witness generation", async function () {
    const t = await compileToy();
    await expectReject(t.calculateWitness({ secret: 43n, h }, true), /Assert Failed/);
  });

  it("C-TOY-1 negatives: a witness whose private secret was overwritten is rejected", async function () {
    const t = await compileToy();
    const nw = new NamedWitness(t, await t.calculateWitness({ secret: 42n, h }, true));
    nw.set("main.secret", 43n);
    await expectReject(t.checkConstraints(nw.w), /Constraint doesn't match/);
  });
});
