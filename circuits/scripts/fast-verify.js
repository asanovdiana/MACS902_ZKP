"use strict";
// Fast Groth16 (BN254) verifier for a long-running service: the default implementation behind
// circuits/scripts/verify.js verify() (G1-S1-CIRC-037; ported unchanged in substance from the
// removed circuits prototype, where it shipped as G1-S1-CIRC-011).
// Measurements: circuits/reports/perf-v4.md. Differential test: circuits/test/fast_verify.test.js.
// Most callers want verify.js (input rules, per-vkey cache, escape hatch), not this module.
//
// It checks the same pairing equation as snarkjs.groth16.verify on the same ffjavascript wasm:
//
//     e(-A, B) · e(vk_x, gamma) · e(C, delta) == e(alpha, beta)^-1,   vk_x = IC0 + Σ pub_i·IC_i
//
// restructured so that per-request work is minimal:
//   - the vkey is parsed and validated once (makeVerifier), not on every call;
//   - e(alpha, beta)^-1 is computed once, and gamma and delta are prepared once (prepareG2), so a
//     request does 1 prepareG2 + 3 Miller loops + 1 final exponentiation (snarkjs: 4 + 4 + 1);
//   - vk_x is one synchronous wasm multi-exponentiation on the calling thread instead of
//     multiExpAffine split over the worker pool, whose round-trips dominate for 12 points;
//   - the independent pieces overlap: e(-A,B) and e(C,delta) Miller loops and the [r]B subgroup
//     check run on the curve's worker pool while this thread does vk_x and e(vk_x,gamma).
//     On a single-thread curve the same tasks run inline (same result, slower).
//
// Proof-point checks (match or exceed snarkjs 0.7.6 / ffjavascript 0.3.1):
//   snarkjs     : A, C: G1.isValid (on curve, or the point at infinity);
//                 B: G2.isValid (on the twist, or infinity) — NO G2 subgroup check.
//   this module : A, C: on curve AND not infinity. G1 of BN254 has cofactor 1, so on-curve means
//                 in the prime-order group.
//                 B: on the twist AND not infinity AND in the order-r subgroup ([r]B == O).
//                 The twist E'(Fp2) has order r·(2p − r), so on-curve alone admits points outside
//                 G2; snarkjs accepts those and leaves them to the pairing. We reject them up front.
//                 An honest prover never outputs infinity for A, B or C (they carry fresh
//                 randomness r, s), so rejecting it costs no completeness.
// Public signals: canonical decimal strings < r (the same rule as scripts/verify.js
// isCanonicalSignal), checked here too so the module is safe on its own.
const crypto = require("crypto");
const { buildBn128, utils, Scalar } = require("ffjavascript");

// BN254 scalar field order r (circom / snarkjs `p`) and base field order q.
const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const CANONICAL = /^(?:0|[1-9][0-9]*)$/;

/** Canonical decimal string with value < r. Never throws. */
function isCanonicalScalar(s) {
  return typeof s === "string" && s.length <= 77 && CANONICAL.test(s) && BigInt(s) < FR;
}

/**
 * Content hash of the fields of a Groth16 vkey that determine verification. Two vkeys with the
 * same hash verify identically. Throws on a non-serialisable vkey (callers catch).
 * @param {object} vkey
 * @returns {string} hex sha256
 */
function vkeyHash(vkey) {
  const k = vkey || {};
  const material = JSON.stringify([
    k.protocol, k.curve, k.nPublic, k.vk_alpha_1, k.vk_beta_2, k.vk_gamma_2, k.vk_delta_2, k.IC,
  ]);
  return crypto.createHash("sha256").update(material).digest("hex");
}

/**
 * Checks on the three proof points (internal ffjavascript representation). See header.
 * @returns {boolean}
 */
function proofPointsValid(curve, A, B, C) {
  return proofPointsOnCurve(curve, A, B, C) && g2InSubgroup(curve, B);
}

/** All of proofPointsValid except the G2 subgroup check (which verify() runs on a worker). */
function proofPointsOnCurve(curve, A, B, C) {
  const { G1, G2 } = curve;
  if (G1.isZero(A) || G1.isZero(C) || G2.isZero(B)) return false;
  return G1.isValid(A) && G1.isValid(C) && G2.isValid(B);
}

/** [r]Q == O. Plain scalar multiplication: slower than an endomorphism test but obviously right. */
function g2InSubgroup(curve, Q) {
  return curve.G2.isZero(curve.G2.timesScalar(Q, FR));
}

/** Parse snarkjs proof JSON into curve points; throws on malformed input (callers catch). */
function parseProof(curve, proof) {
  const pf = utils.unstringifyBigInts({ pi_a: proof.pi_a, pi_b: proof.pi_b, pi_c: proof.pi_c });
  return { A: curve.G1.fromObject(pf.pi_a), B: curve.G2.fromObject(pf.pi_b), C: curve.G1.fromObject(pf.pi_c) };
}

let sharedCurve = null; // Promise<curve>

/**
 * The process-wide BN254 curve used by scripts/verify.js: ffjavascript's multi-thread curve, i.e.
 * the same `globalThis.curve_bn128` snarkjs uses (one worker pool per process, not two).
 */
function getSharedCurve() {
  if (!sharedCurve) {
    sharedCurve = buildBn128(false);
    sharedCurve.catch(() => {
      sharedCurve = null;
    });
  }
  return sharedCurve;
}

/** Terminate the shared curve (if built). The next getSharedCurve() builds a new one. */
async function terminateSharedCurve() {
  const p = sharedCurve;
  sharedCurve = null;
  if (p) {
    try {
      const c = await p;
      if (globalThis.curve_bn128 === c) delete globalThis.curve_bn128;
      await c.terminate();
    } catch (_) {
      /* already gone */
    }
  }
}

/**
 * Build a verifier for one vkey.
 * @param {object} vkey snarkjs Groth16 verification key (bn128)
 * @param {{curve?: object, singleThread?: boolean}} [opt] `curve`: an ffjavascript bn128 curve to
 *        use (not terminated by the verifier). Otherwise the verifier builds and owns one
 *        (single-thread, no workers, when `singleThread` is true).
 * @returns {Promise<{verify(publicSignals: string[], proof: object): Promise<boolean>,
 *          linearCombination(scalars: string[]): Uint8Array, nPublic: number,
 *          hash: string, terminate(): Promise<void>}>}  verify() never throws
 * @throws if the vkey is not a well-formed groth16/bn128 key with valid points
 */
async function makeVerifier(vkey, opt = {}) {
  if (!vkey || typeof vkey !== "object" || vkey.protocol !== "groth16" || vkey.curve !== "bn128") {
    throw new Error("groth16/bn128 vkey required");
  }
  const nPublic = vkey.nPublic;
  if (!Number.isInteger(nPublic) || nPublic < 0 || !Array.isArray(vkey.IC) || vkey.IC.length !== nPublic + 1) {
    throw new Error("vkey nPublic / IC mismatch");
  }
  const owns = !opt.curve;
  const curve = opt.curve || (await buildBn128(!!opt.singleThread));
  try {
    const { G1, G2, Gt } = curve;
    const vk = utils.unstringifyBigInts(vkey);
    const IC = vk.IC.map((p) => G1.fromObject(p));
    const alpha = G1.fromObject(vk.vk_alpha_1);
    const beta = G2.fromObject(vk.vk_beta_2);
    const gamma = G2.fromObject(vk.vk_gamma_2);
    const delta = G2.fromObject(vk.vk_delta_2);
    if (!IC.every((p) => G1.isValid(p)) || !G1.isValid(alpha)) throw new Error("vkey G1 point off curve");
    for (const q of [beta, gamma, delta]) {
      if (G2.isZero(q) || !G2.isValid(q) || !g2InSubgroup(curve, q)) throw new Error("vkey G2 point invalid");
    }
    // Precomputation. millerLoop takes prepareG1/prepareG2 output of JACOBIAN points (that is
    // what pairingEq feeds it); passing affine buffers silently gives a wrong result.
    const target = Gt.inv(curve.pairing(alpha, beta));
    const preGamma = curve.prepareG2(G2.toJacobian(gamma));
    const preDelta = curve.prepareG2(G2.toJacobian(delta));
    const hash = vkeyHash(vkey);
    const bases = new Uint8Array(G1.F.n8 * 2 * nPublic); // IC[1..n], affine, internal form
    for (let i = 0; i < nPublic; i++) bases.set(G1.toAffine(IC[i + 1]), G1.F.n8 * 2 * i);
    const tm = curve.tm;

    /**
     * vk_x = IC0 + Σ s_i·IC_i for canonical decimal scalars s_i < r. One synchronous call to the
     * wasm multi-exponentiation (g1m_multiexpAffine, the routine snarkjs's multiExpAffine runs
     * in chunks on its workers) on the calling thread: ~0.8 ms vs ~1.3 ms for 12 timesScalar.
     */
    function linearCombination(scalars) {
      if (nPublic === 0) return IC[0];
      const sc = new Uint8Array(32 * nPublic);
      for (let i = 0; i < nPublic; i++) Scalar.toRprLE(sc, 32 * i, BigInt(scalars[i]), 32);
      tm.startSyncOp();
      let acc;
      try {
        const pB = tm.allocBuff(bases);
        const pS = tm.allocBuff(sc);
        const pR = tm.alloc(G1.F.n8 * 3);
        tm.instance.exports.g1m_multiexpAffine(pB, pS, 32, nPublic, pR);
        acc = tm.getBuff(pR, G1.F.n8 * 3);
      } finally {
        tm.endSyncOp();
      }
      return G1.add(acc, IC[0]);
    }

    const P = curve.name; // "bn128": wasm export prefix
    // Worker task: Miller loop of (g1, prepared-or-raw g2). With `preQ` the G2 lines are reused.
    const millerTask = (g1Jac, g2Jac, preQ) => {
      const t = [
        { cmd: "ALLOCSET", var: 0, buff: g1Jac },
        { cmd: "ALLOC", var: 1, len: curve.prePSize },
        preQ ? { cmd: "ALLOCSET", var: 3, buff: preQ } : { cmd: "ALLOC", var: 3, len: curve.preQSize },
        { cmd: "ALLOC", var: 4, len: Gt.n8 },
        { cmd: "CALL", fnName: P + "_prepareG1", params: [{ var: 0 }, { var: 1 }] },
      ];
      if (!preQ) {
        t.push({ cmd: "ALLOCSET", var: 2, buff: g2Jac });
        t.push({ cmd: "CALL", fnName: P + "_prepareG2", params: [{ var: 2 }, { var: 3 }] });
      }
      t.push({ cmd: "CALL", fnName: P + "_millerLoop", params: [{ var: 1 }, { var: 3 }, { var: 4 }] });
      t.push({ cmd: "GET", out: 0, var: 4, len: Gt.n8 });
      return tm.queueAction(t);
    };
    // Worker task: [r]Q for the G2 subgroup check (same wasm routine as G2.timesScalar).
    const rLE = Scalar.toLEBuff(FR);
    const subgroupTask = (g2Jac) =>
      tm.queueAction([
        { cmd: "ALLOCSET", var: 0, buff: g2Jac },
        { cmd: "ALLOCSET", var: 1, buff: rLE },
        { cmd: "ALLOC", var: 2, len: G2.F.n8 * 3 },
        { cmd: "CALL", fnName: "g2m_timesScalar", params: [{ var: 0 }, { var: 1 }, { val: rLE.byteLength }, { var: 2 }] },
        { cmd: "GET", out: 0, var: 2, len: G2.F.n8 * 3 },
      ]);

    /**
     * The three independent pieces run concurrently: e(-A, B) Miller loop (with prepareG2(B)), the
     * [r]B subgroup check and the e(C, delta) Miller loop go to the curve's worker pool, while
     * this thread computes vk_x and the e(vk_x, gamma) Miller loop. Then the product, one final
     * exponentiation and the comparison run here. On a single-thread curve queueAction runs the
     * same tasks inline, so the result is identical either way.
     */
    async function verify(publicSignals, proof) {
      try {
        if (!Array.isArray(publicSignals) || publicSignals.length !== nPublic) return false;
        if (!proof || typeof proof !== "object") return false;
        for (let i = 0; i < nPublic; i++) if (!isCanonicalScalar(publicSignals[i])) return false;
        const { A, B, C } = parseProof(curve, proof);
        if (!proofPointsOnCurve(curve, A, B, C)) return false;

        const Bj = G2.toJacobian(B);
        const pending = Promise.all([
          millerTask(G1.toJacobian(G1.neg(A)), Bj, null),
          subgroupTask(Bj),
          millerTask(G1.toJacobian(C), null, preDelta),
        ]);
        pending.catch(() => {}); // observed below; avoid an unhandled rejection if we throw first
        const vkx = linearCombination(publicSignals);
        // e(O, Q) = 1: skip the factor rather than feed the point at infinity to the Miller loop.
        let f = G1.isZero(vkx) ? Gt.one : curve.millerLoop(curve.prepareG1(G1.toJacobian(vkx)), preGamma);
        const [mlAB, rB, mlC] = await pending;
        if (!G2.isZero(rB[0])) return false; // B not in G2
        f = Gt.mul(Gt.mul(f, mlAB[0]), mlC[0]);
        return Gt.eq(curve.finalExponentiation(f), target) === true;
      } catch (_) {
        return false;
      }
    }

    return {
      verify,
      linearCombination,
      nPublic,
      hash,
      terminate: async () => {
        if (owns) await curve.terminate();
      },
    };
  } catch (e) {
    if (owns) await curve.terminate();
    throw e;
  }
}

module.exports = {
  makeVerifier,
  vkeyHash,
  proofPointsValid,
  proofPointsOnCurve,
  g2InSubgroup,
  parseProof,
  getSharedCurve,
  terminateSharedCurve,
  isCanonicalScalar,
  FR,
  FQ,
};
