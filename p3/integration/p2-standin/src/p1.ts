/**
 * Helpers that drive the REAL, UNMODIFIED P1 circuit `integrated_access_v3`.
 * Input layout mirrors P1's scripts/generate_integrated_v3.js exactly.
 */
import { randomBytes } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import * as snarkjs from 'snarkjs';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { P1_ARTIFACT_DIR } from './paths.js';

export const P1_TREE_DEPTH = 2; // fixed by MerkleMembership() in P1
export const P1_TREE_SIZE = 1 << P1_TREE_DEPTH;

export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

export interface P1Attributes {
  role: number;
  clearance: number;
  deviceCompliant: number;
  employeeActive: number;
}

export interface Signature {
  R8x: string;
  R8y: string;
  S: string;
}

export interface IssuerKey {
  privateKeyHex: string;
  Ax: string;
  Ay: string;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let cache: Promise<{ poseidon: any; eddsa: any }> | null = null;
export function crypto() {
  cache ??= Promise.all([buildPoseidon(), buildEddsa()]).then(([poseidon, eddsa]) => ({
    poseidon,
    eddsa,
  }));
  return cache;
}

export async function poseidon2(a: bigint, b: bigint): Promise<bigint> {
  const { poseidon } = await crypto();
  return poseidon.F.toObject(poseidon([a, b])) as bigint;
}

export function randomField(): bigint {
  return BigInt('0x' + randomBytes(31).toString('hex'));
}

export async function newIssuerKey(): Promise<IssuerKey> {
  const { eddsa } = await crypto();
  const priv = randomBytes(32);
  const pub = eddsa.prv2pub(priv);
  return {
    privateKeyHex: priv.toString('hex'),
    Ax: eddsa.F.toObject(pub[0]).toString(),
    Ay: eddsa.F.toObject(pub[1]).toString(),
  };
}

export async function signCommitment(key: IssuerKey, commitment: bigint): Promise<Signature> {
  const { eddsa } = await crypto();
  const sig = eddsa.signPoseidon(Buffer.from(key.privateKeyHex, 'hex'), eddsa.F.e(commitment));
  return {
    R8x: eddsa.F.toObject(sig.R8[0]).toString(),
    R8y: eddsa.F.toObject(sig.R8[1]).toString(),
    S: sig.S.toString(),
  };
}

export async function commitmentOf(secret: bigint, salt: bigint): Promise<bigint> {
  return poseidon2(secret, salt);
}

/** Depth-2 Poseidon tree exactly as P1's MerkleMembership (left/right selected by pathIndices). */
export async function computeTree(leaves: bigint[]) {
  if (leaves.length !== P1_TREE_SIZE) throw new Error(`P1 tree needs ${P1_TREE_SIZE} leaves`);
  const l1 = [await poseidon2(leaves[0]!, leaves[1]!), await poseidon2(leaves[2]!, leaves[3]!)];
  const root = await poseidon2(l1[0]!, l1[1]!);
  return { levels: [leaves, l1, [root]], root };
}

export async function merklePath(leaves: bigint[], index: number) {
  const { levels } = await computeTree(leaves);
  const pathElements: string[] = [];
  const pathIndices: number[] = [];
  let idx = index;
  for (let level = 0; level < P1_TREE_DEPTH; level++) {
    const isRight = idx % 2;
    const sibling = levels[level]![isRight ? idx - 1 : idx + 1]!;
    pathElements.push(sibling.toString());
    // P1: pathIndices[i] = 1 => current hash goes on the RIGHT
    pathIndices.push(isRight);
    idx = Math.floor(idx / 2);
  }
  return { pathElements, pathIndices };
}

export interface V3Witness {
  credentialSecret: string;
  credentialSalt: string;
  role: number;
  clearance: number;
  deviceCompliant: number;
  employeeActive: number;
  Ax: string;
  Ay: string;
  R8x: string;
  R8y: string;
  S: string;
  M: string;
  leaf: string;
  pathElements: string[];
  pathIndices: number[];
  root: string;
}

export async function buildV3Input(args: {
  secret: bigint;
  salt: bigint;
  attributes: P1Attributes;
  issuer: Pick<IssuerKey, 'Ax' | 'Ay'>;
  signature: Signature;
  leaves: bigint[];
  index: number;
}): Promise<V3Witness> {
  const commitment = await commitmentOf(args.secret, args.salt);
  const { root } = await computeTree(args.leaves);
  const path = await merklePath(args.leaves, args.index);
  return {
    credentialSecret: args.secret.toString(),
    credentialSalt: args.salt.toString(),
    ...args.attributes,
    Ax: args.issuer.Ax,
    Ay: args.issuer.Ay,
    ...args.signature,
    M: commitment.toString(),
    leaf: commitment.toString(),
    ...path,
    root: root.toString(),
  };
}

export function artifactPaths(dir = P1_ARTIFACT_DIR) {
  return {
    wasm: join(dir, 'integrated_access_v3.wasm'),
    zkey: join(dir, 'integrated_access_v3.zkey'),
    vkey: join(dir, 'verification_key.json'),
  };
}

export function artifactsAvailable(dir = P1_ARTIFACT_DIR): boolean {
  const p = artifactPaths(dir);
  return existsSync(p.wasm) && existsSync(p.zkey) && existsSync(p.vkey);
}

export class WitnessError extends Error {}

export async function proveV3(input: V3Witness, dir = P1_ARTIFACT_DIR) {
  const p = artifactPaths(dir);
  const t0 = performance.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, p.wasm, p.zkey);
    return {
      proof: proof as Groth16Proof,
      publicSignals: publicSignals as string[],
      provingMs: performance.now() - t0,
    };
  } catch (err) {
    // Witness calculation throws "Assert Failed" when a constraint cannot be satisfied.
    throw new WitnessError(err instanceof Error ? err.message.split('\n')[0] : String(err));
  }
}

let vkeyCache: unknown = null;
export async function verifyV3(
  proof: Groth16Proof,
  publicSignals: string[],
  dir = P1_ARTIFACT_DIR,
) {
  vkeyCache ??= JSON.parse(readFileSync(artifactPaths(dir).vkey, 'utf8'));
  const t0 = performance.now();
  const ok: boolean = await snarkjs.groth16.verify(vkeyCache, publicSignals, proof);
  return { ok, verifyMs: performance.now() - t0 };
}

/** snarkjs keeps worker threads for the curve; call when a CLI finishes. */
export async function shutdown() {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const curve = (globalThis as any).curve_bn128;
  if (curve?.terminate) await curve.terminate();
}
