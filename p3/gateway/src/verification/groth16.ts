import { performance } from 'node:perf_hooks';
import * as snarkjs from 'snarkjs';
import type { VerificationKey } from './artifacts.js';
import type { Groth16Proof } from './schema.js';

export interface Groth16Verifier {
  readonly kind: string;
  verify(
    vkey: VerificationKey,
    publicSignals: string[],
    proof: Groth16Proof,
  ): Promise<{ valid: boolean; durationMs: number }>;
}

/** Real cryptographic verification via snarkjs. Exceptions are treated as invalid proofs. */
export class SnarkjsGroth16Verifier implements Groth16Verifier {
  readonly kind = 'snarkjs-groth16';

  /** Build the bn128 curve once at startup so the first real verification is not a cold start. */
  async warmUp(vkey: VerificationKey, nPublic: number) {
    const dummy = {
      pi_a: ['1', '2', '1'],
      pi_b: [
        ['1', '0'],
        ['1', '0'],
        ['1', '0'],
      ],
      pi_c: ['1', '2', '1'],
      protocol: 'groth16',
      curve: 'bn128',
    } as Groth16Proof;
    await this.verify(
      vkey,
      Array.from({ length: nPublic }, () => '0'),
      dummy,
    );
  }
  async verify(vkey: VerificationKey, publicSignals: string[], proof: Groth16Proof) {
    const t0 = performance.now();
    let valid = false;
    try {
      valid = (await snarkjs.groth16.verify(vkey, publicSignals, proof, silentLogger)) === true;
    } catch {
      valid = false;
    }
    return { valid, durationMs: performance.now() - t0 };
  }
}

const noop = () => undefined;
const silentLogger = { debug: noop, info: noop, warn: noop, error: noop };
