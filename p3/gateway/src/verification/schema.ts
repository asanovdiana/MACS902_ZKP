import { z } from 'zod';
import { isCanonicalFieldElement, RESOURCE_IDS } from '@zkag/shared';

const field = z
  .string()
  .max(78)
  .refine(isCanonicalFieldElement, 'not a canonical BN254 field element');
/** Groth16 point coordinates are base-field elements (Fq). We only check shape here; snarkjs validates curve membership. */
const coord = z.string().regex(/^(0|[1-9][0-9]{0,77})$/, 'coordinate must be a decimal integer');

export const proofSchema = z
  .object({
    pi_a: z.tuple([coord, coord, coord]),
    pi_b: z.tuple([z.tuple([coord, coord]), z.tuple([coord, coord]), z.tuple([coord, coord])]),
    pi_c: z.tuple([coord, coord, coord]),
    protocol: z.literal('groth16'),
    curve: z.literal('bn128'),
  })
  .strict();
export type Groth16Proof = z.infer<typeof proofSchema>;

export const verifyRequestSchema = z
  .object({
    challengeId: z.string().regex(/^[A-Za-z0-9_-]{16,64}$/),
    proof: proofSchema,
    publicSignals: z.array(field).min(1).max(32),
    client: z
      .object({
        provingMs: z.number().nonnegative().max(600000).optional(),
        prover: z.string().max(64).optional(),
      })
      .strict()
      .optional(),
  })
  .strict();
export type VerifyRequest = z.infer<typeof verifyRequestSchema>;

export const challengeRequestSchema = z.object({ resource: z.enum(RESOURCE_IDS) }).strict();

/** Uncompressed affine size of a BN254 Groth16 proof: A,C ∈ G1 (2×32 B each), B ∈ G2 (4×32 B). */
export const GROTH16_BN254_PROOF_BYTES = 256;
