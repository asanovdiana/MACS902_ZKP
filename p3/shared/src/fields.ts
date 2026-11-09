/** BN254 (bn128) scalar field modulus used by Circom/snarkjs. */
export const BN254_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const DECIMAL_RE = /^(0|[1-9][0-9]{0,77})$/;

/** True when `value` is a canonical (no leading zeros, < p) decimal field element string. */
export function isCanonicalFieldElement(value: unknown): value is string {
  if (typeof value !== 'string' || !DECIMAL_RE.test(value)) return false;
  return BigInt(value) < BN254_FIELD_MODULUS;
}

export function toFieldString(value: bigint): string {
  if (value < 0n || value >= BN254_FIELD_MODULUS) throw new RangeError('value outside BN254 field');
  return value.toString(10);
}

/** Short display form of a field element: 0x1234…abcd */
export function shortField(value: string, chars = 6): string {
  try {
    const hex = BigInt(value).toString(16);
    return hex.length <= chars * 2 ? `0x${hex}` : `0x${hex.slice(0, chars)}…${hex.slice(-chars)}`;
  } catch {
    return '<invalid>';
  }
}
