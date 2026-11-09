import { randomBytes, createHash, randomUUID } from 'node:crypto';

export const randomId = (bytes = 18) => randomBytes(bytes).toString('base64url');
/** 248-bit random value: always a canonical BN254 field element. */
export const randomFieldNonce = () => BigInt('0x' + randomBytes(31).toString('hex')).toString(10);
export const digest = (value: string) =>
  createHash('sha256').update(value).digest('hex').slice(0, 16);
export const correlationId = () => randomUUID();
