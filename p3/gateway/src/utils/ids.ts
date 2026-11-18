import { randomBytes, createHash, randomUUID } from 'node:crypto';

export const randomId = (bytes = 18) => randomBytes(bytes).toString('base64url');
/** 128 random bits as a canonical decimal string (always < BN254 r). */
export const randomNonce128 = () => BigInt('0x' + randomBytes(16).toString('hex')).toString(10);
export const digest = (value: string) =>
  createHash('sha256').update(value).digest('hex').slice(0, 16);
export const correlationId = () => randomUUID();
