import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { CircuitProfile } from './profiles.js';

export interface ArtifactManifest {
  circuitId: string;
  profile: string;
  version: string;
  proofSystem: string;
  curve: string;
  nPublic: number;
  publicSignals: string[];
  securityStatus: string;
  trustedSetup?: string;
  securityReview?: {
    status: 'accepted' | 'rejected' | 'pending';
    reviewer?: string;
    date?: string;
    reference?: string;
  };
  files: { verificationKey: { path: string; sha256: string } } & Record<
    string,
    { path: string; sha256: string }
  >;
}

export interface VerificationKey {
  protocol: string;
  curve: string;
  nPublic: number;
  [k: string]: unknown;
}

export type ArtifactState =
  | {
      status: 'ready';
      manifest: ArtifactManifest;
      vkey: VerificationKey;
      vkeySha256: string;
      reviewed: boolean;
    }
  | { status: 'missing' | 'invalid'; detail: string };

const sha256 = (buf: Buffer) => createHash('sha256').update(buf).digest('hex');

/**
 * Load and integrity-check verification artifacts for a profile. Any mismatch between
 * manifest, verification key and profile signal layout makes the artifacts unusable.
 */
export function loadArtifacts(dir: string, profile: CircuitProfile): ArtifactState {
  const manifestPath = join(dir, 'manifest.json');
  if (!existsSync(manifestPath)) {
    return { status: 'missing', detail: `no manifest at ${manifestPath}` };
  }
  let manifest: ArtifactManifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as ArtifactManifest;
  } catch {
    return { status: 'invalid', detail: 'manifest.json is not valid JSON' };
  }
  if (manifest.profile !== profile.id || manifest.circuitId !== profile.circuitId) {
    return {
      status: 'invalid',
      detail: `manifest is for ${manifest.profile}/${manifest.circuitId}, expected ${profile.id}/${profile.circuitId}`,
    };
  }
  if (manifest.proofSystem !== 'groth16' || manifest.curve !== 'bn128') {
    return { status: 'invalid', detail: 'only groth16/bn128 artifacts are supported' };
  }
  const expected = profile.signals.join(',');
  if ((manifest.publicSignals ?? []).join(',') !== expected) {
    return {
      status: 'invalid',
      detail: `public signal layout mismatch: manifest [${manifest.publicSignals}] vs profile [${expected}]`,
    };
  }
  const vkPath = join(dir, manifest.files?.verificationKey?.path ?? 'verification_key.json');
  if (!existsSync(vkPath)) return { status: 'missing', detail: 'verification key file missing' };
  const raw = readFileSync(vkPath);
  const digest = sha256(raw);
  if (digest !== manifest.files.verificationKey.sha256) {
    return {
      status: 'invalid',
      detail: 'verification key sha256 does not match manifest (artifact/circuit version mismatch)',
    };
  }
  let vkey: VerificationKey;
  try {
    vkey = JSON.parse(raw.toString('utf8')) as VerificationKey;
  } catch {
    return { status: 'invalid', detail: 'verification key is not valid JSON' };
  }
  if (vkey.protocol !== 'groth16' || vkey.curve !== 'bn128')
    return { status: 'invalid', detail: 'verification key is not groth16/bn128' };
  if (vkey.nPublic !== profile.signals.length || manifest.nPublic !== vkey.nPublic) {
    return {
      status: 'invalid',
      detail: `nPublic mismatch: vkey ${vkey.nPublic}, manifest ${manifest.nPublic}, profile ${profile.signals.length}`,
    };
  }
  return {
    status: 'ready',
    manifest,
    vkey,
    vkeySha256: digest,
    reviewed: manifest.securityReview?.status === 'accepted',
  };
}
