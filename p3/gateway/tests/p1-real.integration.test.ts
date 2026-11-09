/**
 * Integration with the REAL P1 artifacts (unmodified integrated_access_v3) and REAL
 * Groth16 proofs. If artifacts are missing this suite is reported as skipped (BLOCKED).
 */
import { beforeAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { createApp } from '../src/app/createApp.js';
import { REPO_ROOT } from '../src/config/env.js';
import { FakeRegistry, testConfig } from './helpers.js';
import { generateFixtures } from '../../integration/p2-standin/src/fixtures.js';
import {
  buildV3Input,
  computeTree,
  newIssuerKey,
  proveV3,
  signCommitment,
} from '../../integration/p2-standin/src/p1.js';
import type { Groth16Proof } from '../../integration/p2-standin/src/p1.js';

const ART = resolve(REPO_ROOT, 'artifacts/p1-integrated-v3');
const available =
  existsSync(resolve(ART, 'manifest.json')) &&
  existsSync(resolve(ART, 'integrated_access_v3.zkey'));

describe.skipIf(!available)('gateway × real P1 v3 artifacts (diagnostic profile)', () => {
  let root: string;
  let honest: { proof: Groth16Proof; publicSignals: string[] };
  let tampered: { proof: Groth16Proof; publicSignals: string[] };
  let forged: { proof: Groth16Proof; publicSignals: string[] };

  const strip = (r: { proof: Groth16Proof; publicSignals: string[] }) => ({
    proof: r.proof,
    publicSignals: r.publicSignals,
  });
  beforeAll(async () => {
    const fx = await generateFixtures();
    const leaves = fx.leaves.map(BigInt);
    root = (await computeTree(leaves)).root.toString();
    const alice = fx.personas[0]!;
    const bob = fx.personas[1]!;
    honest = strip(
      await proveV3(
        await buildV3Input({
          secret: BigInt(alice.secret),
          salt: BigInt(alice.salt),
          attributes: alice.attributes,
          issuer: fx.devIssuer,
          signature: alice.signature,
          leaves,
          index: alice.slot,
        }),
      ),
    );
    tampered = strip(
      await proveV3(
        await buildV3Input({
          secret: BigInt(bob.secret),
          salt: BigInt(bob.salt),
          attributes: { role: 3, clearance: 3, deviceCompliant: 1, employeeActive: 1 },
          issuer: fx.devIssuer,
          signature: bob.signature,
          leaves,
          index: bob.slot,
        }),
      ),
    );
    const rogue = await newIssuerKey();
    forged = strip(
      await proveV3(
        await buildV3Input({
          secret: BigInt(alice.secret),
          salt: BigInt(alice.salt),
          attributes: alice.attributes,
          issuer: rogue,
          signature: await signCommitment(rogue, BigInt(alice.commitment)),
          leaves,
          index: alice.slot,
        }),
      ),
    );
  });

  const setup = () => {
    const registry = new FakeRegistry(root);
    const { app, ctx } = createApp({
      config: testConfig({ ZK_PROFILE: 'p1-integrated-v3' }),
      registry,
    });
    const challenge = async (resource = 'file-share') =>
      (await request(app).post('/api/zk/challenges').send({ resource }).expect(201)).body;
    return { app, ctx, registry, challenge };
  };

  it('loads and integrity-checks the real verification key', () => {
    const { ctx } = setup();
    expect(ctx.artifacts().status).toBe('ready');
  });

  it('valid P1 proof: Groth16 VALID but authorization BLOCKED, no session cookie', async () => {
    const { app, challenge } = setup();
    const c = await challenge();
    const res = await request(app)
      .post('/api/zk/verify')
      .send({ challengeId: c.challengeId, ...honest });
    expect(res.status).toBe(424);
    expect(res.body.decision).toBe('blocked');
    expect(res.body.reason).toBe('PROFILE_NOT_AUTHORIZATION_ELIGIBLE');
    expect(res.body.groth16.valid).toBe(true);
    expect(res.headers['set-cookie']).toBeUndefined();
    const nonce = res.body.checks.find((x: { id: string }) => x.id === 'nonce');
    expect(nonce.status).toBe('not-supported');
    expect(res.body.missingGuarantees).toContain('Attributes bound to issuer-signed credential');
  });

  it('replay of the same challenge is rejected by gateway state', async () => {
    const { app, challenge } = setup();
    const c = await challenge();
    await request(app)
      .post('/api/zk/verify')
      .send({ challengeId: c.challengeId, ...honest });
    const replay = await request(app)
      .post('/api/zk/verify')
      .send({ challengeId: c.challengeId, ...honest });
    expect(replay.status).toBe(409);
    expect(replay.body.reason).toBe('CHALLENGE_REPLAYED');
  });

  it('concurrent replay: exactly one submission consumes the challenge', async () => {
    const { app, challenge } = setup();
    const c = await challenge();
    const results = await Promise.all(
      Array.from({ length: 5 }, () =>
        request(app)
          .post('/api/zk/verify')
          .send({ challengeId: c.challengeId, ...honest }),
      ),
    );
    expect(results.filter((r) => r.body.reason === 'CHALLENGE_REPLAYED')).toHaveLength(4);
  });

  it('KNOWN P1 GAP: captured proof under a fresh challenge is still Groth16-valid (no nonce binding) — gateway still issues no session', async () => {
    const { app, challenge } = setup();
    const c1 = await challenge();
    await request(app)
      .post('/api/zk/verify')
      .send({ challengeId: c1.challengeId, ...honest });
    const c2 = await challenge('admin-panel');
    const res = await request(app)
      .post('/api/zk/verify')
      .send({ challengeId: c2.challengeId, ...honest });
    expect(res.body.groth16.valid).toBe(true);
    expect(res.body.decision).toBe('blocked');
    expect(res.headers['set-cookie']).toBeUndefined();
  });

  it('KNOWN P1 GAP: tampered attributes and rogue issuer produce valid proofs — gateway refuses authorization', async () => {
    const { app, challenge } = setup();
    for (const p of [tampered, forged]) {
      const c = await challenge();
      const res = await request(app)
        .post('/api/zk/verify')
        .send({ challengeId: c.challengeId, ...p });
      expect(res.body.groth16.valid).toBe(true);
      expect(res.body.decision).toBe('blocked');
      expect(res.headers['set-cookie']).toBeUndefined();
    }
  });

  it('revoked credential / stale root is denied with ROOT_MISMATCH', async () => {
    const { app, challenge, registry } = setup();
    registry.setRoot('12345');
    const c = await challenge();
    const res = await request(app)
      .post('/api/zk/verify')
      .send({ challengeId: c.challengeId, ...honest });
    expect(res.status).toBe(403);
    expect(res.body.reason).toBe('ROOT_MISMATCH');
  });

  it('incorrect public input (root+1 claimed) fails', async () => {
    const { app, challenge, registry } = setup();
    const forgedRoot = (BigInt(root) + 1n).toString();
    registry.setRoot(forgedRoot);
    const c = await challenge();
    const res = await request(app)
      .post('/api/zk/verify')
      .send({ challengeId: c.challengeId, proof: honest.proof, publicSignals: [forgedRoot] });
    expect(res.status).toBe(403);
    expect(res.body.reason).toBe('PROOF_INVALID');
    expect(res.body.groth16.valid).toBe(false);
  });

  it('tampered proof element is rejected by snarkjs', async () => {
    const { app, challenge } = setup();
    const c = await challenge();
    const bad = structuredClone(honest.proof);
    bad.pi_a[0] = (BigInt(bad.pi_a[0]!) + 1n).toString();
    const res = await request(app)
      .post('/api/zk/verify')
      .send({ challengeId: c.challengeId, proof: bad, publicSignals: honest.publicSignals });
    expect(res.body.reason).toBe('PROOF_INVALID');
  });

  it('public-signal count/order mismatch is rejected before verification', async () => {
    const { app, challenge } = setup();
    const c = await challenge();
    const res = await request(app)
      .post('/api/zk/verify')
      .send({ challengeId: c.challengeId, proof: honest.proof, publicSignals: [root, '1'] });
    expect(res.status).toBe(400);
    expect(res.body.reason).toBe('PUBLIC_SIGNAL_LAYOUT_MISMATCH');
    expect(res.body.groth16.valid).toBeNull();
  });

  it('registry unavailable → fail closed', async () => {
    const { app, challenge, registry } = setup();
    registry.up = false;
    const c = await challenge();
    const res = await request(app)
      .post('/api/zk/verify')
      .send({ challengeId: c.challengeId, ...honest });
    expect(res.status).toBe(503);
    expect(res.body.reason).toBe('REGISTRY_UNAVAILABLE');
  });

  it('readiness reports blocked ZK authorization', async () => {
    const { app } = setup();
    const res = await request(app).get('/readyz');
    expect(res.status).toBe(503);
    expect(res.body.zkAuthorization).toBe('blocked');
    expect(res.body.components.artifacts.ok).toBe(true);
    expect(res.body.components.cryptographicIntegration.ok).toBe(false);
  });
});
