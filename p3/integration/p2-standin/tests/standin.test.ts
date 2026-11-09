import { describe, expect, it } from 'vitest';
import request from 'supertest';
import { generateFixtures } from '../src/fixtures.js';
import { createStandin } from '../src/server.js';
import { artifactsAvailable, computeTree, verifyV3 } from '../src/p1.js';

const ADMIN = { Authorization: 'Bearer dev-registry-admin-token-change-me-0000' };

describe('P2 diagnostic stand-in (contract conformance)', () => {
  it('publishes a root, changes it on revocation, and resets', async () => {
    const fx = await generateFixtures();
    const { app } = await createStandin(fx);
    const r1 = (await request(app).get('/v1/registry/root')).body;
    expect(r1.root).toBe((await computeTree(fx.leaves.map(BigInt))).root.toString());
    expect((await request(app).post('/v1/credentials/cred-bob/revoke')).status).toBe(401);
    const rev = await request(app).post('/v1/credentials/cred-bob/revoke').set(ADMIN);
    expect(rev.body.root).not.toBe(r1.root);
    expect((await request(app).get('/v1/credentials/cred-bob/status')).body.status).toBe('revoked');
    expect((await request(app).post('/v1/credentials/cred-bob/revoke').set(ADMIN)).status).toBe(
      409,
    );
    expect((await request(app).post('/v1/credentials').set(ADMIN).send({})).status).toBe(501);
    await request(app).post('/v1/admin/reset').set(ADMIN).expect(200);
    expect((await request(app).get('/v1/registry/root')).body.root).toBe(r1.root);
  });

  it.skipIf(!artifactsAvailable())(
    'proves with the real P1 circuit; honest contractor cannot prove; revoked holder cannot prove against the new tree',
    async () => {
      const fx = await generateFixtures();
      const { app } = await createStandin(fx);
      const challenge = { challengeId: 'abcdefghijklmnop', profile: 'p1-integrated-v3' };
      const ok = await request(app)
        .post('/v1/prover/proofs')
        .send({ credentialRef: 'cred-alice', challenge });
      expect(ok.status).toBe(200);
      expect(ok.body.bindings.nonce).toBe(false);
      expect((await verifyV3(ok.body.proof, ok.body.publicSignals)).ok).toBe(true);
      expect(
        (
          await request(app)
            .post('/v1/prover/proofs')
            .send({ credentialRef: 'cred-bob', challenge })
        ).body.error.code,
      ).toBe('WITNESS_UNSATISFIABLE');
      await request(app).post('/v1/credentials/cred-alice/revoke').set(ADMIN).expect(200);
      expect(
        (
          await request(app)
            .post('/v1/prover/proofs')
            .send({ credentialRef: 'cred-alice', challenge })
        ).status,
      ).toBe(422);
      expect(
        (
          await request(app)
            .post('/v1/prover/proofs')
            .send({
              credentialRef: 'cred-alice',
              challenge: { ...challenge, profile: 'zkag-access-v1' },
            })
        ).status,
      ).toBe(409);
    },
  );
});
