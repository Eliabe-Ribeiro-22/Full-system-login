import test from 'node:test';
import assert from 'node:assert/strict';
import {
  consumeBackupCode,
  createTotpInstance,
  generateBackupCodes,
  generateTotpSetup,
  hashPassword,
  signAccessToken,
  signPreviewInboxList,
  signTwoFactorChallengeToken,
  verifyAccessToken,
  verifyPassword,
  verifyPreviewInboxList,
  verifyTotpCode,
  verifyTwoFactorChallengeToken,
} from './authCrypto';

test('hashPassword and verifyPassword use bcrypt and reject wrong passwords', async () => {
  const hash = await hashPassword('MinhaSenha@2026');
  assert.equal(hash.startsWith('$2'), true);
  assert.equal(await verifyPassword('MinhaSenha@2026', hash), true);
  assert.equal(await verifyPassword('Errada@2026', hash), false);
});

test('JWT access tokens and 2FA challenge tokens are strictly isolated by purpose', () => {
  const accessToken = signAccessToken({
    sub: '1',
    userId: 1,
    email: 'dev@vertice.app',
    name: 'Dev',
    role: 'user',
    emailVerified: true,
    twoFactorVerified: true,
  });

  const decodedAccess = verifyAccessToken(accessToken);
  assert.equal(decodedAccess.email, 'dev@vertice.app');
  assert.throws(() => verifyTwoFactorChallengeToken(accessToken));

  const challengeToken = signTwoFactorChallengeToken(1, 'dev@vertice.app');
  const decodedChallenge = verifyTwoFactorChallengeToken(challengeToken);
  assert.equal(decodedChallenge.userId, 1);
  assert.throws(() => verifyAccessToken(challengeToken));
});

test('TOTP setup generates valid QR code and verifies live generated 6-digit token', async () => {
  const setup = await generateTotpSetup('usuario@teste.com');
  assert.equal(setup.qrCodeDataUrl.startsWith('data:image/png;base64,'), true);
  assert.equal(setup.secretBase32.length >= 16, true);

  const liveCode = createTotpInstance('usuario@teste.com', setup.secretBase32).generate();
  assert.equal(verifyTotpCode('usuario@teste.com', setup.secretBase32, liveCode), true);
  assert.equal(verifyTotpCode('usuario@teste.com', setup.secretBase32, '000000'), false);
});

test('backup codes are single-use and removed upon consumption', () => {
  const { plainCodes, hashedCodes } = generateBackupCodes(4);
  assert.equal(plainCodes.length, 4);
  const storedJson = JSON.stringify(hashedCodes);

  const firstAttempt = consumeBackupCode(plainCodes[0], storedJson);
  assert.equal(firstAttempt.matched, true);

  const replayAttempt = consumeBackupCode(plainCodes[0], firstAttempt.remainingHashesJson);
  assert.equal(replayAttempt.matched, false);

  const secondCodeAttempt = consumeBackupCode(plainCodes[1], firstAttempt.remainingHashesJson);
  assert.equal(secondCodeAttempt.matched, true);
});

test('HMAC preview inbox cookie rejects tampered signatures', () => {
  const signed = signPreviewInboxList(['a@teste.com', 'b@teste.com']);
  assert.deepEqual(verifyPreviewInboxList(signed), ['a@teste.com', 'b@teste.com']);

  const [payload, sig] = signed.split('.');
  const tamperedPayload = Buffer.from(JSON.stringify(['vitima@empresa.com'])).toString('base64url');
  assert.deepEqual(verifyPreviewInboxList(`${tamperedPayload}.${sig}`), []);
  assert.deepEqual(verifyPreviewInboxList(`${payload}.invalid`), []);
});
