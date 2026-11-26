import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import * as OTPAuth from 'otpauth';
import QRCode from 'qrcode';
import { formatBackupCode, normalizeBackupCode, normalizeTotpCode } from '../utils/authValidation.ts';

const BCRYPT_ROUNDS = 12;

let cachedEphemeralSecret: string | null = null;

export function getJwtSecret(): string {
  if (process.env.JWT_SECRET && process.env.JWT_SECRET.trim().length >= 16) {
    return process.env.JWT_SECRET.trim();
  }
  if (!cachedEphemeralSecret) {
    cachedEphemeralSecret = crypto.randomBytes(32).toString('hex');
  }
  return cachedEphemeralSecret;
}

export async function hashPassword(plainText: string): Promise<string> {
  return bcrypt.hash(plainText, BCRYPT_ROUNDS);
}

export async function verifyPassword(plainText: string, hash: string): Promise<boolean> {
  return bcrypt.compare(plainText, hash);
}

export function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function generateRandomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('hex');
}

export function generateNumericCode(): string {
  return crypto.randomInt(100000, 1000000).toString();
}

export interface AccessTokenClaims {
  sub: string;
  userId: number;
  email: string;
  name: string;
  role: string;
  emailVerified: boolean;
  twoFactorVerified: boolean;
  purpose: 'access';
  iat?: number;
  exp?: number;
}

export interface TwoFactorChallengeClaims {
  sub: string;
  userId: number;
  email: string;
  purpose: '2fa_challenge';
  iat?: number;
  exp?: number;
}

export function signAccessToken(
  payload: Omit<AccessTokenClaims, 'purpose' | 'iat' | 'exp'>,
  expiresInSeconds = 60 * 60 * 4
): string {
  return jwt.sign(
    { ...payload, purpose: 'access' },
    getJwtSecret(),
    { algorithm: 'HS256', expiresIn: expiresInSeconds }
  );
}

export function verifyAccessToken(token: string): AccessTokenClaims {
  const decoded = jwt.verify(token, getJwtSecret(), { algorithms: ['HS256'] }) as AccessTokenClaims;
  if (decoded.purpose !== 'access' || typeof decoded.userId !== 'number') {
    throw new Error('Invalid access token purpose');
  }
  return decoded;
}

export function signTwoFactorChallengeToken(userId: number, email: string): string {
  return jwt.sign(
    { sub: String(userId), userId, email, purpose: '2fa_challenge' },
    getJwtSecret(),
    { algorithm: 'HS256', expiresIn: '5m' }
  );
}

export function verifyTwoFactorChallengeToken(token: string): TwoFactorChallengeClaims {
  const decoded = jwt.verify(token, getJwtSecret(), { algorithms: ['HS256'] }) as TwoFactorChallengeClaims;
  if (decoded.purpose !== '2fa_challenge' || typeof decoded.userId !== 'number') {
    throw new Error('Invalid 2FA challenge token');
  }
  return decoded;
}

export function createTotpInstance(email: string, secretBase32?: string): OTPAuth.TOTP {
  return new OTPAuth.TOTP({
    issuer: 'VerticeAuth',
    label: email,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: secretBase32
      ? OTPAuth.Secret.fromBase32(secretBase32)
      : new OTPAuth.Secret({ size: 20 }),
  });
}

export async function generateTotpSetup(email: string): Promise<{
  secretBase32: string;
  otpauthUrl: string;
  qrCodeDataUrl: string;
}> {
  const totp = createTotpInstance(email);
  const otpauthUrl = totp.toString();
  const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl, {
    width: 220,
    margin: 2,
    color: {
      dark: '#0f172a',
      light: '#ffffff',
    },
  });
  return {
    secretBase32: totp.secret.base32,
    otpauthUrl,
    qrCodeDataUrl,
  };
}

export function verifyTotpCode(email: string, secretBase32: string, code: string): boolean {
  const normalized = normalizeTotpCode(code);
  if (!/^\d{6}$/.test(normalized)) {
    return false;
  }
  const totp = createTotpInstance(email, secretBase32);
  const delta = totp.validate({ token: normalized, window: 1 });
  return delta !== null;
}

export function generateBackupCodes(count = 8): {
  plainCodes: string[];
  hashedCodes: string[];
} {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const plainCodes: string[] = [];
  const hashedCodes: string[] = [];

  for (let i = 0; i < count; i += 1) {
    let raw = '';
    for (let j = 0; j < 8; j += 1) {
      raw += alphabet[crypto.randomInt(0, alphabet.length)];
    }
    plainCodes.push(formatBackupCode(raw));
    hashedCodes.push(sha256Hex(normalizeBackupCode(raw)));
  }

  return { plainCodes, hashedCodes };
}

export function consumeBackupCode(
  inputCode: string,
  storedHashesJson: string | null
): { matched: boolean; remainingHashesJson: string | null } {
  if (!storedHashesJson) {
    return { matched: false, remainingHashesJson: null };
  }
  let hashes: string[] = [];
  try {
    const parsed = JSON.parse(storedHashesJson);
    if (Array.isArray(parsed)) {
      hashes = parsed.filter((item): item is string => typeof item === 'string');
    }
  } catch {
    return { matched: false, remainingHashesJson: storedHashesJson };
  }

  const candidateHash = sha256Hex(normalizeBackupCode(inputCode));
  const index = hashes.findIndex((h) => {
    if (h.length !== candidateHash.length) return false;
    return crypto.timingSafeEqual(Buffer.from(h), Buffer.from(candidateHash));
  });

  if (index === -1) {
    return { matched: false, remainingHashesJson: storedHashesJson };
  }

  const remaining = [...hashes.slice(0, index), ...hashes.slice(index + 1)];
  return {
    matched: true,
    remainingHashesJson: JSON.stringify(remaining),
  };
}

export function signPreviewInboxList(emails: string[]): string {
  const unique = Array.from(new Set(emails.map((e) => e.trim().toLowerCase()).filter(Boolean))).slice(0, 12);
  const payload = Buffer.from(JSON.stringify(unique), 'utf8').toString('base64url');
  const sig = crypto
    .createHmac('sha256', getJwtSecret())
    .update(payload)
    .digest('base64url');
  return `${payload}.${sig}`;
}

export function verifyPreviewInboxList(cookieValue: string | undefined): string[] {
  if (!cookieValue || !cookieValue.includes('.')) {
    return [];
  }
  const [payload, sig] = cookieValue.split('.');
  if (!payload || !sig) return [];

  const expectedSig = crypto
    .createHmac('sha256', getJwtSecret())
    .update(payload)
    .digest('base64url');

  const sigBuf = Buffer.from(sig);
  const expectedBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return [];
  }

  try {
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (Array.isArray(parsed)) {
      return parsed.filter((item): item is string => typeof item === 'string');
    }
    return [];
  } catch {
    return [];
  }
}
