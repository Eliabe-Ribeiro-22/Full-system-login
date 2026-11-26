import dotenv from 'dotenv';
dotenv.config();

import express, { Request, Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer as createViteServer } from 'vite';
import {
  activateTwoFactor,
  clearPreviewEmailsForRecipients,
  consumePasswordResetToken,
  consumeVerificationToken,
  createLocalUser,
  disableTwoFactor,
  findUserByEmail,
  findUserById,
  issueAuthToken,
  listPreviewEmailsForRecipients,
  listUserAuthEvents,
  logAuthEvent,
  resetLoginFailures,
  sanitizeUser,
  setPendingTwoFactorSecret,
  updateBackupCodesJson,
  updateLoginFailure,
  updateUserPassword,
  upsertGoogleUser,
} from './src/db/authRepo.ts';
import {
  consumeBackupCode,
  generateBackupCodes,
  generateNumericCode,
  generateRandomToken,
  generateTotpSetup,
  hashPassword,
  sha256Hex,
  signAccessToken,
  signPreviewInboxList,
  signTwoFactorChallengeToken,
  verifyAccessToken,
  verifyPassword,
  verifyPreviewInboxList,
  verifyTotpCode,
  verifyTwoFactorChallengeToken,
} from './src/lib/authCrypto.ts';
import { adminAuth } from './src/lib/firebase-admin.ts';
import { dispatchSecurityEmail, isSmtpConfigured } from './src/lib/mailer.ts';
import { AuthenticatedRequest, requireJwtAuth } from './src/middleware/auth.ts';
import {
  evaluatePasswordStrength,
  isValidEmail,
  normalizeEmail,
} from './src/utils/authValidation.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PREVIEW_COOKIE_NAME = 'vertice_preview_inbox';
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION_MS = 5 * 60 * 1000;

function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  if (!cookieHeader) return {};
  const result: Record<string, string> = {};
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key) {
      result[key] = decodeURIComponent(val);
    }
  }
  return result;
}

function getPreviewOwnedEmails(req: Request): string[] {
  const cookies = parseCookies(req.headers.cookie);
  return verifyPreviewInboxList(cookies[PREVIEW_COOKIE_NAME]);
}

function appendPreviewOwnedEmail(req: Request, res: Response, email: string): void {
  const normalized = normalizeEmail(email);
  const current = getPreviewOwnedEmails(req);
  const signed = signPreviewInboxList([...current, normalized]);
  res.append(
    'Set-Cookie',
    `${PREVIEW_COOKIE_NAME}=${encodeURIComponent(signed)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=None; Partitioned`
  );
}

function getClientMeta(req: Request): { ipAddress: string; userAgent: string } {
  const forwarded = req.headers['x-forwarded-for'];
  const rawIp =
    typeof forwarded === 'string'
      ? forwarded.split(',')[0]?.trim()
      : req.ip || '127.0.0.1';
  const userAgent = (req.headers['user-agent'] || 'Desconhecido').slice(0, 180);
  return {
    ipAddress: rawIp || '127.0.0.1',
    userAgent,
  };
}

function isSameOriginMutation(req: Request): boolean {
  if (req.headers['x-requested-with'] === 'XMLHttpRequest') {
    return true;
  }
  const origin = req.headers.origin;
  const host = (req.headers['x-forwarded-host'] as string) || req.headers.host;
  if (!origin || !host) return false;
  try {
    const parsedOrigin = new URL(origin);
    return parsedOrigin.host === host;
  } catch {
    return false;
  }
}

async function createAndSendVerificationEmail(userId: number, email: string) {
  const rawToken = generateRandomToken(32);
  const rawCode = generateNumericCode();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

  await issueAuthToken({
    userId,
    type: 'email_verification',
    tokenHash: sha256Hex(rawToken),
    codeHash: sha256Hex(rawCode),
    expiresAt,
  });

  return dispatchSecurityEmail({
    recipientEmail: email,
    subject: 'Confirme seu e-mail no Vértice Auth',
    category: 'verification',
    actionCode: rawCode,
    actionToken: rawToken,
    bodyPreview:
      'Use o código de 6 dígitos ou clique no botão de confirmação para validar seu endereço de e-mail. Válido por 24 horas.',
  });
}

async function startServer() {
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '100kb' }));

  // Health check
  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({
      ok: true,
      smtpConfigured: isSmtpConfigured(),
    });
  });

  // Register local account with bcrypt + email verification token
  app.post('/api/auth/register', async (req: Request, res: Response) => {
    try {
      const rawName = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
      const rawEmail = typeof req.body?.email === 'string' ? req.body.email : '';
      const password = typeof req.body?.password === 'string' ? req.body.password : '';

      if (rawName.length < 2 || rawName.length > 80) {
        return res.status(400).json({ error: 'Informe um nome completo entre 2 e 80 caracteres.' });
      }
      if (!isValidEmail(rawEmail)) {
        return res.status(400).json({ error: 'Informe um endereço de e-mail válido.' });
      }
      const strength = evaluatePasswordStrength(password);
      if (!strength.valid) {
        return res.status(400).json({
          error:
            'A senha deve ter no mínimo 8 caracteres, com letra maiúscula, minúscula, número e símbolo.',
        });
      }

      const email = normalizeEmail(rawEmail);
      const existing = await findUserByEmail(email);
      if (existing) {
        return res.status(409).json({
          error: 'Já existe uma conta cadastrada com este endereço de e-mail.',
        });
      }

      const passwordHash = await hashPassword(password);
      const user = await createLocalUser({
        name: rawName,
        email,
        passwordHash,
        emailVerified: false,
      });

      const { deliveredVia } = await createAndSendVerificationEmail(user.id, user.email);
      appendPreviewOwnedEmail(req, res, user.email);

      const meta = getClientMeta(req);
      await logAuthEvent({
        userId: user.id,
        eventType: 'Cadastro realizado',
        status: 'success',
        detail: 'Conta criada com hash bcrypt (custo 12). Verificação de e-mail enviada.',
        ...meta,
      });

      const token = signAccessToken({
        sub: String(user.id),
        userId: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        emailVerified: user.emailVerified,
        twoFactorVerified: false,
      });

      return res.status(201).json({
        token,
        user: sanitizeUser(user),
        requiresEmailVerification: true,
        deliveredVia,
      });
    } catch (error: unknown) {
      console.error('Register error:', error);
      return res.status(500).json({ error: 'Não foi possível concluir o cadastro.' });
    }
  });

  // Verify email by token or (email + 6-digit code)
  app.post('/api/auth/verify-email', async (req: Request, res: Response) => {
    try {
      const rawToken = typeof req.body?.token === 'string' ? req.body.token.trim() : '';
      const rawEmail = typeof req.body?.email === 'string' ? req.body.email : '';
      const rawCode = typeof req.body?.code === 'string' ? req.body.code.trim() : '';

      let verifiedUser = null;
      if (rawToken) {
        verifiedUser = await consumeVerificationToken({
          tokenHash: sha256Hex(rawToken),
        });
      } else if (isValidEmail(rawEmail) && /^\d{6}$/.test(rawCode)) {
        const target = await findUserByEmail(normalizeEmail(rawEmail));
        if (target) {
          verifiedUser = await consumeVerificationToken({
            userId: target.id,
            codeHash: sha256Hex(rawCode),
          });
        }
      } else {
        return res.status(400).json({
          error: 'Informe o token de verificação ou seu e-mail e código de 6 dígitos.',
        });
      }

      if (!verifiedUser) {
        return res.status(400).json({
          error: 'Código ou link de verificação inválido ou expirado.',
        });
      }

      const meta = getClientMeta(req);
      await logAuthEvent({
        userId: verifiedUser.id,
        eventType: 'E-mail validado',
        status: 'success',
        detail: 'Endereço de e-mail confirmado com token único SHA-256.',
        ...meta,
      });

      // Only issue an access JWT on email verification if 2FA is not enabled
      let token: string | undefined;
      if (!verifiedUser.twoFactorEnabled) {
        token = signAccessToken({
          sub: String(verifiedUser.id),
          userId: verifiedUser.id,
          email: verifiedUser.email,
          name: verifiedUser.name,
          role: verifiedUser.role,
          emailVerified: true,
          twoFactorVerified: false,
        });
      }

      return res.json({
        verified: true,
        user: sanitizeUser(verifiedUser),
        token,
      });
    } catch (error) {
      console.error('Verify email error:', error);
      return res.status(500).json({ error: 'Erro ao validar o endereço de e-mail.' });
    }
  });

  // Resend verification email
  app.post('/api/auth/resend-verification', async (req: Request, res: Response) => {
    try {
      let targetUser = null;
      const authHeader = req.headers.authorization;
      if (authHeader?.startsWith('Bearer ')) {
        try {
          const claims = verifyAccessToken(authHeader.slice(7).trim());
          targetUser = await findUserById(claims.userId);
        } catch {
          targetUser = null;
        }
      }

      if (!targetUser) {
        const rawEmail = typeof req.body?.email === 'string' ? req.body.email : '';
        if (!isValidEmail(rawEmail)) {
          return res.status(400).json({ error: 'Informe um e-mail válido.' });
        }
        targetUser = await findUserByEmail(normalizeEmail(rawEmail));
      }

      if (!targetUser || targetUser.emailVerified) {
        return res.json({
          message:
            'Se a conta existir e ainda não estiver verificada, um novo código foi enviado.',
        });
      }

      const { deliveredVia } = await createAndSendVerificationEmail(
        targetUser.id,
        targetUser.email
      );

      return res.json({
        message: 'Novo código de verificação enviado com sucesso.',
        deliveredVia,
      });
    } catch (error) {
      console.error('Resend verification error:', error);
      return res.status(500).json({ error: 'Não foi possível reenviar a verificação.' });
    }
  });

  // Login with email + password (bcrypt) -> returns JWT or 2FA challenge
  app.post('/api/auth/login', async (req: Request, res: Response) => {
    try {
      const rawEmail = typeof req.body?.email === 'string' ? req.body.email : '';
      const password = typeof req.body?.password === 'string' ? req.body.password : '';

      if (!isValidEmail(rawEmail) || !password) {
        return res.status(400).json({ error: 'Informe e-mail e senha válidos.' });
      }

      const email = normalizeEmail(rawEmail);
      const user = await findUserByEmail(email);
      const meta = getClientMeta(req);

      if (!user || !user.passwordHash) {
        return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
      }

      if (user.lockedUntil && user.lockedUntil > new Date()) {
        const remainingMinutes = Math.max(
          1,
          Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60000)
        );
        await logAuthEvent({
          userId: user.id,
          eventType: 'Tentativa bloqueada',
          status: 'blocked',
          detail: `Conta temporariamente bloqueada após ${MAX_FAILED_ATTEMPTS} falhas consecutivas.`,
          ...meta,
        });
        return res.status(423).json({
          error: `Muitas tentativas inválidas. Tente novamente em cerca de ${remainingMinutes} minuto(s) ou redefina sua senha.`,
        });
      }

      const validPassword = await verifyPassword(password, user.passwordHash);
      if (!validPassword) {
        const nextAttempts = user.failedLoginAttempts + 1;
        const lockedUntil =
          nextAttempts >= MAX_FAILED_ATTEMPTS ? new Date(Date.now() + LOCK_DURATION_MS) : null;

        await updateLoginFailure(user.id, nextAttempts, lockedUntil);
        await logAuthEvent({
          userId: user.id,
          eventType: 'Falha de login',
          status: lockedUntil ? 'blocked' : 'warning',
          detail: lockedUntil
            ? 'Senha incorreta. Bloqueio temporário de 5 minutos ativado.'
            : `Senha incorreta (tentativa ${nextAttempts} de ${MAX_FAILED_ATTEMPTS}).`,
          ...meta,
        });

        if (lockedUntil) {
          return res.status(423).json({
            error:
              'Conta temporariamente bloqueada por excesso de tentativas incorretas. Aguarde 5 minutos ou use a recuperação de senha.',
          });
        }
        return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
      }

      await resetLoginFailures(user.id);

      if (user.twoFactorEnabled) {
        const challengeToken = signTwoFactorChallengeToken(user.id, user.email);
        await logAuthEvent({
          userId: user.id,
          eventType: 'Desafio 2FA solicitado',
          status: 'warning',
          detail: 'Senha validada via bcrypt; aguardando código TOTP ou código de backup.',
          ...meta,
        });
        return res.json({
          requiresTwoFactor: true,
          challengeToken,
          email: user.email,
        });
      }

      appendPreviewOwnedEmail(req, res, user.email);
      await logAuthEvent({
        userId: user.id,
        eventType: 'Login realizado',
        status: 'success',
        detail: 'Autenticação concluída via senha bcrypt e emissão de JWT.',
        ...meta,
      });

      const token = signAccessToken({
        sub: String(user.id),
        userId: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        emailVerified: user.emailVerified,
        twoFactorVerified: false,
      });

      return res.json({
        requiresTwoFactor: false,
        token,
        user: sanitizeUser(user),
      });
    } catch (error) {
      console.error('Login error:', error);
      return res.status(500).json({ error: 'Erro interno ao processar autenticação.' });
    }
  });

  // Complete 2FA challenge with TOTP or single-use backup code
  app.post('/api/auth/login/2fa', async (req: Request, res: Response) => {
    try {
      const challengeToken =
        typeof req.body?.challengeToken === 'string' ? req.body.challengeToken.trim() : '';
      const code = typeof req.body?.code === 'string' ? req.body.code.trim() : '';
      const isBackupCode = Boolean(req.body?.isBackupCode);

      if (!challengeToken || !code) {
        return res.status(400).json({ error: 'Informe o token de desafio e o código 2FA.' });
      }

      let claims;
      try {
        claims = verifyTwoFactorChallengeToken(challengeToken);
      } catch {
        return res.status(401).json({
          error: 'Desafio 2FA expirado ou inválido. Faça login novamente.',
        });
      }

      const user = await findUserById(claims.userId);
      if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
        return res.status(401).json({ error: 'Configuração 2FA inválida para esta conta.' });
      }

      const meta = getClientMeta(req);
      let verified = false;
      let detail = '';

      if (isBackupCode) {
        const result = consumeBackupCode(code, user.twoFactorBackupCodes);
        if (result.matched && result.remainingHashesJson !== null) {
          verified = true;
          await updateBackupCodesJson(user.id, result.remainingHashesJson);
          detail = 'Login concluído com código de backup único (2FA).';
        }
      } else {
        verified = verifyTotpCode(user.email, user.twoFactorSecret, code);
        detail = 'Login concluído com verificação TOTP 2FA.';
      }

      if (!verified) {
        await logAuthEvent({
          userId: user.id,
          eventType: 'Código 2FA inválido',
          status: 'warning',
          detail: isBackupCode
            ? 'Código de backup inválido ou já utilizado.'
            : 'Código TOTP de 6 dígitos incorreto ou expirado.',
          ...meta,
        });
        return res.status(401).json({
          error: isBackupCode
            ? 'Código de backup inválido ou já utilizado.'
            : 'Código de autenticação inválido ou expirado.',
        });
      }

      const refreshedUser = (await findUserById(user.id)) ?? user;
      appendPreviewOwnedEmail(req, res, refreshedUser.email);

      await logAuthEvent({
        userId: refreshedUser.id,
        eventType: 'Login com 2FA',
        status: 'success',
        detail,
        ...meta,
      });

      const token = signAccessToken({
        sub: String(refreshedUser.id),
        userId: refreshedUser.id,
        email: refreshedUser.email,
        name: refreshedUser.name,
        role: refreshedUser.role,
        emailVerified: refreshedUser.emailVerified,
        twoFactorVerified: true,
      });

      return res.json({
        token,
        user: sanitizeUser(refreshedUser),
      });
    } catch (error) {
      console.error('2FA login error:', error);
      return res.status(500).json({ error: 'Erro ao validar o segundo fator.' });
    }
  });

  // Google Sign-In via Firebase Admin ID token verification
  app.post('/api/auth/google', async (req: Request, res: Response) => {
    try {
      const idToken = typeof req.body?.idToken === 'string' ? req.body.idToken.trim() : '';
      if (!idToken) {
        return res.status(400).json({ error: 'Token do Google ausente.' });
      }

      let decoded;
      try {
        decoded = await adminAuth.verifyIdToken(idToken);
      } catch (err) {
        console.error('Firebase token verification error:', err);
        return res.status(401).json({ error: 'Falha ao validar credencial Google.' });
      }

      if (!decoded.email) {
        return res.status(400).json({ error: 'Conta Google sem endereço de e-mail disponível.' });
      }

      const user = await upsertGoogleUser({
        uid: decoded.uid,
        email: normalizeEmail(decoded.email),
        name: decoded.name || decoded.email.split('@')[0] || 'Usuário Google',
        emailVerified: Boolean(decoded.email_verified),
      });

      const meta = getClientMeta(req);

      if (user.twoFactorEnabled) {
        const challengeToken = signTwoFactorChallengeToken(user.id, user.email);
        await logAuthEvent({
          userId: user.id,
          eventType: 'Login Google (2FA pendente)',
          status: 'warning',
          detail: 'Conta Google validada; aguardando segundo fator 2FA.',
          ...meta,
        });
        return res.json({
          requiresTwoFactor: true,
          challengeToken,
          email: user.email,
        });
      }

      appendPreviewOwnedEmail(req, res, user.email);
      await logAuthEvent({
        userId: user.id,
        eventType: 'Login Google',
        status: 'success',
        detail: 'Autenticação federada via Firebase Auth + sessão JWT.',
        ...meta,
      });

      const token = signAccessToken({
        sub: String(user.id),
        userId: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        emailVerified: user.emailVerified,
        twoFactorVerified: false,
      });

      return res.json({
        requiresTwoFactor: false,
        token,
        user: sanitizeUser(user),
      });
    } catch (error) {
      console.error('Google auth error:', error);
      return res.status(500).json({ error: 'Erro ao autenticar com Google.' });
    }
  });

  // Non-privileged deterministic demo session for quick exploration
  app.post('/api/auth/demo', async (req: Request, res: Response) => {
    try {
      const demoEmail = 'demo@verticeauth.local';
      let user = await findUserByEmail(demoEmail);

      if (!user) {
        const ephemeralPasswordHash = await hashPassword(generateRandomToken(24));
        user = await createLocalUser({
          name: 'Mariana Costa (Demo)',
          email: demoEmail,
          passwordHash: ephemeralPasswordHash,
          emailVerified: true,
        });
      }

      const meta = getClientMeta(req);
      appendPreviewOwnedEmail(req, res, user.email);

      await logAuthEvent({
        userId: user.id,
        eventType: 'Sessão de demonstração',
        status: 'success',
        detail: 'Acesso instantâneo de demonstração iniciado com JWT.',
        ...meta,
      });

      const token = signAccessToken({
        sub: String(user.id),
        userId: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        emailVerified: user.emailVerified,
        twoFactorVerified: user.twoFactorEnabled,
      });

      return res.json({
        token,
        user: sanitizeUser(user),
      });
    } catch (error) {
      console.error('Demo session error:', error);
      return res.status(500).json({ error: 'Não foi possível iniciar a conta de demonstração.' });
    }
  });

  // Forgot password -> generates hashed 15-min reset token & 6-digit code
  app.post('/api/auth/forgot-password', async (req: Request, res: Response) => {
    try {
      const rawEmail = typeof req.body?.email === 'string' ? req.body.email : '';
      if (!isValidEmail(rawEmail)) {
        return res.status(400).json({ error: 'Informe um endereço de e-mail válido.' });
      }

      const email = normalizeEmail(rawEmail);
      const user = await findUserByEmail(email);

      if (user) {
        const rawToken = generateRandomToken(32);
        const rawCode = generateNumericCode();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

        await issueAuthToken({
          userId: user.id,
          type: 'password_reset',
          tokenHash: sha256Hex(rawToken),
          codeHash: sha256Hex(rawCode),
          expiresAt,
        });

        await dispatchSecurityEmail({
          recipientEmail: user.email,
          subject: 'Recuperação de senha — Vértice Auth',
          category: 'password_reset',
          actionCode: rawCode,
          actionToken: rawToken,
          bodyPreview:
            'Recebemos uma solicitação para redefinir sua senha. Use o código abaixo ou clique no link seguro (expira em 15 minutos).',
        });

        const meta = getClientMeta(req);
        await logAuthEvent({
          userId: user.id,
          eventType: 'Recuperação solicitada',
          status: 'warning',
          detail: 'Token de redefinição (expiração de 15 min) emitido.',
          ...meta,
        });
      }

      return res.json({
        message:
          'Se o e-mail estiver cadastrado, enviamos as instruções para redefinição de senha.',
        smtpConfigured: isSmtpConfigured(),
      });
    } catch (error) {
      console.error('Forgot password error:', error);
      return res.status(500).json({ error: 'Erro ao solicitar recuperação de senha.' });
    }
  });

  // Reset password with token or (email + 6-digit code)
  app.post('/api/auth/reset-password', async (req: Request, res: Response) => {
    try {
      const rawToken = typeof req.body?.token === 'string' ? req.body.token.trim() : '';
      const rawEmail = typeof req.body?.email === 'string' ? req.body.email : '';
      const rawCode = typeof req.body?.code === 'string' ? req.body.code.trim() : '';
      const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';

      const strength = evaluatePasswordStrength(newPassword);
      if (!strength.valid) {
        return res.status(400).json({
          error:
            'A nova senha deve ter no mínimo 8 caracteres, com maiúscula, minúscula, número e símbolo.',
        });
      }

      const newPasswordHash = await hashPassword(newPassword);
      let updatedUser = null;

      if (rawToken) {
        updatedUser = await consumePasswordResetToken({
          tokenHash: sha256Hex(rawToken),
          newPasswordHash,
        });
      } else if (isValidEmail(rawEmail) && /^\d{6}$/.test(rawCode)) {
        const target = await findUserByEmail(normalizeEmail(rawEmail));
        if (target) {
          updatedUser = await consumePasswordResetToken({
            userId: target.id,
            codeHash: sha256Hex(rawCode),
            newPasswordHash,
          });
        }
      } else {
        return res.status(400).json({
          error: 'Informe o token ou o e-mail e código de recuperação de 6 dígitos.',
        });
      }

      if (!updatedUser) {
        return res.status(400).json({
          error: 'Código ou link de recuperação inválido ou expirado.',
        });
      }

      const meta = getClientMeta(req);
      await logAuthEvent({
        userId: updatedUser.id,
        eventType: 'Senha redefinida',
        status: 'success',
        detail: 'Senha atualizada via fluxo de recuperação com novo hash bcrypt.',
        ...meta,
      });

      return res.json({
        message: 'Senha redefinida com sucesso! Você já pode entrar com a nova senha.',
      });
    } catch (error) {
      console.error('Reset password error:', error);
      return res.status(500).json({ error: 'Erro ao redefinir a senha.' });
    }
  });

  // Protected: get current user profile + JWT claims
  app.get('/api/auth/me', requireJwtAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const user = await findUserById(req.auth!.userId);
      if (!user) {
        return res.status(404).json({ error: 'Usuário não encontrado.' });
      }
      return res.json({
        user: sanitizeUser(user),
        claims: req.auth,
      });
    } catch (error) {
      console.error('Get /me error:', error);
      return res.status(500).json({ error: 'Erro ao carregar dados do usuário.' });
    }
  });

  // Protected: start 2FA TOTP setup (returns QR code + manual secret)
  app.post('/api/auth/2fa/setup', requireJwtAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const user = await findUserById(req.auth!.userId);
      if (!user) {
        return res.status(404).json({ error: 'Usuário não encontrado.' });
      }
      if (user.twoFactorEnabled) {
        return res.status(400).json({ error: 'A autenticação em 2 fatores já está ativa.' });
      }

      const setup = await generateTotpSetup(user.email);
      await setPendingTwoFactorSecret(user.id, setup.secretBase32);

      return res.json({
        qrCodeDataUrl: setup.qrCodeDataUrl,
        manualKey: setup.secretBase32,
        otpauthUrl: setup.otpauthUrl,
      });
    } catch (error) {
      console.error('2FA setup error:', error);
      return res.status(500).json({ error: 'Erro ao gerar configuração 2FA.' });
    }
  });

  // Protected: verify first TOTP code and activate 2FA + generate backup codes
  app.post('/api/auth/2fa/enable', requireJwtAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const code = typeof req.body?.code === 'string' ? req.body.code.trim() : '';
      const user = await findUserById(req.auth!.userId);
      if (!user) {
        return res.status(404).json({ error: 'Usuário não encontrado.' });
      }
      if (!user.twoFactorPendingSecret) {
        return res.status(400).json({
          error: 'Nenhuma configuração 2FA pendente. Gere o QR Code primeiro.',
        });
      }

      const valid = verifyTotpCode(user.email, user.twoFactorPendingSecret, code);
      if (!valid) {
        return res.status(400).json({
          error: 'Código de 6 dígitos inválido. Confira o aplicativo autenticador e tente novamente.',
        });
      }

      const { plainCodes, hashedCodes } = generateBackupCodes(8);
      const updatedUser = await activateTwoFactor(
        user.id,
        user.twoFactorPendingSecret,
        JSON.stringify(hashedCodes)
      );

      const meta = getClientMeta(req);
      await logAuthEvent({
        userId: user.id,
        eventType: '2FA ativado',
        status: 'success',
        detail: 'Autenticação em dois fatores (TOTP) ativada com 8 códigos de backup.',
        ...meta,
      });

      const token = signAccessToken({
        sub: String(updatedUser.id),
        userId: updatedUser.id,
        email: updatedUser.email,
        name: updatedUser.name,
        role: updatedUser.role,
        emailVerified: updatedUser.emailVerified,
        twoFactorVerified: true,
      });

      return res.json({
        user: sanitizeUser(updatedUser),
        token,
        backupCodes: plainCodes,
      });
    } catch (error) {
      console.error('2FA enable error:', error);
      return res.status(500).json({ error: 'Erro ao ativar 2FA.' });
    }
  });

  // Protected: disable 2FA (requires current TOTP code or password confirmation)
  app.post('/api/auth/2fa/disable', requireJwtAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const code = typeof req.body?.code === 'string' ? req.body.code.trim() : '';
      const password = typeof req.body?.password === 'string' ? req.body.password : '';
      const user = await findUserById(req.auth!.userId);

      if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
        return res.status(400).json({ error: 'A autenticação 2FA não está ativa.' });
      }

      const totpValid = code ? verifyTotpCode(user.email, user.twoFactorSecret, code) : false;
      const passwordValid =
        password && user.passwordHash ? await verifyPassword(password, user.passwordHash) : false;

      if (!totpValid && !passwordValid) {
        return res.status(401).json({
          error: 'Confirme com o código 2FA atual ou com sua senha para desativar.',
        });
      }

      const updatedUser = await disableTwoFactor(user.id);
      const meta = getClientMeta(req);
      await logAuthEvent({
        userId: user.id,
        eventType: '2FA desativado',
        status: 'warning',
        detail: 'Autenticação em dois fatores removida pelo titular da conta.',
        ...meta,
      });

      const token = signAccessToken({
        sub: String(updatedUser.id),
        userId: updatedUser.id,
        email: updatedUser.email,
        name: updatedUser.name,
        role: updatedUser.role,
        emailVerified: updatedUser.emailVerified,
        twoFactorVerified: false,
      });

      return res.json({
        user: sanitizeUser(updatedUser),
        token,
      });
    } catch (error) {
      console.error('2FA disable error:', error);
      return res.status(500).json({ error: 'Erro ao desativar 2FA.' });
    }
  });

  // Protected: change password
  app.post('/api/auth/change-password', requireJwtAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const currentPassword =
        typeof req.body?.currentPassword === 'string' ? req.body.currentPassword : '';
      const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';

      const user = await findUserById(req.auth!.userId);
      if (!user) {
        return res.status(404).json({ error: 'Usuário não encontrado.' });
      }

      if (user.passwordHash) {
        if (!currentPassword) {
          return res.status(400).json({ error: 'Informe sua senha atual.' });
        }
        const matches = await verifyPassword(currentPassword, user.passwordHash);
        if (!matches) {
          return res.status(401).json({ error: 'A senha atual está incorreta.' });
        }
      }

      const strength = evaluatePasswordStrength(newPassword);
      if (!strength.valid) {
        return res.status(400).json({
          error:
            'A nova senha deve ter no mínimo 8 caracteres, com maiúscula, minúscula, número e símbolo.',
        });
      }

      const newHash = await hashPassword(newPassword);
      await updateUserPassword(user.id, newHash);

      const meta = getClientMeta(req);
      await logAuthEvent({
        userId: user.id,
        eventType: 'Senha alterada',
        status: 'success',
        detail: 'Senha atualizada manualmente pelo usuário autenticado.',
        ...meta,
      });

      const refreshedUser = (await findUserById(user.id)) ?? user;
      return res.json({
        message: 'Senha alterada com sucesso.',
        user: sanitizeUser(refreshedUser),
      });
    } catch (error) {
      console.error('Change password error:', error);
      return res.status(500).json({ error: 'Erro ao atualizar senha.' });
    }
  });

  // Protected: real audit events
  app.get('/api/auth/events', requireJwtAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const events = await listUserAuthEvents(req.auth!.userId, 30);
      return res.json({
        events: events.map((ev) => ({
          id: ev.id,
          eventType: ev.eventType,
          status: ev.status,
          detail: ev.detail,
          ipAddress: ev.ipAddress,
          userAgent: ev.userAgent,
          createdAt: ev.createdAt.toISOString(),
        })),
      });
    } catch (error) {
      console.error('Get events error:', error);
      return res.status(500).json({ error: 'Erro ao carregar eventos de auditoria.' });
    }
  });

  // Preview mailbox (scoped strictly to emails owned by this browser's HMAC cookie or active JWT)
  app.get('/api/preview-emails', async (req: Request, res: Response) => {
    try {
      const owned = new Set(getPreviewOwnedEmails(req));
      const authHeader = req.headers.authorization;
      if (authHeader?.startsWith('Bearer ')) {
        try {
          const claims = verifyAccessToken(authHeader.slice(7).trim());
          owned.add(normalizeEmail(claims.email));
        } catch {
          // Ignore invalid optional header
        }
      }

      const emails = await listPreviewEmailsForRecipients(Array.from(owned));
      return res.json({
        smtpConfigured: isSmtpConfigured(),
        emails: emails.map((mail) => ({
          id: mail.id,
          recipientEmail: mail.recipientEmail,
          subject: mail.subject,
          category: mail.category,
          actionCode: mail.actionCode,
          actionToken: mail.actionToken,
          bodyPreview: mail.bodyPreview,
          createdAt: mail.createdAt.toISOString(),
        })),
      });
    } catch (error) {
      console.error('Preview emails error:', error);
      return res.status(500).json({ error: 'Erro ao carregar caixa simulada.' });
    }
  });

  app.post('/api/preview-emails/clear', async (req: Request, res: Response) => {
    if (!isSameOriginMutation(req)) {
      return res.status(403).json({ error: 'Origem da requisição não autorizada.' });
    }
    try {
      const owned = new Set(getPreviewOwnedEmails(req));
      const authHeader = req.headers.authorization;
      if (authHeader?.startsWith('Bearer ')) {
        try {
          const claims = verifyAccessToken(authHeader.slice(7).trim());
          owned.add(normalizeEmail(claims.email));
        } catch {
          // Ignore
        }
      }
      await clearPreviewEmailsForRecipients(Array.from(owned));
      return res.json({ cleared: true });
    } catch (error) {
      console.error('Clear preview emails error:', error);
      return res.status(500).json({ error: 'Erro ao limpar caixa simulada.' });
    }
  });

  // Vite dev middleware or static dist serving
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: process.env.DISABLE_HMR !== 'true',
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req: Request, res: Response) => {
      const indexFile = path.join(distDir, 'index.html');
      if (fs.existsSync(indexFile)) {
        res.sendFile(indexFile);
      } else {
        res.status(404).send('Build output not found.');
      }
    });
  }

  const port = Number(process.env.PORT) || 3000;
  app.listen(port, '0.0.0.0', () => {
    console.log(`Vértice Auth server listening on http://0.0.0.0:${port}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
