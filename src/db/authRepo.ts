import { and, desc, eq, gt, inArray, isNull } from 'drizzle-orm';
import { db } from '../db/index.ts';
import { authEvents, authTokens, previewEmails, users } from '../db/schema.ts';

export type UserRow = typeof users.$inferSelect;
export type AuthEventRow = typeof authEvents.$inferSelect;
export type PreviewEmailRow = typeof previewEmails.$inferSelect;

export interface SafeUserProfile {
  id: number;
  uid: string | null;
  name: string;
  email: string;
  role: string;
  emailVerified: boolean;
  twoFactorEnabled: boolean;
  hasPassword: boolean;
  backupCodesRemaining: number;
  createdAt: string;
}

export function sanitizeUser(user: UserRow): SafeUserProfile {
  let backupCodesRemaining = 0;
  if (user.twoFactorBackupCodes) {
    try {
      const parsed = JSON.parse(user.twoFactorBackupCodes);
      if (Array.isArray(parsed)) {
        backupCodesRemaining = parsed.length;
      }
    } catch {
      backupCodesRemaining = 0;
    }
  }

  return {
    id: user.id,
    uid: user.uid,
    name: user.name,
    email: user.email,
    role: user.role,
    emailVerified: user.emailVerified,
    twoFactorEnabled: user.twoFactorEnabled,
    hasPassword: Boolean(user.passwordHash),
    backupCodesRemaining,
    createdAt: user.createdAt.toISOString(),
  };
}

export async function findUserByEmail(email: string): Promise<UserRow | null> {
  try {
    const rows = await db.select().from(users).where(eq(users.email, email)).limit(1);
    return rows[0] ?? null;
  } catch (error) {
    console.error('Database query failed (findUserByEmail):', error);
    throw new Error('Erro ao consultar usuário no banco de dados.', { cause: error });
  }
}

export async function findUserById(id: number): Promise<UserRow | null> {
  try {
    const rows = await db.select().from(users).where(eq(users.id, id)).limit(1);
    return rows[0] ?? null;
  } catch (error) {
    console.error('Database query failed (findUserById):', error);
    throw new Error('Erro ao consultar perfil do usuário.', { cause: error });
  }
}

export async function createLocalUser(input: {
  name: string;
  email: string;
  passwordHash: string;
  emailVerified?: boolean;
}): Promise<UserRow> {
  try {
    const rows = await db
      .insert(users)
      .values({
        name: input.name,
        email: input.email,
        passwordHash: input.passwordHash,
        emailVerified: input.emailVerified ?? false,
      })
      .returning();
    return rows[0];
  } catch (error) {
    console.error('Database query failed (createLocalUser):', error);
    throw new Error('Não foi possível criar o usuário no banco de dados.', { cause: error });
  }
}

export async function upsertGoogleUser(input: {
  uid: string;
  email: string;
  name: string;
  emailVerified: boolean;
}): Promise<UserRow> {
  try {
    const existingByEmail = await db
      .select()
      .from(users)
      .where(eq(users.email, input.email))
      .limit(1);

    if (existingByEmail[0]) {
      const updated = await db
        .update(users)
        .set({
          uid: input.uid,
          emailVerified: existingByEmail[0].emailVerified || input.emailVerified,
          updatedAt: new Date(),
        })
        .where(eq(users.id, existingByEmail[0].id))
        .returning();
      return updated[0];
    }

    const result = await db
      .insert(users)
      .values({
        uid: input.uid,
        name: input.name,
        email: input.email,
        emailVerified: input.emailVerified,
      })
      .onConflictDoUpdate({
        target: users.uid,
        set: {
          email: input.email,
          name: input.name,
          emailVerified: input.emailVerified,
          updatedAt: new Date(),
        },
      })
      .returning();
    return result[0];
  } catch (error) {
    console.error('Database query failed (upsertGoogleUser):', error);
    throw new Error('Erro ao sincronizar conta Google no banco de dados.', { cause: error });
  }
}

export async function updateLoginFailure(
  userId: number,
  failedAttempts: number,
  lockedUntil: Date | null
): Promise<void> {
  try {
    await db
      .update(users)
      .set({
        failedLoginAttempts: failedAttempts,
        lockedUntil,
        updatedAt: new Date(),
      })
      .where(eq(users.id, userId));
  } catch (error) {
    console.error('Database query failed (updateLoginFailure):', error);
    throw new Error('Erro ao atualizar tentativas de login.', { cause: error });
  }
}

export async function resetLoginFailures(userId: number): Promise<void> {
  try {
    await db
      .update(users)
      .set({
        failedLoginAttempts: 0,
        lockedUntil: null,
        updatedAt: new Date(),
      })
      .where(eq(users.id, userId));
  } catch (error) {
    console.error('Database query failed (resetLoginFailures):', error);
    throw new Error('Erro ao redefinir contador de tentativas.', { cause: error });
  }
}

export async function issueAuthToken(input: {
  userId: number;
  type: 'email_verification' | 'password_reset';
  tokenHash: string;
  codeHash: string;
  expiresAt: Date;
}): Promise<void> {
  try {
    await db
      .update(authTokens)
      .set({ usedAt: new Date() })
      .where(
        and(
          eq(authTokens.userId, input.userId),
          eq(authTokens.type, input.type),
          isNull(authTokens.usedAt)
        )
      );

    await db.insert(authTokens).values({
      userId: input.userId,
      type: input.type,
      tokenHash: input.tokenHash,
      codeHash: input.codeHash,
      expiresAt: input.expiresAt,
    });
  } catch (error) {
    console.error('Database query failed (issueAuthToken):', error);
    throw new Error('Erro ao registrar token de verificação.', { cause: error });
  }
}

export async function consumeVerificationToken(input: {
  tokenHash?: string;
  userId?: number;
  codeHash?: string;
}): Promise<UserRow | null> {
  try {
    const now = new Date();
    let matchedToken: typeof authTokens.$inferSelect | undefined;

    if (input.tokenHash) {
      const rows = await db
        .select()
        .from(authTokens)
        .where(
          and(
            eq(authTokens.type, 'email_verification'),
            eq(authTokens.tokenHash, input.tokenHash),
            isNull(authTokens.usedAt),
            gt(authTokens.expiresAt, now)
          )
        )
        .limit(1);
      matchedToken = rows[0];
    } else if (input.userId && input.codeHash) {
      const rows = await db
        .select()
        .from(authTokens)
        .where(
          and(
            eq(authTokens.type, 'email_verification'),
            eq(authTokens.userId, input.userId),
            eq(authTokens.codeHash, input.codeHash),
            isNull(authTokens.usedAt),
            gt(authTokens.expiresAt, now)
          )
        )
        .limit(1);
      matchedToken = rows[0];
    }

    if (!matchedToken) {
      return null;
    }

    await db
      .update(authTokens)
      .set({ usedAt: now })
      .where(eq(authTokens.id, matchedToken.id));

    const updatedUsers = await db
      .update(users)
      .set({ emailVerified: true, updatedAt: now })
      .where(eq(users.id, matchedToken.userId))
      .returning();

    return updatedUsers[0] ?? null;
  } catch (error) {
    console.error('Database query failed (consumeVerificationToken):', error);
    throw new Error('Erro ao validar token de e-mail.', { cause: error });
  }
}

export async function consumePasswordResetToken(input: {
  tokenHash?: string;
  userId?: number;
  codeHash?: string;
  newPasswordHash: string;
}): Promise<UserRow | null> {
  try {
    const now = new Date();
    let matchedToken: typeof authTokens.$inferSelect | undefined;

    if (input.tokenHash) {
      const rows = await db
        .select()
        .from(authTokens)
        .where(
          and(
            eq(authTokens.type, 'password_reset'),
            eq(authTokens.tokenHash, input.tokenHash),
            isNull(authTokens.usedAt),
            gt(authTokens.expiresAt, now)
          )
        )
        .limit(1);
      matchedToken = rows[0];
    } else if (input.userId && input.codeHash) {
      const rows = await db
        .select()
        .from(authTokens)
        .where(
          and(
            eq(authTokens.type, 'password_reset'),
            eq(authTokens.userId, input.userId),
            eq(authTokens.codeHash, input.codeHash),
            isNull(authTokens.usedAt),
            gt(authTokens.expiresAt, now)
          )
        )
        .limit(1);
      matchedToken = rows[0];
    }

    if (!matchedToken) {
      return null;
    }

    await db
      .update(authTokens)
      .set({ usedAt: now })
      .where(eq(authTokens.id, matchedToken.id));

    const updatedUsers = await db
      .update(users)
      .set({
        passwordHash: input.newPasswordHash,
        failedLoginAttempts: 0,
        lockedUntil: null,
        updatedAt: now,
      })
      .where(eq(users.id, matchedToken.userId))
      .returning();

    return updatedUsers[0] ?? null;
  } catch (error) {
    console.error('Database query failed (consumePasswordResetToken):', error);
    throw new Error('Erro ao redefinir senha.', { cause: error });
  }
}

export async function setPendingTwoFactorSecret(userId: number, secret: string): Promise<void> {
  try {
    await db
      .update(users)
      .set({ twoFactorPendingSecret: secret, updatedAt: new Date() })
      .where(eq(users.id, userId));
  } catch (error) {
    console.error('Database query failed (setPendingTwoFactorSecret):', error);
    throw new Error('Erro ao iniciar configuração 2FA.', { cause: error });
  }
}

export async function activateTwoFactor(
  userId: number,
  secret: string,
  backupCodesJson: string
): Promise<UserRow> {
  try {
    const rows = await db
      .update(users)
      .set({
        twoFactorEnabled: true,
        twoFactorSecret: secret,
        twoFactorPendingSecret: null,
        twoFactorBackupCodes: backupCodesJson,
        updatedAt: new Date(),
      })
      .where(eq(users.id, userId))
      .returning();
    return rows[0];
  } catch (error) {
    console.error('Database query failed (activateTwoFactor):', error);
    throw new Error('Erro ao ativar 2FA.', { cause: error });
  }
}

export async function disableTwoFactor(userId: number): Promise<UserRow> {
  try {
    const rows = await db
      .update(users)
      .set({
        twoFactorEnabled: false,
        twoFactorSecret: null,
        twoFactorPendingSecret: null,
        twoFactorBackupCodes: null,
        updatedAt: new Date(),
      })
      .where(eq(users.id, userId))
      .returning();
    return rows[0];
  } catch (error) {
    console.error('Database query failed (disableTwoFactor):', error);
    throw new Error('Erro ao desativar 2FA.', { cause: error });
  }
}

export async function updateBackupCodesJson(userId: number, remainingJson: string): Promise<void> {
  try {
    await db
      .update(users)
      .set({ twoFactorBackupCodes: remainingJson, updatedAt: new Date() })
      .where(eq(users.id, userId));
  } catch (error) {
    console.error('Database query failed (updateBackupCodesJson):', error);
    throw new Error('Erro ao atualizar códigos de backup.', { cause: error });
  }
}

export async function updateUserPassword(userId: number, passwordHash: string): Promise<void> {
  try {
    await db
      .update(users)
      .set({ passwordHash, updatedAt: new Date() })
      .where(eq(users.id, userId));
  } catch (error) {
    console.error('Database query failed (updateUserPassword):', error);
    throw new Error('Erro ao atualizar senha.', { cause: error });
  }
}

export async function logAuthEvent(input: {
  userId: number;
  eventType: string;
  status: 'success' | 'warning' | 'blocked';
  detail: string;
  ipAddress: string;
  userAgent: string;
}): Promise<void> {
  try {
    await db.insert(authEvents).values(input);
  } catch (error) {
    console.error('Database query failed (logAuthEvent):', error);
  }
}

export async function listUserAuthEvents(userId: number, limit = 25): Promise<AuthEventRow[]> {
  try {
    return await db
      .select()
      .from(authEvents)
      .where(eq(authEvents.userId, userId))
      .orderBy(desc(authEvents.createdAt))
      .limit(limit);
  } catch (error) {
    console.error('Database query failed (listUserAuthEvents):', error);
    throw new Error('Erro ao carregar histórico de auditoria.', { cause: error });
  }
}

export async function insertPreviewEmail(input: {
  recipientEmail: string;
  subject: string;
  category: 'verification' | 'password_reset';
  actionCode: string;
  actionToken: string;
  bodyPreview: string;
}): Promise<void> {
  try {
    await db.insert(previewEmails).values(input);
  } catch (error) {
    console.error('Database query failed (insertPreviewEmail):', error);
    throw new Error('Erro ao gravar e-mail de visualização.', { cause: error });
  }
}

export async function listPreviewEmailsForRecipients(
  emails: string[]
): Promise<PreviewEmailRow[]> {
  if (emails.length === 0) return [];
  try {
    return await db
      .select()
      .from(previewEmails)
      .where(inArray(previewEmails.recipientEmail, emails))
      .orderBy(desc(previewEmails.createdAt))
      .limit(15);
  } catch (error) {
    console.error('Database query failed (listPreviewEmailsForRecipients):', error);
    throw new Error('Erro ao carregar caixa simulada.', { cause: error });
  }
}

export async function clearPreviewEmailsForRecipients(emails: string[]): Promise<void> {
  if (emails.length === 0) return;
  try {
    await db.delete(previewEmails).where(inArray(previewEmails.recipientEmail, emails));
  } catch (error) {
    console.error('Database query failed (clearPreviewEmailsForRecipients):', error);
    throw new Error('Erro ao limpar caixa simulada.', { cause: error });
  }
}
