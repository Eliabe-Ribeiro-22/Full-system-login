export interface UserProfile {
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

export interface JwtClaims {
  sub: string;
  userId: number;
  email: string;
  name: string;
  role: string;
  emailVerified: boolean;
  twoFactorVerified: boolean;
  purpose: string;
  iat?: number;
  exp?: number;
}

export interface AuthEvent {
  id: number;
  eventType: string;
  status: 'success' | 'warning' | 'blocked';
  detail: string;
  ipAddress: string;
  userAgent: string;
  createdAt: string;
}

export interface PreviewEmail {
  id: number;
  recipientEmail: string;
  subject: string;
  category: 'verification' | 'password_reset';
  actionCode: string;
  actionToken: string;
  bodyPreview: string;
  createdAt: string;
}

export type AuthScreen =
  | 'login'
  | 'register'
  | 'verify-email'
  | 'two-factor'
  | 'forgot-password'
  | 'reset-password';

export type DashboardTab = 'overview' | 'security' | 'jwt' | 'audit';
