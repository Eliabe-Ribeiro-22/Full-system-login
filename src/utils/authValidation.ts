export interface PasswordChecks {
  minLength: boolean;
  hasUppercase: boolean;
  hasLowercase: boolean;
  hasNumber: boolean;
  hasSymbol: boolean;
}

export interface PasswordStrengthResult {
  score: number; // 0..5
  label: 'Muito fraca' | 'Fraca' | 'Razoável' | 'Forte' | 'Excelente';
  valid: boolean;
  checks: PasswordChecks;
}

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function isValidEmail(email: string): boolean {
  const normalized = normalizeEmail(email);
  return normalized.length <= 254 && EMAIL_REGEX.test(normalized);
}

export function evaluatePasswordStrength(password: string): PasswordStrengthResult {
  const checks: PasswordChecks = {
    minLength: password.length >= 8,
    hasUppercase: /[A-Z]/.test(password),
    hasLowercase: /[a-z]/.test(password),
    hasNumber: /\d/.test(password),
    hasSymbol: /[^A-Za-z0-9]/.test(password),
  };

  const score = Object.values(checks).filter(Boolean).length;

  let label: PasswordStrengthResult['label'] = 'Muito fraca';
  if (score === 2) label = 'Fraca';
  else if (score === 3) label = 'Razoável';
  else if (score === 4) label = 'Forte';
  else if (score === 5) label = 'Excelente';

  return {
    score,
    label,
    valid: checks.minLength && checks.hasUppercase && checks.hasLowercase && checks.hasNumber && checks.hasSymbol,
    checks,
  };
}

export function normalizeTotpCode(code: string): string {
  return code.replace(/\s+/g, '').trim();
}

export function isValidTotpFormat(code: string): boolean {
  return /^\d{6}$/.test(normalizeTotpCode(code));
}

export function normalizeBackupCode(code: string): string {
  return code.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
}

export function formatBackupCode(raw: string): string {
  const clean = normalizeBackupCode(raw);
  if (clean.length !== 8) return clean;
  return `${clean.slice(0, 4)}-${clean.slice(4)}`;
}
