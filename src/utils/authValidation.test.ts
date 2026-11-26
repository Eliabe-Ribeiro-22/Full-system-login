import test from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluatePasswordStrength,
  formatBackupCode,
  isValidEmail,
  isValidTotpFormat,
  normalizeBackupCode,
  normalizeEmail,
} from './authValidation';

test('normalizeEmail trims and lowercases input', () => {
  assert.equal(normalizeEmail('  Usuario@Exemplo.COM  '), 'usuario@exemplo.com');
});

test('isValidEmail validates standard email addresses and rejects malformed ones', () => {
  assert.equal(isValidEmail('ana.silva@empresa.com.br'), true);
  assert.equal(isValidEmail('invalido@'), false);
  assert.equal(isValidEmail('sem-arroba.com'), false);
  assert.equal(isValidEmail('espaco @dominio.com'), false);
});

test('evaluatePasswordStrength enforces all 5 security rules', () => {
  const weak = evaluatePasswordStrength('abc');
  assert.equal(weak.valid, false);
  assert.equal(weak.score, 1);

  const missingSymbol = evaluatePasswordStrength('SenhaForte123');
  assert.equal(missingSymbol.valid, false);
  assert.equal(missingSymbol.checks.hasSymbol, false);
  assert.equal(missingSymbol.score, 4);

  const strong = evaluatePasswordStrength('Senha@Forte2026!');
  assert.equal(strong.valid, true);
  assert.equal(strong.score, 5);
  assert.equal(strong.label, 'Excelente');
});

test('isValidTotpFormat accepts 6 digits with optional whitespace', () => {
  assert.equal(isValidTotpFormat('123456'), true);
  assert.equal(isValidTotpFormat(' 123 456 '), true);
  assert.equal(isValidTotpFormat('12345'), false);
  assert.equal(isValidTotpFormat('12345a'), false);
});

test('backup code normalization and formatting round-trip cleanly', () => {
  assert.equal(normalizeBackupCode('ab12-cd34'), 'AB12CD34');
  assert.equal(formatBackupCode('ab12cd34'), 'AB12-CD34');
});
