import { signInWithPopup } from 'firebase/auth';
import {
  AlertCircle,
  ArrowLeft,
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  Mail,
  ShieldCheck,
} from 'lucide-react';
import { FormEvent, useState } from 'react';
import { apiRequest, ApiError } from '../lib/apiClient';
import { auth, googleAuthProvider } from '../lib/firebase';
import { AuthScreen, UserProfile } from '../types/auth';
import { evaluatePasswordStrength, isValidEmail, isValidTotpFormat } from '../utils/authValidation';
import { PasswordStrengthMeter } from './PasswordStrengthMeter';

interface AuthPortalProps {
  screen: AuthScreen;
  onChangeScreen: (screen: AuthScreen) => void;
  pendingEmail: string;
  onChangePendingEmail: (email: string) => void;
  resetTokenPrefill: string;
  onResetTokenPrefillChange: (token: string) => void;
  onAuthenticated: (token: string, user: UserProfile) => void;
  onOpenMailbox: () => void;
  onRefreshMailbox: () => void;
  mailboxCount: number;
}

interface LoginResponse {
  requiresTwoFactor?: boolean;
  challengeToken?: string;
  email?: string;
  token?: string;
  user?: UserProfile;
}

interface RegisterResponse {
  token: string;
  user: UserProfile;
  requiresEmailVerification: boolean;
  deliveredVia: 'smtp' | 'preview';
}

export function AuthPortal({
  screen,
  onChangeScreen,
  pendingEmail,
  onChangePendingEmail,
  resetTokenPrefill,
  onResetTokenPrefillChange,
  onAuthenticated,
  onOpenMailbox,
  onRefreshMailbox,
  mailboxCount,
}: AuthPortalProps) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState(pendingEmail || '');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const [verificationCode, setVerificationCode] = useState('');
  const [challengeToken, setChallengeToken] = useState('');
  const [challengeEmail, setChallengeEmail] = useState('');
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [useBackupCode, setUseBackupCode] = useState(false);

  const [resetCode, setResetCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');

  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [infoMsg, setInfoMsg] = useState<string | null>(null);

  const clearNotices = () => {
    setErrorMsg(null);
    setInfoMsg(null);
  };

  const switchScreen = (next: AuthScreen) => {
    clearNotices();
    onChangeScreen(next);
  };

  const handleLogin = async (e: FormEvent) => {
    e.preventDefault();
    clearNotices();

    if (!isValidEmail(email)) {
      setErrorMsg('Informe um endereço de e-mail válido.');
      return;
    }
    if (!password) {
      setErrorMsg('Informe sua senha.');
      return;
    }

    setSubmitting(true);
    try {
      const data = await apiRequest<LoginResponse>('/api/auth/login', {
        method: 'POST',
        body: { email, password },
      });

      if (data.requiresTwoFactor && data.challengeToken) {
        setChallengeToken(data.challengeToken);
        setChallengeEmail(data.email || email);
        setTwoFactorCode('');
        setUseBackupCode(false);
        onChangeScreen('two-factor');
        return;
      }

      if (data.token && data.user) {
        onAuthenticated(data.token, data.user);
      }
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : 'Falha ao entrar.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleGoogleSignIn = async () => {
    clearNotices();
    setSubmitting(true);
    try {
      const credential = await signInWithPopup(auth, googleAuthProvider);
      const idToken = await credential.user.getIdToken();
      const data = await apiRequest<LoginResponse>('/api/auth/google', {
        method: 'POST',
        body: { idToken },
      });

      if (data.requiresTwoFactor && data.challengeToken) {
        setChallengeToken(data.challengeToken);
        setChallengeEmail(data.email || credential.user.email || '');
        setTwoFactorCode('');
        setUseBackupCode(false);
        onChangeScreen('two-factor');
        return;
      }

      if (data.token && data.user) {
        onAuthenticated(data.token, data.user);
      }
    } catch (err) {
      setErrorMsg(
        err instanceof ApiError
          ? err.message
          : 'Não foi possível concluir o login com Google.'
      );
    } finally {
      setSubmitting(false);
    }
  };

  const handleRegister = async (e: FormEvent) => {
    e.preventDefault();
    clearNotices();

    if (name.trim().length < 2) {
      setErrorMsg('Informe seu nome completo (mínimo 2 caracteres).');
      return;
    }
    if (!isValidEmail(email)) {
      setErrorMsg('Informe um endereço de e-mail válido.');
      return;
    }
    const strength = evaluatePasswordStrength(password);
    if (!strength.valid) {
      setErrorMsg('A senha precisa cumprir todos os 5 critérios de segurança.');
      return;
    }
    if (password !== confirmPassword) {
      setErrorMsg('A confirmação de senha não confere.');
      return;
    }

    setSubmitting(true);
    try {
      const data = await apiRequest<RegisterResponse>('/api/auth/register', {
        method: 'POST',
        body: { name: name.trim(), email, password },
      });
      onChangePendingEmail(data.user.email);
      setVerificationCode('');
      onRefreshMailbox();
      setInfoMsg(
        data.deliveredVia === 'preview'
          ? 'Conta criada! Enviamos o código de validação para a Caixa Simulada.'
          : 'Conta criada! Verifique sua caixa de entrada para confirmar seu e-mail.'
      );
      onChangeScreen('verify-email');
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : 'Erro ao criar conta.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleVerifyEmail = async (e: FormEvent) => {
    e.preventDefault();
    clearNotices();

    const targetEmail = pendingEmail || email;
    if (!isValidEmail(targetEmail)) {
      setErrorMsg('Informe o e-mail cadastrado.');
      return;
    }
    if (!isValidTotpFormat(verificationCode)) {
      setErrorMsg('Informe o código de verificação de 6 dígitos.');
      return;
    }

    setSubmitting(true);
    try {
      const data = await apiRequest<{
        verified: boolean;
        user: UserProfile;
        token?: string;
      }>('/api/auth/verify-email', {
        method: 'POST',
        body: { email: targetEmail, code: verificationCode.trim() },
      });

      if (data.token && data.user) {
        onAuthenticated(data.token, data.user);
      } else {
        setInfoMsg('E-mail validado com sucesso! Entre com sua senha para continuar.');
        onChangeScreen('login');
      }
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : 'Código inválido ou expirado.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleResendVerification = async () => {
    clearNotices();
    const targetEmail = pendingEmail || email;
    if (!isValidEmail(targetEmail)) {
      setErrorMsg('Informe um e-mail válido para reenviar.');
      return;
    }

    setSubmitting(true);
    try {
      const res = await apiRequest<{ message: string }>('/api/auth/resend-verification', {
        method: 'POST',
        body: { email: targetEmail },
      });
      onRefreshMailbox();
      setInfoMsg(res.message);
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : 'Erro ao reenviar código.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleVerifyTwoFactor = async (e: FormEvent) => {
    e.preventDefault();
    clearNotices();

    if (!twoFactorCode.trim()) {
      setErrorMsg(
        useBackupCode
          ? 'Informe um código de backup válido.'
          : 'Informe o código de 6 dígitos do aplicativo autenticador.'
      );
      return;
    }

    setSubmitting(true);
    try {
      const data = await apiRequest<{ token: string; user: UserProfile }>(
        '/api/auth/login/2fa',
        {
          method: 'POST',
          body: {
            challengeToken,
            code: twoFactorCode.trim(),
            isBackupCode: useBackupCode,
          },
        }
      );
      onAuthenticated(data.token, data.user);
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : 'Código 2FA inválido.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleForgotPassword = async (e: FormEvent) => {
    e.preventDefault();
    clearNotices();

    if (!isValidEmail(email)) {
      setErrorMsg('Informe um endereço de e-mail válido.');
      return;
    }

    setSubmitting(true);
    try {
      const data = await apiRequest<{ message: string }>('/api/auth/forgot-password', {
        method: 'POST',
        body: { email },
      });
      onChangePendingEmail(email);
      onRefreshMailbox();
      setInfoMsg(data.message);
      onChangeScreen('reset-password');
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : 'Erro ao solicitar recuperação.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleResetPassword = async (e: FormEvent) => {
    e.preventDefault();
    clearNotices();

    const targetEmail = pendingEmail || email;
    if (!resetTokenPrefill && (!isValidEmail(targetEmail) || !isValidTotpFormat(resetCode))) {
      setErrorMsg('Informe o e-mail e o código de 6 dígitos recebido.');
      return;
    }
    const strength = evaluatePasswordStrength(newPassword);
    if (!strength.valid) {
      setErrorMsg('A nova senha precisa atender aos 5 critérios de força.');
      return;
    }
    if (newPassword !== confirmNewPassword) {
      setErrorMsg('A confirmação da nova senha não confere.');
      return;
    }

    setSubmitting(true);
    try {
      const data = await apiRequest<{ message: string }>('/api/auth/reset-password', {
        method: 'POST',
        body: resetTokenPrefill
          ? { token: resetTokenPrefill, newPassword }
          : { email: targetEmail, code: resetCode.trim(), newPassword },
      });
      onResetTokenPrefillChange('');
      setResetCode('');
      setNewPassword('');
      setConfirmNewPassword('');
      setPassword('');
      setInfoMsg(data.message);
      onChangeScreen('login');
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : 'Falha ao redefinir a senha.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="mx-auto max-w-6xl px-6 py-10 lg:py-14">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-12 items-stretch">
        {/* Left editorial column */}
        <section className="lg:col-span-6 flex flex-col justify-between py-2">
          <div>
            <p className="text-xs font-medium tracking-wide text-blue-700">
              Autenticação e Segurança de Identidade
            </p>
            <h1 className="mt-3 text-3xl sm:text-4xl font-bold tracking-tight text-slate-900 leading-[1.15] [text-wrap:balance]">
              Controle de acesso completo com JWT, bcrypt, validação de e-mail e 2FA.
            </h1>
            <p className="mt-4 text-base text-slate-600 leading-relaxed max-w-xl">
              Fluxo ponta a ponta com criptografia de senhas via bcrypt, tokens JWT mantidos apenas em memória, verificação de e-mail com expiração, segundo fator TOTP com QR Code e recuperação segura de senha.
            </p>

            <div className="mt-8 border-t border-slate-200 pt-6 grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-6">
              <div>
                <h2 className="text-sm font-semibold text-slate-900">
                  Criptografia bcrypt & Bloqueio
                </h2>
                <p className="mt-1 text-sm text-slate-600 leading-relaxed">
                  Senhas armazenadas com salt individual (custo 12) e proteção automática após 5 tentativas incorretas.
                </p>
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-900">
                  Sessão JWT em Memória
                </h2>
                <p className="mt-1 text-sm text-slate-600 leading-relaxed">
                  Tokens assinados em HS256 e enviados via cabeçalho Bearer sem exposição em armazenamento persistente.
                </p>
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-900">
                  2FA TOTP & Códigos de Backup
                </h2>
                <p className="mt-1 text-sm text-slate-600 leading-relaxed">
                  Autenticador compatível com Google Authenticator/Authy e 8 códigos de uso único com hash SHA-256.
                </p>
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-900">
                  Validação & Recuperação
                </h2>
                <p className="mt-1 text-sm text-slate-600 leading-relaxed">
                  Tokens de uso único com expiração automática e auditoria completa de eventos no Cloud SQL PostgreSQL.
                </p>
              </div>
            </div>
          </div>

          <div className="mt-8 border-t border-slate-200 pt-5 flex flex-wrap items-center justify-between gap-4">
            <div className="text-xs text-slate-500">
              <span>Testando sem servidor SMTP?</span>
              <span className="mx-1.5" aria-hidden="true">·</span>
              <span className="font-mono text-slate-700">{mailboxCount} e-mail(s) na caixa</span>
            </div>
            <button
              type="button"
              onClick={onOpenMailbox}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-medium text-slate-800 hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0"
            >
              <Mail className="w-3.5 h-3.5 text-blue-700" aria-hidden="true" />
              <span>Abrir Caixa Simulada</span>
            </button>
          </div>
        </section>

        {/* Right authentication card */}
        <section className="lg:col-span-6 flex items-center">
          <div className="w-full rounded-xl border border-slate-200 bg-white p-6 sm:p-8 shadow-sm">
            {/* Segmented Mode Tabs */}
            {(screen === 'login' || screen === 'register' || screen === 'forgot-password') && (
              <div
                className="mb-6 grid grid-cols-3 gap-1 rounded-lg bg-slate-100 p-1"
                role="tablist"
                aria-label="Modo de autenticação"
              >
                <button
                  type="button"
                  role="tab"
                  aria-selected={screen === 'login'}
                  onClick={() => switchScreen('login')}
                  className={`rounded-md px-3 py-2 text-xs font-medium transition-colors whitespace-nowrap ${
                    screen === 'login'
                      ? 'bg-white text-slate-900 shadow-sm'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Entrar
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={screen === 'register'}
                  onClick={() => switchScreen('register')}
                  className={`rounded-md px-3 py-2 text-xs font-medium transition-colors whitespace-nowrap ${
                    screen === 'register'
                      ? 'bg-white text-slate-900 shadow-sm'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Criar Conta
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={screen === 'forgot-password'}
                  onClick={() => switchScreen('forgot-password')}
                  className={`rounded-md px-3 py-2 text-xs font-medium transition-colors whitespace-nowrap ${
                    screen === 'forgot-password'
                      ? 'bg-white text-slate-900 shadow-sm'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Recuperar Senha
                </button>
              </div>
            )}

            {errorMsg && (
              <div
                role="alert"
                className="mb-5 flex items-start gap-2.5 rounded-lg border border-red-200 bg-red-50 px-3.5 py-3 text-xs text-red-800"
              >
                <AlertCircle className="w-4 h-4 shrink-0 text-red-600 mt-0.5" aria-hidden="true" />
                <span>{errorMsg}</span>
              </div>
            )}

            {infoMsg && (
              <div
                role="status"
                className="mb-5 flex items-start gap-2.5 rounded-lg border border-emerald-200 bg-emerald-50 px-3.5 py-3 text-xs text-emerald-900"
              >
                <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600 mt-0.5" aria-hidden="true" />
                <span>{infoMsg}</span>
              </div>
            )}

            {/* SCREEN: LOGIN */}
            {screen === 'login' && (
              <div>
                <h2 className="text-xl font-semibold text-slate-900">
                  Acessar sua conta
                </h2>
                <p className="mt-1 text-sm text-slate-500">
                  Entre com seu e-mail e senha cadastrados ou via Google.
                </p>

                <form onSubmit={handleLogin} className="mt-6 space-y-4" noValidate>
                  <div>
                    <label
                      htmlFor="login-email"
                      className="block text-xs font-medium text-slate-700"
                    >
                      E-mail
                    </label>
                    <input
                      id="login-email"
                      type="email"
                      autoComplete="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="voce@empresa.com.br"
                      className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-700/15"
                      required
                    />
                  </div>

                  <div>
                    <div className="flex items-center justify-between">
                      <label
                        htmlFor="login-password"
                        className="block text-xs font-medium text-slate-700"
                      >
                        Senha
                      </label>
                      <button
                        type="button"
                        onClick={() => switchScreen('forgot-password')}
                        className="text-xs font-medium text-blue-700 hover:text-blue-800"
                      >
                        Esqueci minha senha
                      </button>
                    </div>
                    <div className="relative mt-1.5">
                      <input
                        id="login-password"
                        type={showPassword ? 'text' : 'password'}
                        autoComplete="current-password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Digite sua senha"
                        className="block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 pr-10 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-700/15"
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword((prev) => !prev)}
                        className="absolute inset-y-0 right-0 flex items-center px-3 text-slate-500 hover:text-slate-800"
                        aria-label={showPassword ? 'Ocultar senha' : 'Mostrar senha'}
                      >
                        {showPassword ? (
                          <EyeOff className="w-4 h-4" aria-hidden="true" />
                        ) : (
                          <Eye className="w-4 h-4" aria-hidden="true" />
                        )}
                      </button>
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full rounded-lg bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-60 transition-colors"
                  >
                    {submitting ? 'Autenticando...' : 'Entrar com E-mail e Senha'}
                  </button>
                </form>

                <div className="my-5 flex items-center gap-3 text-xs text-slate-400">
                  <div className="h-px flex-1 bg-slate-200" />
                  <span>ou</span>
                  <div className="h-px flex-1 bg-slate-200" />
                </div>

                <button
                  type="button"
                  disabled={submitting}
                  onClick={handleGoogleSignIn}
                  className="w-full inline-flex items-center justify-center gap-2.5 rounded-lg border border-slate-300 bg-white px-4 py-2.5 text-sm font-medium text-slate-800 hover:bg-slate-50 disabled:opacity-60 transition-colors"
                >
                  <ShieldCheck className="w-4 h-4 text-blue-700" aria-hidden="true" />
                  <span>Entrar com Conta Google</span>
                </button>

                <div className="mt-5 flex items-center justify-between border-t border-slate-100 pt-4 text-xs text-slate-500">
                  <span>Já possui um código de verificação?</span>
                  <button
                    type="button"
                    onClick={() => switchScreen('verify-email')}
                    className="font-medium text-blue-700 hover:text-blue-800"
                  >
                    Validar e-mail
                  </button>
                </div>
              </div>
            )}

            {/* SCREEN: REGISTER */}
            {screen === 'register' && (
              <div>
                <h2 className="text-xl font-semibold text-slate-900">
                  Criar nova conta
                </h2>
                <p className="mt-1 text-sm text-slate-500">
                  Sua senha será criptografada com bcrypt e exigirá confirmação de e-mail.
                </p>

                <form onSubmit={handleRegister} className="mt-6 space-y-4" noValidate>
                  <div>
                    <label
                      htmlFor="reg-name"
                      className="block text-xs font-medium text-slate-700"
                    >
                      Nome completo
                    </label>
                    <input
                      id="reg-name"
                      type="text"
                      autoComplete="name"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="Ex.: Ana Beatriz Oliveira"
                      className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-700/15"
                      required
                    />
                  </div>

                  <div>
                    <label
                      htmlFor="reg-email"
                      className="block text-xs font-medium text-slate-700"
                    >
                      E-mail
                    </label>
                    <input
                      id="reg-email"
                      type="email"
                      autoComplete="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="ana@empresa.com.br"
                      className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-700/15"
                      required
                    />
                  </div>

                  <div>
                    <label
                      htmlFor="reg-password"
                      className="block text-xs font-medium text-slate-700"
                    >
                      Senha segura
                    </label>
                    <div className="relative mt-1.5">
                      <input
                        id="reg-password"
                        type={showPassword ? 'text' : 'password'}
                        autoComplete="new-password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Crie uma senha forte"
                        className="block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 pr-10 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-700/15"
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword((prev) => !prev)}
                        className="absolute inset-y-0 right-0 flex items-center px-3 text-slate-500 hover:text-slate-800"
                        aria-label={showPassword ? 'Ocultar senha' : 'Mostrar senha'}
                      >
                        {showPassword ? (
                          <EyeOff className="w-4 h-4" aria-hidden="true" />
                        ) : (
                          <Eye className="w-4 h-4" aria-hidden="true" />
                        )}
                      </button>
                    </div>
                    <PasswordStrengthMeter password={password} />
                  </div>

                  <div>
                    <label
                      htmlFor="reg-confirm"
                      className="block text-xs font-medium text-slate-700"
                    >
                      Confirmar senha
                    </label>
                    <input
                      id="reg-confirm"
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="new-password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="Repita a senha"
                      className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-700/15"
                      required
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full rounded-lg bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-60 transition-colors"
                  >
                    {submitting ? 'Criando conta...' : 'Criar Conta e Enviar Validação'}
                  </button>
                </form>
              </div>
            )}

            {/* SCREEN: VERIFY EMAIL */}
            {screen === 'verify-email' && (
              <div>
                <button
                  type="button"
                  onClick={() => switchScreen('login')}
                  className="mb-4 inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900"
                >
                  <ArrowLeft className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Voltar para entrar</span>
                </button>

                <h2 className="text-xl font-semibold text-slate-900">
                  Validar endereço de e-mail
                </h2>
                <p className="mt-1 text-sm text-slate-500">
                  Informe o código de 6 dígitos enviado para{' '}
                  <span className="font-medium text-slate-800">
                    {pendingEmail || email || 'seu e-mail'}
                  </span>{' '}
                  ou confirme diretamente pela Caixa Simulada.
                </p>

                <form onSubmit={handleVerifyEmail} className="mt-6 space-y-4" noValidate>
                  <div>
                    <label
                      htmlFor="verify-email-addr"
                      className="block text-xs font-medium text-slate-700"
                    >
                      E-mail da conta
                    </label>
                    <input
                      id="verify-email-addr"
                      type="email"
                      value={pendingEmail || email}
                      onChange={(e) => {
                        onChangePendingEmail(e.target.value);
                        setEmail(e.target.value);
                      }}
                      className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm text-slate-900 focus:border-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-700/15"
                      required
                    />
                  </div>

                  <div>
                    <label
                      htmlFor="verify-code"
                      className="block text-xs font-medium text-slate-700"
                    >
                      Código de validação (6 dígitos)
                    </label>
                    <input
                      id="verify-code"
                      type="text"
                      inputMode="numeric"
                      maxLength={6}
                      value={verificationCode}
                      onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, ''))}
                      placeholder="000000"
                      className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 font-mono text-base tracking-widest text-slate-900 focus:border-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-700/15"
                      required
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full rounded-lg bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-60 transition-colors"
                  >
                    {submitting ? 'Validando...' : 'Confirmar E-mail'}
                  </button>
                </form>

                <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-slate-100 pt-4 text-xs">
                  <button
                    type="button"
                    disabled={submitting}
                    onClick={handleResendVerification}
                    className="font-medium text-slate-600 hover:text-slate-900"
                  >
                    Reenviar código
                  </button>
                  <button
                    type="button"
                    onClick={onOpenMailbox}
                    className="inline-flex items-center gap-1.5 font-medium text-blue-700 hover:text-blue-800"
                  >
                    <Mail className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Abrir Caixa Simulada</span>
                  </button>
                </div>
              </div>
            )}

            {/* SCREEN: 2FA CHALLENGE */}
            {screen === 'two-factor' && (
              <div>
                <button
                  type="button"
                  onClick={() => switchScreen('login')}
                  className="mb-4 inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900"
                >
                  <ArrowLeft className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Cancelar e voltar</span>
                </button>

                <div className="flex items-center gap-2 text-blue-700">
                  <Lock className="w-4 h-4" aria-hidden="true" />
                  <span className="text-xs font-semibold">Verificação em Duas Etapas (2FA)</span>
                </div>
                <h2 className="mt-2 text-xl font-semibold text-slate-900">
                  Confirme sua identidade
                </h2>
                <p className="mt-1 text-sm text-slate-500">
                  Senha validada para <span className="font-medium text-slate-800">{challengeEmail}</span>.{' '}
                  {useBackupCode
                    ? 'Informe um dos seus códigos de backup de 8 caracteres.'
                    : 'Digite o código de 6 dígitos do seu aplicativo autenticador.'}
                </p>

                <form onSubmit={handleVerifyTwoFactor} className="mt-6 space-y-4" noValidate>
                  <div>
                    <label
                      htmlFor="twofa-code"
                      className="block text-xs font-medium text-slate-700"
                    >
                      {useBackupCode ? 'Código de backup' : 'Código do autenticador (6 dígitos)'}
                    </label>
                    <input
                      id="twofa-code"
                      type="text"
                      value={twoFactorCode}
                      onChange={(e) => setTwoFactorCode(e.target.value)}
                      placeholder={useBackupCode ? 'XXXX-XXXX' : '000000'}
                      autoFocus
                      className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 font-mono text-base tracking-widest text-slate-900 focus:border-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-700/15"
                      required
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full rounded-lg bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-60 transition-colors"
                  >
                    {submitting ? 'Verificando...' : 'Validar e Entrar'}
                  </button>
                </form>

                <div className="mt-4 border-t border-slate-100 pt-4 text-center">
                  <button
                    type="button"
                    onClick={() => {
                      clearNotices();
                      setTwoFactorCode('');
                      setUseBackupCode((prev) => !prev);
                    }}
                    className="text-xs font-medium text-blue-700 hover:text-blue-800"
                  >
                    {useBackupCode
                      ? 'Usar código do aplicativo autenticador'
                      : 'Perdi o acesso ao autenticador: usar código de backup'}
                  </button>
                </div>
              </div>
            )}

            {/* SCREEN: FORGOT PASSWORD */}
            {screen === 'forgot-password' && (
              <div>
                <h2 className="text-xl font-semibold text-slate-900">
                  Recuperar acesso
                </h2>
                <p className="mt-1 text-sm text-slate-500">
                  Enviaremos um código e um link de redefinição válidos por 15 minutos.
                </p>

                <form onSubmit={handleForgotPassword} className="mt-6 space-y-4" noValidate>
                  <div>
                    <label
                      htmlFor="forgot-email"
                      className="block text-xs font-medium text-slate-700"
                    >
                      E-mail cadastrado
                    </label>
                    <input
                      id="forgot-email"
                      type="email"
                      autoComplete="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="voce@empresa.com.br"
                      className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-700/15"
                      required
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full rounded-lg bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-60 transition-colors"
                  >
                    {submitting ? 'Enviando...' : 'Enviar Código de Recuperação'}
                  </button>
                </form>

                <div className="mt-5 flex items-center justify-between border-t border-slate-100 pt-4 text-xs text-slate-500">
                  <span>Já possui o código de recuperação?</span>
                  <button
                    type="button"
                    onClick={() => switchScreen('reset-password')}
                    className="font-medium text-blue-700 hover:text-blue-800"
                  >
                    Inserir código agora
                  </button>
                </div>
              </div>
            )}

            {/* SCREEN: RESET PASSWORD */}
            {screen === 'reset-password' && (
              <div>
                <button
                  type="button"
                  onClick={() => switchScreen('forgot-password')}
                  className="mb-4 inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900"
                >
                  <ArrowLeft className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Voltar</span>
                </button>

                <div className="flex items-center gap-2 text-blue-700">
                  <KeyRound className="w-4 h-4" aria-hidden="true" />
                  <span className="text-xs font-semibold">Redefinição Segura de Senha</span>
                </div>
                <h2 className="mt-2 text-xl font-semibold text-slate-900">
                  Definir nova senha
                </h2>
                <p className="mt-1 text-sm text-slate-500">
                  {resetTokenPrefill
                    ? 'Link de recuperação validado. Escolha sua nova senha abaixo.'
                    : 'Informe o código de 6 dígitos enviado e defina sua nova senha.'}
                </p>

                <form onSubmit={handleResetPassword} className="mt-6 space-y-4" noValidate>
                  {!resetTokenPrefill && (
                    <>
                      <div>
                        <label
                          htmlFor="reset-email"
                          className="block text-xs font-medium text-slate-700"
                        >
                          E-mail da conta
                        </label>
                        <input
                          id="reset-email"
                          type="email"
                          value={pendingEmail || email}
                          onChange={(e) => {
                            onChangePendingEmail(e.target.value);
                            setEmail(e.target.value);
                          }}
                          className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm text-slate-900 focus:border-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-700/15"
                          required
                        />
                      </div>

                      <div>
                        <label
                          htmlFor="reset-code"
                          className="block text-xs font-medium text-slate-700"
                        >
                          Código de recuperação (6 dígitos)
                        </label>
                        <input
                          id="reset-code"
                          type="text"
                          inputMode="numeric"
                          maxLength={6}
                          value={resetCode}
                          onChange={(e) => setResetCode(e.target.value.replace(/\D/g, ''))}
                          placeholder="000000"
                          className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 font-mono text-base tracking-widest text-slate-900 focus:border-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-700/15"
                          required
                        />
                      </div>
                    </>
                  )}

                  <div>
                    <label
                      htmlFor="reset-new-password"
                      className="block text-xs font-medium text-slate-700"
                    >
                      Nova senha
                    </label>
                    <input
                      id="reset-new-password"
                      type="password"
                      autoComplete="new-password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      placeholder="Crie uma senha forte"
                      className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm text-slate-900 focus:border-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-700/15"
                      required
                    />
                    <PasswordStrengthMeter password={newPassword} />
                  </div>

                  <div>
                    <label
                      htmlFor="reset-confirm-password"
                      className="block text-xs font-medium text-slate-700"
                    >
                      Confirmar nova senha
                    </label>
                    <input
                      id="reset-confirm-password"
                      type="password"
                      autoComplete="new-password"
                      value={confirmNewPassword}
                      onChange={(e) => setConfirmNewPassword(e.target.value)}
                      placeholder="Repita a nova senha"
                      className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm text-slate-900 focus:border-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-700/15"
                      required
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full rounded-lg bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-60 transition-colors"
                  >
                    {submitting ? 'Salvando...' : 'Redefinir Senha'}
                  </button>
                </form>

                <div className="mt-4 flex items-center justify-end border-t border-slate-100 pt-4 text-xs">
                  <button
                    type="button"
                    onClick={onOpenMailbox}
                    className="inline-flex items-center gap-1.5 font-medium text-blue-700 hover:text-blue-800"
                  >
                    <Mail className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Ver código na Caixa Simulada</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
