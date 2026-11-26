import {
  AlertCircle,
  Check,
  CheckCircle2,
  Copy,
  Download,
  History,
  KeyRound,
  LayoutDashboard,
  Lock,
  Mail,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import { apiRequest, ApiError } from '../lib/apiClient';
import { AuthEvent, DashboardTab, JwtClaims, UserProfile } from '../types/auth';
import { evaluatePasswordStrength, isValidTotpFormat } from '../utils/authValidation';
import { PasswordStrengthMeter } from './PasswordStrengthMeter';

interface SecurityDashboardProps {
  user: UserProfile;
  token: string;
  activeTab: DashboardTab;
  onChangeTab: (tab: DashboardTab) => void;
  onUpdateSession: (token: string, user: UserProfile) => void;
  onOpenMailbox: () => void;
  onRefreshMailbox: () => void;
}

function decodeJwtClaims(token: string): {
  header: Record<string, unknown> | null;
  claims: JwtClaims | null;
} {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return { header: null, claims: null };
    const decodeBase64Url = (segment: string) => {
      const normalized = segment.replace(/-/g, '+').replace(/_/g, '/');
      const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
      return JSON.parse(atob(normalized + pad));
    };
    return {
      header: decodeBase64Url(parts[0]),
      claims: decodeBase64Url(parts[1]) as JwtClaims,
    };
  } catch {
    return { header: null, claims: null };
  }
}

export function SecurityDashboard({
  user,
  token,
  activeTab,
  onChangeTab,
  onUpdateSession,
  onOpenMailbox,
  onRefreshMailbox,
}: SecurityDashboardProps) {
  // Inline email verification
  const [inlineVerifyCode, setInlineVerifyCode] = useState('');

  // 2FA setup & disable state
  const [setupData, setSetupData] = useState<{
    qrCodeDataUrl: string;
    manualKey: string;
    otpauthUrl: string;
  } | null>(null);
  const [totpConfirmCode, setTotpConfirmCode] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedBackup, setCopiedBackup] = useState(false);

  const [disableCode, setDisableCode] = useState('');
  const [disablePassword, setDisablePassword] = useState('');

  // Password change state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');

  // Audit events state
  const [events, setEvents] = useState<AuthEvent[]>([]);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventsError, setEventsError] = useState<string | null>(null);
  const [eventSearch, setEventSearch] = useState('');
  const [eventFilter, setEventFilter] = useState<'all' | 'success' | 'warning' | 'blocked'>('all');

  // JWT server check state
  const [serverCheckResult, setServerCheckResult] = useState<{
    verifiedAt: string;
    userId: number;
  } | null>(null);

  const [busy, setBusy] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const decodedJwt = useMemo(() => decodeJwtClaims(token), [token]);

  const clearFeedback = () => {
    setErrorMsg(null);
    setSuccessMsg(null);
  };

  const fetchEvents = useCallback(async () => {
    setEventsLoading(true);
    setEventsError(null);
    try {
      const data = await apiRequest<{ events: AuthEvent[] }>('/api/auth/events', { token });
      setEvents(data.events);
    } catch (err) {
      setEventsError(
        err instanceof ApiError ? err.message : 'Erro ao carregar eventos de auditoria.'
      );
    } finally {
      setEventsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    if (activeTab === 'audit' || activeTab === 'overview') {
      void fetchEvents();
    }
  }, [activeTab, fetchEvents]);

  const handleInlineVerifyEmail = async (e: FormEvent) => {
    e.preventDefault();
    clearFeedback();
    if (!isValidTotpFormat(inlineVerifyCode)) {
      setErrorMsg('Informe o código de verificação de 6 dígitos.');
      return;
    }

    setBusy(true);
    try {
      const data = await apiRequest<{
        verified: boolean;
        user: UserProfile;
        token?: string;
      }>('/api/auth/verify-email', {
        method: 'POST',
        token,
        body: { email: user.email, code: inlineVerifyCode.trim() },
      });
      onUpdateSession(data.token || token, data.user);
      setInlineVerifyCode('');
      setSuccessMsg('Endereço de e-mail validado com sucesso.');
      void fetchEvents();
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : 'Código inválido ou expirado.');
    } finally {
      setBusy(false);
    }
  };

  const handleResendVerification = async () => {
    clearFeedback();
    setBusy(true);
    try {
      const res = await apiRequest<{ message: string }>('/api/auth/resend-verification', {
        method: 'POST',
        token,
        body: { email: user.email },
      });
      onRefreshMailbox();
      setSuccessMsg(res.message);
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : 'Erro ao reenviar e-mail.');
    } finally {
      setBusy(false);
    }
  };

  const handleStartTwoFactorSetup = async () => {
    clearFeedback();
    setBusy(true);
    try {
      const data = await apiRequest<{
        qrCodeDataUrl: string;
        manualKey: string;
        otpauthUrl: string;
      }>('/api/auth/2fa/setup', {
        method: 'POST',
        token,
      });
      setSetupData(data);
      setTotpConfirmCode('');
      setBackupCodes(null);
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : 'Erro ao iniciar 2FA.');
    } finally {
      setBusy(false);
    }
  };

  const handleEnableTwoFactor = async (e: FormEvent) => {
    e.preventDefault();
    clearFeedback();
    if (!isValidTotpFormat(totpConfirmCode)) {
      setErrorMsg('Informe o código de 6 dígitos gerado pelo aplicativo autenticador.');
      return;
    }

    setBusy(true);
    try {
      const data = await apiRequest<{
        user: UserProfile;
        token: string;
        backupCodes: string[];
      }>('/api/auth/2fa/enable', {
        method: 'POST',
        token,
        body: { code: totpConfirmCode.trim() },
      });
      onUpdateSession(data.token, data.user);
      setSetupData(null);
      setTotpConfirmCode('');
      setBackupCodes(data.backupCodes);
      setSuccessMsg(
        'Autenticação em dois fatores (2FA) ativada! Guarde seus códigos de backup em local seguro.'
      );
      void fetchEvents();
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : 'Código 2FA inválido.');
    } finally {
      setBusy(false);
    }
  };

  const handleDisableTwoFactor = async (e: FormEvent) => {
    e.preventDefault();
    clearFeedback();
    if (!disableCode.trim() && !disablePassword) {
      setErrorMsg('Informe o código 2FA atual ou sua senha para confirmar a desativação.');
      return;
    }

    setBusy(true);
    try {
      const data = await apiRequest<{ user: UserProfile; token: string }>(
        '/api/auth/2fa/disable',
        {
          method: 'POST',
          token,
          body: {
            code: disableCode.trim(),
            password: disablePassword,
          },
        }
      );
      onUpdateSession(data.token, data.user);
      setDisableCode('');
      setDisablePassword('');
      setBackupCodes(null);
      setSuccessMsg('Autenticação em dois fatores desativada.');
      void fetchEvents();
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : 'Não foi possível desativar 2FA.');
    } finally {
      setBusy(false);
    }
  };

  const handleChangePassword = async (e: FormEvent) => {
    e.preventDefault();
    clearFeedback();

    if (user.hasPassword && !currentPassword) {
      setErrorMsg('Informe sua senha atual.');
      return;
    }
    const strength = evaluatePasswordStrength(newPassword);
    if (!strength.valid) {
      setErrorMsg('A nova senha precisa cumprir os 5 critérios de segurança.');
      return;
    }
    if (newPassword !== confirmNewPassword) {
      setErrorMsg('A confirmação da nova senha não confere.');
      return;
    }

    setBusy(true);
    try {
      const data = await apiRequest<{ message: string; user: UserProfile }>(
        '/api/auth/change-password',
        {
          method: 'POST',
          token,
          body: { currentPassword, newPassword },
        }
      );
      onUpdateSession(token, data.user);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmNewPassword('');
      setSuccessMsg(data.message);
      void fetchEvents();
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : 'Erro ao alterar senha.');
    } finally {
      setBusy(false);
    }
  };

  const handleVerifyServerJwt = async () => {
    clearFeedback();
    setBusy(true);
    try {
      const data = await apiRequest<{ user: UserProfile; claims: JwtClaims }>('/api/auth/me', {
        token,
      });
      onUpdateSession(token, data.user);
      setServerCheckResult({
        verifiedAt: new Date().toLocaleTimeString('pt-BR'),
        userId: data.user.id,
      });
      setSuccessMsg('Assinatura JWT validada com sucesso no servidor Express.');
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : 'Falha na validação JWT.');
    } finally {
      setBusy(false);
    }
  };

  const copyManualKey = async () => {
    if (!setupData) return;
    try {
      await navigator.clipboard.writeText(setupData.manualKey);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 1800);
    } catch {
      // Ignore clipboard failure
    }
  };

  const copyBackupCodes = async () => {
    if (!backupCodes) return;
    try {
      await navigator.clipboard.writeText(backupCodes.join('\n'));
      setCopiedBackup(true);
      setTimeout(() => setCopiedBackup(false), 1800);
    } catch {
      // Ignore
    }
  };

  const downloadBackupCodes = () => {
    if (!backupCodes) return;
    const content = [
      'Vértice Auth — Códigos de Backup 2FA (Uso Único)',
      `Conta: ${user.email}`,
      `Gerado em: ${new Date().toLocaleString('pt-BR')}`,
      '',
      ...backupCodes,
    ].join('\n');
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'vertice-auth-codigos-backup.txt';
    link.click();
    URL.revokeObjectURL(url);
  };

  const filteredEvents = useMemo(() => {
    return events.filter((ev) => {
      if (eventFilter !== 'all' && ev.status !== eventFilter) {
        return false;
      }
      if (eventSearch.trim()) {
        const q = eventSearch.trim().toLowerCase();
        return (
          ev.eventType.toLowerCase().includes(q) ||
          ev.detail.toLowerCase().includes(q) ||
          ev.ipAddress.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [events, eventFilter, eventSearch]);

  const breadcrumbMap: Record<DashboardTab, string> = {
    overview: 'Conta / Visão Geral',
    security: 'Conta / Segurança & 2FA',
    jwt: 'Conta / Sessão JWT',
    audit: 'Conta / Auditoria de Acessos',
  };

  const navItems: { id: DashboardTab; label: string; icon: typeof LayoutDashboard }[] = [
    { id: 'overview', label: 'Visão Geral', icon: LayoutDashboard },
    { id: 'security', label: 'Segurança & 2FA', icon: ShieldCheck },
    { id: 'jwt', label: 'Sessão JWT', icon: KeyRound },
    { id: 'audit', label: 'Auditoria', icon: History },
  ];

  return (
    <div className="mx-auto max-w-7xl px-6 py-8">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Sidebar Navigation (240px–280px equivalent in 12-col grid) */}
        <aside className="lg:col-span-3 rounded-xl border border-slate-200 bg-white p-4">
          <div className="border-b border-slate-200 pb-4">
            <p className="text-sm font-semibold text-slate-900 truncate">{user.name}</p>
            <p className="mt-0.5 text-xs text-slate-500 truncate">{user.email}</p>
            <div className="mt-2.5 flex items-center gap-2 text-xs text-slate-600">
              <span>{user.emailVerified ? 'E-mail verificado' : 'E-mail pendente'}</span>
              <span aria-hidden="true">·</span>
              <span>{user.twoFactorEnabled ? '2FA ativo' : '2FA inativo'}</span>
            </div>
          </div>

          <nav className="mt-3 space-y-1" aria-label="Menu da conta">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    clearFeedback();
                    onChangeTab(item.id);
                  }}
                  className={`w-full flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors whitespace-nowrap ${
                    isActive
                      ? 'bg-blue-50 text-blue-800'
                      : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                  }`}
                >
                  <Icon
                    className={`w-4 h-4 shrink-0 ${
                      isActive ? 'text-blue-700' : 'text-slate-400'
                    }`}
                    aria-hidden="true"
                  />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          <div className="mt-4 border-t border-slate-200 pt-4">
            <button
              type="button"
              onClick={onOpenMailbox}
              className="w-full inline-flex items-center justify-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-colors whitespace-nowrap"
            >
              <Mail className="w-3.5 h-3.5 text-blue-700" aria-hidden="true" />
              <span>Abrir Caixa Simulada</span>
            </button>
          </div>
        </aside>

        {/* Main Content Viewport */}
        <main className="lg:col-span-9 space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-4">
            <div>
              <p className="text-xs font-medium text-slate-500">{breadcrumbMap[activeTab]}</p>
              <h1 className="mt-1 text-2xl font-bold tracking-tight text-slate-900">
                {activeTab === 'overview' && 'Resumo da Identidade'}
                {activeTab === 'security' && 'Segurança da Conta e 2FA'}
                {activeTab === 'jwt' && 'Inspetor da Sessão JWT'}
                {activeTab === 'audit' && 'Registro de Atividades'}
              </h1>
            </div>
          </div>

          {errorMsg && (
            <div
              role="alert"
              className="flex items-start gap-2.5 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800"
            >
              <AlertCircle className="w-4 h-4 shrink-0 text-red-600 mt-0.5" aria-hidden="true" />
              <span>{errorMsg}</span>
            </div>
          )}

          {successMsg && (
            <div
              role="status"
              className="flex items-start gap-2.5 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900"
            >
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600 mt-0.5" aria-hidden="true" />
              <span>{successMsg}</span>
            </div>
          )}

          {/* TAB: OVERVIEW */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {!user.emailVerified && (
                <section className="rounded-xl border border-amber-200 bg-amber-50/70 p-6">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div>
                      <h2 className="text-base font-semibold text-slate-900">
                        Validação de e-mail pendente
                      </h2>
                      <p className="mt-1 text-sm text-slate-600 max-w-xl">
                        Confirme o endereço <span className="font-medium text-slate-900">{user.email}</span> usando o código de 6 dígitos enviado para concluir a verificação da conta.
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        disabled={busy}
                        onClick={handleResendVerification}
                        className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 whitespace-nowrap"
                      >
                        Reenviar código
                      </button>
                      <button
                        type="button"
                        onClick={onOpenMailbox}
                        className="rounded-lg bg-blue-700 px-3 py-2 text-xs font-medium text-white hover:bg-blue-800 whitespace-nowrap"
                      >
                        Ver código na Caixa
                      </button>
                    </div>
                  </div>

                  <form
                    onSubmit={handleInlineVerifyEmail}
                    className="mt-4 flex flex-wrap items-end gap-3"
                  >
                    <div>
                      <label
                        htmlFor="inline-verify-code"
                        className="block text-xs font-medium text-slate-700"
                      >
                        Código de 6 dígitos
                      </label>
                      <input
                        id="inline-verify-code"
                        type="text"
                        inputMode="numeric"
                        maxLength={6}
                        value={inlineVerifyCode}
                        onChange={(e) => setInlineVerifyCode(e.target.value.replace(/\D/g, ''))}
                        placeholder="000000"
                        className="mt-1 w-40 rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-sm tracking-widest text-slate-900 focus:border-blue-700 focus:outline-none"
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={busy}
                      className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60 whitespace-nowrap"
                    >
                      Validar E-mail
                    </button>
                  </form>
                </section>
              )}

              {/* 3-Column KPI Strip */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="rounded-xl border border-slate-200 bg-white p-5">
                  <p className="text-xs font-medium text-slate-500">Validação de E-mail</p>
                  <div className="mt-2 flex items-center gap-2">
                    {user.emailVerified ? (
                      <CheckCircle2 className="w-5 h-5 text-emerald-600" aria-hidden="true" />
                    ) : (
                      <ShieldAlert className="w-5 h-5 text-amber-600" aria-hidden="true" />
                    )}
                    <span className="text-lg font-semibold text-slate-900">
                      {user.emailVerified ? 'Verificado' : 'Pendente'}
                    </span>
                  </div>
                  <p className="mt-1.5 text-xs text-slate-500 truncate">{user.email}</p>
                </div>

                <div className="rounded-xl border border-slate-200 bg-white p-5">
                  <p className="text-xs font-medium text-slate-500">Segundo Fator (2FA)</p>
                  <div className="mt-2 flex items-center gap-2">
                    {user.twoFactorEnabled ? (
                      <ShieldCheck className="w-5 h-5 text-emerald-600" aria-hidden="true" />
                    ) : (
                      <Lock className="w-5 h-5 text-slate-400" aria-hidden="true" />
                    )}
                    <span className="text-lg font-semibold text-slate-900">
                      {user.twoFactorEnabled ? 'Ativo (TOTP)' : 'Desativado'}
                    </span>
                  </div>
                  <p className="mt-1.5 text-xs text-slate-500">
                    {user.twoFactorEnabled ? (
                      <>
                        <span className="font-mono font-medium text-slate-700">
                          {user.backupCodesRemaining}
                        </span>{' '}
                        código(s) de backup
                      </>
                    ) : (
                      'Recomendado ativar'
                    )}
                  </p>
                </div>

                <div className="rounded-xl border border-slate-200 bg-white p-5">
                  <p className="text-xs font-medium text-slate-500">Eventos Registrados</p>
                  <p className="mt-2 text-2xl font-bold font-mono text-slate-900">
                    {eventsLoading && events.length === 0 ? '—' : events.length}
                  </p>
                  <p className="mt-1.5 text-xs text-slate-500">
                    Persistidos no Cloud SQL
                  </p>
                </div>
              </div>

              {/* Action cards */}
              <div className="rounded-xl border border-slate-200 bg-white p-6">
                <h2 className="text-base font-semibold text-slate-900">
                  Próximas configurações recomendadas
                </h2>
                <div className="mt-4 divide-y divide-slate-200">
                  <div className="flex flex-wrap items-center justify-between gap-4 py-3.5 first:pt-0">
                    <div>
                      <p className="text-sm font-medium text-slate-900">
                        Autenticação em Dois Fatores (TOTP)
                      </p>
                      <p className="text-xs text-slate-500">
                        {user.twoFactorEnabled
                          ? 'Proteção ativa via aplicativo autenticador e códigos de backup.'
                          : 'Proteja seu login exigindo um código de 6 dígitos além da senha.'}
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => onChangeTab('security')}
                      className="rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-medium text-slate-800 hover:bg-slate-50 whitespace-nowrap"
                    >
                      {user.twoFactorEnabled ? 'Gerenciar 2FA' : 'Configurar 2FA'}
                    </button>
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-4 py-3.5 last:pb-0">
                    <div>
                      <p className="text-sm font-medium text-slate-900">
                        Inspeção do Token JWT
                      </p>
                      <p className="text-xs text-slate-500">
                        Confira os claims reais assinados pelo servidor Express e valide a sessão.
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => onChangeTab('jwt')}
                      className="rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-medium text-slate-800 hover:bg-slate-50 whitespace-nowrap"
                    >
                      Ver Sessão JWT
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB: SECURITY & 2FA */}
          {activeTab === 'security' && (
            <div className="space-y-6">
              {/* 2FA Section */}
              <section className="rounded-xl border border-slate-200 bg-white p-6">
                <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-200 pb-4">
                  <div>
                    <h2 className="text-base font-semibold text-slate-900">
                      Autenticação em Dois Fatores (2FA / TOTP)
                    </h2>
                    <p className="mt-1 text-sm text-slate-500">
                      Adicione uma segunda camada de proteção compatível com Google Authenticator, Authy ou 1Password.
                    </p>
                  </div>
                  <span
                    className={`text-xs font-semibold ${
                      user.twoFactorEnabled ? 'text-emerald-700' : 'text-slate-500'
                    }`}
                  >
                    {user.twoFactorEnabled ? 'Status: Ativo' : 'Status: Desativado'}
                  </span>
                </div>

                {!user.twoFactorEnabled && !setupData && (
                  <div className="mt-5 flex flex-wrap items-center justify-between gap-4">
                    <p className="text-sm text-slate-600 max-w-lg">
                      Ao ativar o 2FA, você receberá um QR Code para escanear no seu celular e 8 códigos de backup de uso único.
                    </p>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={handleStartTwoFactorSetup}
                      className="rounded-lg bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-60 whitespace-nowrap"
                    >
                      Configurar 2FA com QR Code
                    </button>
                  </div>
                )}

                {!user.twoFactorEnabled && setupData && (
                  <div className="mt-6 grid grid-cols-1 md:grid-cols-12 gap-6 items-start">
                    <div className="md:col-span-5 flex flex-col items-center rounded-lg border border-slate-200 bg-slate-50 p-5">
                      <img
                        src={setupData.qrCodeDataUrl}
                        alt="QR Code para configurar autenticação 2FA"
                        className="h-44 w-44 rounded-md border border-slate-200 bg-white p-2"
                      />
                      <p className="mt-3 text-xs text-slate-500 text-center">
                        Chave manual (Base32):
                      </p>
                      <div className="mt-1.5 flex items-center gap-2">
                        <code className="font-mono text-xs font-medium text-slate-900 break-all text-center">
                          {setupData.manualKey}
                        </code>
                        <button
                          type="button"
                          onClick={copyManualKey}
                          className="rounded p-1 text-blue-700 hover:bg-blue-50"
                          aria-label="Copiar chave manual 2FA"
                        >
                          {copiedKey ? (
                            <Check className="w-3.5 h-3.5" aria-hidden="true" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                          )}
                        </button>
                      </div>
                    </div>

                    <form onSubmit={handleEnableTwoFactor} className="md:col-span-7 space-y-4">
                      <div>
                        <h3 className="text-sm font-semibold text-slate-900">
                          Confirmar ativação
                        </h3>
                        <p className="mt-1 text-xs text-slate-500 leading-relaxed">
                          Escaneie o QR Code ao lado com seu aplicativo autenticador e digite o código atual de 6 dígitos para ativar.
                        </p>
                      </div>

                      <div>
                        <label
                          htmlFor="confirm-totp-code"
                          className="block text-xs font-medium text-slate-700"
                        >
                          Código do autenticador (6 dígitos)
                        </label>
                        <input
                          id="confirm-totp-code"
                          type="text"
                          inputMode="numeric"
                          maxLength={6}
                          value={totpConfirmCode}
                          onChange={(e) => setTotpConfirmCode(e.target.value.replace(/\D/g, ''))}
                          placeholder="000000"
                          className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 font-mono text-base tracking-widest text-slate-900 focus:border-blue-700 focus:outline-none"
                          required
                        />
                      </div>

                      <div className="flex flex-wrap items-center gap-3">
                        <button
                          type="submit"
                          disabled={busy}
                          className="rounded-lg bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-60 whitespace-nowrap"
                        >
                          {busy ? 'Ativando...' : 'Verificar e Ativar 2FA'}
                        </button>
                        <button
                          type="button"
                          onClick={() => setSetupData(null)}
                          className="rounded-lg border border-slate-300 bg-white px-4 py-2.5 text-sm font-medium text-slate-700 hover:bg-slate-50 whitespace-nowrap"
                        >
                          Cancelar
                        </button>
                      </div>
                    </form>
                  </div>
                )}

                {backupCodes && (
                  <div className="mt-6 border-t border-slate-200 pt-5">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <h3 className="text-sm font-semibold text-slate-900">
                          Seus 8 códigos de backup (uso único)
                        </h3>
                        <p className="mt-0.5 text-xs text-slate-600">
                          Salve estes códigos agora. Eles permitem acessar sua conta caso você perca o celular.
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={copyBackupCodes}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-800 hover:bg-slate-50"
                        >
                          {copiedBackup ? (
                            <Check className="w-3.5 h-3.5 text-emerald-600" aria-hidden="true" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                          )}
                          <span>{copiedBackup ? 'Copiados' : 'Copiar todos'}</span>
                        </button>
                        <button
                          type="button"
                          onClick={downloadBackupCodes}
                          className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-slate-800"
                        >
                          <Download className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>Baixar .txt</span>
                        </button>
                      </div>
                    </div>

                    <div className="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-2">
                      {backupCodes.map((code) => (
                        <div
                          key={code}
                          className="rounded-md bg-slate-50 px-3 py-2 text-center font-mono text-xs font-semibold text-slate-900"
                        >
                          {code}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {user.twoFactorEnabled && (
                  <form onSubmit={handleDisableTwoFactor} className="mt-6 space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-600">
                      <span>
                        Códigos de backup disponíveis:{' '}
                        <strong className="font-mono text-slate-900">
                          {user.backupCodesRemaining}
                        </strong>
                      </span>
                    </div>

                    <div className="border-t border-slate-200 pt-4">
                      <h3 className="text-sm font-semibold text-slate-900">
                        Desativar autenticação 2FA
                      </h3>
                      <p className="mt-1 text-xs text-slate-500">
                        Para sua segurança, confirme com o código atual do autenticador ou com sua senha.
                      </p>

                      <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                          <label
                            htmlFor="disable-totp"
                            className="block text-xs font-medium text-slate-700"
                          >
                            Código TOTP atual (6 dígitos)
                          </label>
                          <input
                            id="disable-totp"
                            type="text"
                            inputMode="numeric"
                            maxLength={6}
                            value={disableCode}
                            onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, ''))}
                            placeholder="000000"
                            className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2 font-mono text-sm text-slate-900 focus:border-blue-700 focus:outline-none"
                          />
                        </div>

                        {user.hasPassword && (
                          <div>
                            <label
                              htmlFor="disable-password"
                              className="block text-xs font-medium text-slate-700"
                            >
                              Ou senha atual da conta
                            </label>
                            <input
                              id="disable-password"
                              type="password"
                              value={disablePassword}
                              onChange={(e) => setDisablePassword(e.target.value)}
                              placeholder="Sua senha"
                              className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm text-slate-900 focus:border-blue-700 focus:outline-none"
                            />
                          </div>
                        )}
                      </div>

                      <button
                        type="submit"
                        disabled={busy}
                        className="mt-4 rounded-lg border border-red-300 bg-white px-4 py-2 text-xs font-semibold text-red-700 hover:bg-red-50 disabled:opacity-60 whitespace-nowrap"
                      >
                        Desativar 2FA
                      </button>
                    </div>
                  </form>
                )}
              </section>

              {/* Password Change Section */}
              <section className="rounded-xl border border-slate-200 bg-white p-6">
                <h2 className="text-base font-semibold text-slate-900">
                  {user.hasPassword ? 'Alterar senha (bcrypt)' : 'Definir senha local (bcrypt)'}
                </h2>
                <p className="mt-1 text-sm text-slate-500">
                  {user.hasPassword
                    ? 'A senha atual será validada antes de gerar o novo hash bcrypt.'
                    : 'Sua conta foi criada via Google. Você pode definir uma senha local opcional abaixo.'}
                </p>

                <form onSubmit={handleChangePassword} className="mt-5 max-w-lg space-y-4">
                  {user.hasPassword && (
                    <div>
                      <label
                        htmlFor="dash-current-pwd"
                        className="block text-xs font-medium text-slate-700"
                      >
                        Senha atual
                      </label>
                      <input
                        id="dash-current-pwd"
                        type="password"
                        autoComplete="current-password"
                        value={currentPassword}
                        onChange={(e) => setCurrentPassword(e.target.value)}
                        className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm text-slate-900 focus:border-blue-700 focus:outline-none"
                        required
                      />
                    </div>
                  )}

                  <div>
                    <label
                      htmlFor="dash-new-pwd"
                      className="block text-xs font-medium text-slate-700"
                    >
                      Nova senha
                    </label>
                    <input
                      id="dash-new-pwd"
                      type="password"
                      autoComplete="new-password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm text-slate-900 focus:border-blue-700 focus:outline-none"
                      required
                    />
                    <PasswordStrengthMeter password={newPassword} />
                  </div>

                  <div>
                    <label
                      htmlFor="dash-confirm-pwd"
                      className="block text-xs font-medium text-slate-700"
                    >
                      Confirmar nova senha
                    </label>
                    <input
                      id="dash-confirm-pwd"
                      type="password"
                      autoComplete="new-password"
                      value={confirmNewPassword}
                      onChange={(e) => setConfirmNewPassword(e.target.value)}
                      className="mt-1.5 block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm text-slate-900 focus:border-blue-700 focus:outline-none"
                      required
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={busy}
                    className="rounded-lg bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-60 whitespace-nowrap"
                  >
                    Salvar Nova Senha
                  </button>
                </form>
              </section>
            </div>
          )}

          {/* TAB: JWT INSPECTOR */}
          {activeTab === 'jwt' && (
            <div className="rounded-xl border border-slate-200 bg-white p-6 space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-4">
                <div>
                  <h2 className="text-base font-semibold text-slate-900">
                    Claims do Token JWT Ativo (em memória)
                  </h2>
                  <p className="mt-1 text-sm text-slate-500">
                    O token permanece exclusivamente na memória da aplicação e é enviado no cabeçalho{' '}
                    <code className="font-mono text-xs text-slate-700">Authorization: Bearer</code>.
                  </p>
                </div>
                <button
                  type="button"
                  disabled={busy}
                  onClick={handleVerifyServerJwt}
                  className="inline-flex items-center gap-2 rounded-lg bg-blue-700 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-800 disabled:opacity-60 whitespace-nowrap"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${busy ? 'animate-spin' : ''}`} aria-hidden="true" />
                  <span>Validar Token no Servidor</span>
                </button>
              </div>

              {serverCheckResult && (
                <p className="text-xs text-emerald-700 font-medium">
                  Última verificação remota bem-sucedida às{' '}
                  <span className="font-mono">{serverCheckResult.verifiedAt}</span> para usuário #
                  <span className="font-mono">{serverCheckResult.userId}</span>.
                </p>
              )}

              {decodedJwt.claims && (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="border-b border-slate-200 text-xs text-slate-500">
                      <tr>
                        <th className="py-2.5 pr-4 font-medium">Claim</th>
                        <th className="py-2.5 font-medium">Valor decodificado</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-mono text-xs">
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-500">alg / typ</td>
                        <td className="py-2.5 text-slate-900">
                          {String(decodedJwt.header?.alg ?? 'HS256')} ·{' '}
                          {String(decodedJwt.header?.typ ?? 'JWT')}
                        </td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-500">sub (userId)</td>
                        <td className="py-2.5 text-slate-900">{decodedJwt.claims.sub}</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-500">email</td>
                        <td className="py-2.5 text-slate-900">{decodedJwt.claims.email}</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-500">emailVerified</td>
                        <td className="py-2.5 text-slate-900">
                          {String(decodedJwt.claims.emailVerified)}
                        </td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-500">twoFactorVerified</td>
                        <td className="py-2.5 text-slate-900">
                          {String(decodedJwt.claims.twoFactorVerified)}
                        </td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-500">purpose</td>
                        <td className="py-2.5 text-slate-900">{decodedJwt.claims.purpose}</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-500">iat (emitido em)</td>
                        <td className="py-2.5 text-slate-900">
                          {decodedJwt.claims.iat
                            ? new Date(decodedJwt.claims.iat * 1000).toLocaleString('pt-BR')
                            : '-'}
                        </td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-500">exp (expira em)</td>
                        <td className="py-2.5 text-slate-900">
                          {decodedJwt.claims.exp
                            ? new Date(decodedJwt.claims.exp * 1000).toLocaleString('pt-BR')
                            : '-'}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB: AUDIT LOG */}
          {activeTab === 'audit' && (
            <div className="rounded-xl border border-slate-200 bg-white p-6 space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="relative flex-1 min-w-[220px] max-w-sm">
                  <Search
                    className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400"
                    aria-hidden="true"
                  />
                  <label htmlFor="audit-search" className="sr-only">
                    Buscar eventos de auditoria
                  </label>
                  <input
                    id="audit-search"
                    type="search"
                    value={eventSearch}
                    onChange={(e) => setEventSearch(e.target.value)}
                    placeholder="Filtrar por evento, detalhe ou IP..."
                    className="w-full rounded-lg border border-slate-300 bg-white py-2 pl-9 pr-3 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-700 focus:outline-none"
                  />
                </div>

                <div className="flex items-center gap-1 rounded-lg bg-slate-100 p-1">
                  {(
                    [
                      { id: 'all', label: 'Todos' },
                      { id: 'success', label: 'Sucesso' },
                      { id: 'warning', label: 'Alertas' },
                      { id: 'blocked', label: 'Bloqueios' },
                    ] as const
                  ).map((f) => (
                    <button
                      key={f.id}
                      type="button"
                      onClick={() => setEventFilter(f.id)}
                      className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
                        eventFilter === f.id
                          ? 'bg-white text-slate-900 shadow-sm'
                          : 'text-slate-600 hover:text-slate-900'
                      }`}
                    >
                      {f.label}
                    </button>
                  ))}
                </div>
              </div>

              {eventsLoading ? (
                <div className="space-y-2.5 py-2">
                  <div className="h-10 rounded-lg bg-slate-100 animate-pulse" />
                  <div className="h-10 rounded-lg bg-slate-100 animate-pulse" />
                  <div className="h-10 rounded-lg bg-slate-100 animate-pulse" />
                </div>
              ) : eventsError ? (
                <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800">
                  {eventsError}
                </div>
              ) : filteredEvents.length === 0 ? (
                <div className="py-10 text-center text-sm text-slate-500">
                  Nenhum evento encontrado para o filtro selecionado.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="border-b border-slate-200 text-xs text-slate-500">
                      <tr>
                        <th className="py-2.5 pr-4 font-medium">Data / Hora</th>
                        <th className="py-2.5 pr-4 font-medium">Evento</th>
                        <th className="py-2.5 pr-4 font-medium">Resultado</th>
                        <th className="py-2.5 pr-4 font-medium">Detalhes</th>
                        <th className="py-2.5 font-medium text-right">IP</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 text-xs">
                      {filteredEvents.map((ev) => (
                        <tr key={ev.id} className="hover:bg-slate-50/70">
                          <td className="py-3 pr-4 font-mono text-slate-500 whitespace-nowrap">
                            {new Date(ev.createdAt).toLocaleString('pt-BR')}
                          </td>
                          <td className="py-3 pr-4 font-medium text-slate-900 whitespace-nowrap">
                            {ev.eventType}
                          </td>
                          <td className="py-3 pr-4 whitespace-nowrap">
                            <span
                              className={`font-medium ${
                                ev.status === 'success'
                                  ? 'text-emerald-700'
                                  : ev.status === 'blocked'
                                    ? 'text-red-700'
                                    : 'text-amber-700'
                              }`}
                            >
                              {ev.status === 'success'
                                ? 'Confirmado'
                                : ev.status === 'blocked'
                                  ? 'Bloqueado'
                                  : 'Atenção'}
                            </span>
                          </td>
                          <td className="py-3 pr-4 text-slate-600">{ev.detail}</td>
                          <td className="py-3 font-mono text-slate-500 text-right whitespace-nowrap">
                            {ev.ipAddress}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
