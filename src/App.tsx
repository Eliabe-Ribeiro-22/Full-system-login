import { useCallback, useEffect, useState } from 'react';
import { AuthPortal } from './components/AuthPortal';
import { PreviewMailboxModal } from './components/PreviewMailboxModal';
import { SecurityDashboard } from './components/SecurityDashboard';
import { apiRequest } from './lib/apiClient';
import { AuthScreen, DashboardTab, PreviewEmail, UserProfile } from './types/auth';

export default function App() {
  // JWT session token is intentionally kept strictly in React memory (never localStorage)
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<UserProfile | null>(null);

  const [authScreen, setAuthScreen] = useState<AuthScreen>('login');
  const [dashboardTab, setDashboardTab] = useState<DashboardTab>('overview');
  const [pendingEmail, setPendingEmail] = useState('');
  const [resetTokenPrefill, setResetTokenPrefill] = useState('');

  const [mailboxOpen, setMailboxOpen] = useState(false);
  const [mailboxEmails, setMailboxEmails] = useState<PreviewEmail[]>([]);
  const [mailboxLoading, setMailboxLoading] = useState(false);
  const [smtpConfigured, setSmtpConfigured] = useState(false);
  const [demoLoading, setDemoLoading] = useState(false);

  const refreshMailbox = useCallback(async () => {
    setMailboxLoading(true);
    try {
      const data = await apiRequest<{
        smtpConfigured: boolean;
        emails: PreviewEmail[];
      }>('/api/preview-emails', { token });
      setSmtpConfigured(data.smtpConfigured);
      setMailboxEmails(data.emails);
    } catch {
      // Ignore transient errors on optional preview mailbox fetch
    } finally {
      setMailboxLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void refreshMailbox();
  }, [refreshMailbox]);

  const handleAuthenticated = (nextToken: string, nextUser: UserProfile) => {
    setToken(nextToken);
    setUser(nextUser);
    setDashboardTab('overview');
    void refreshMailbox();
  };

  const handleSignOut = () => {
    setToken(null);
    setUser(null);
    setAuthScreen('login');
    setResetTokenPrefill('');
  };

  const handleDemoLogin = async () => {
    setDemoLoading(true);
    try {
      const data = await apiRequest<{ token: string; user: UserProfile }>('/api/auth/demo', {
        method: 'POST',
      });
      handleAuthenticated(data.token, data.user);
    } finally {
      setDemoLoading(false);
    }
  };

  const handleClearMailbox = async () => {
    try {
      await apiRequest('/api/preview-emails/clear', {
        method: 'POST',
        token,
      });
      setMailboxEmails([]);
    } catch {
      // Ignore
    }
  };

  const handleUseVerificationEmail = async (mail: PreviewEmail) => {
    setMailboxOpen(false);
    try {
      const data = await apiRequest<{
        verified: boolean;
        user: UserProfile;
        token?: string;
      }>('/api/auth/verify-email', {
        method: 'POST',
        token,
        body: { token: mail.actionToken },
      });

      if (data.token && data.user) {
        handleAuthenticated(data.token, data.user);
      } else if (user && data.user) {
        setUser(data.user);
      } else {
        setPendingEmail(mail.recipientEmail);
        setAuthScreen('login');
      }
    } catch {
      setPendingEmail(mail.recipientEmail);
      setAuthScreen('verify-email');
    }
  };

  const handleUseResetEmail = (mail: PreviewEmail) => {
    setMailboxOpen(false);
    setToken(null);
    setUser(null);
    setPendingEmail(mail.recipientEmail);
    setResetTokenPrefill(mail.actionToken);
    setAuthScreen('reset-password');
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col">
      {/* Strict 3-Zone Top Bar Contract */}
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto max-w-7xl px-6 py-4 flex items-center justify-between gap-8">
          <a
            href="#inicio"
            onClick={(e) => {
              e.preventDefault();
              if (user) {
                setDashboardTab('overview');
              } else {
                setAuthScreen('login');
              }
            }}
            className="font-display text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0"
          >
            Vértice Auth
          </a>

          <nav
            aria-label="Navegação principal"
            className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600"
          >
            {user ? (
              <>
                <button
                  type="button"
                  onClick={() => setDashboardTab('overview')}
                  className={`hover:text-slate-900 transition-colors whitespace-nowrap shrink-0 ${
                    dashboardTab === 'overview' ? 'text-slate-900 underline underline-offset-4' : ''
                  }`}
                >
                  Visão Geral
                </button>
                <button
                  type="button"
                  onClick={() => setDashboardTab('security')}
                  className={`hover:text-slate-900 transition-colors whitespace-nowrap shrink-0 ${
                    dashboardTab === 'security' ? 'text-slate-900 underline underline-offset-4' : ''
                  }`}
                >
                  Segurança & 2FA
                </button>
                <button
                  type="button"
                  onClick={() => setDashboardTab('jwt')}
                  className={`hover:text-slate-900 transition-colors whitespace-nowrap shrink-0 ${
                    dashboardTab === 'jwt' ? 'text-slate-900 underline underline-offset-4' : ''
                  }`}
                >
                  Sessão JWT
                </button>
                <button
                  type="button"
                  onClick={() => setDashboardTab('audit')}
                  className={`hover:text-slate-900 transition-colors whitespace-nowrap shrink-0 ${
                    dashboardTab === 'audit' ? 'text-slate-900 underline underline-offset-4' : ''
                  }`}
                >
                  Auditoria
                </button>
              </>
            ) : (
              <>
                <button
                  type="button"
                  onClick={() => setAuthScreen('login')}
                  className={`hover:text-slate-900 transition-colors whitespace-nowrap shrink-0 ${
                    authScreen === 'login' ? 'text-slate-900 underline underline-offset-4' : ''
                  }`}
                >
                  Entrar
                </button>
                <button
                  type="button"
                  onClick={() => setAuthScreen('register')}
                  className={`hover:text-slate-900 transition-colors whitespace-nowrap shrink-0 ${
                    authScreen === 'register' ? 'text-slate-900 underline underline-offset-4' : ''
                  }`}
                >
                  Criar Conta
                </button>
                <button
                  type="button"
                  onClick={() => setAuthScreen('forgot-password')}
                  className={`hover:text-slate-900 transition-colors whitespace-nowrap shrink-0 ${
                    authScreen === 'forgot-password' || authScreen === 'reset-password'
                      ? 'text-slate-900 underline underline-offset-4'
                      : ''
                  }`}
                >
                  Recuperar Senha
                </button>
                <button
                  type="button"
                  onClick={() => {
                    void refreshMailbox();
                    setMailboxOpen(true);
                  }}
                  className="hover:text-slate-900 transition-colors whitespace-nowrap shrink-0"
                >
                  Caixa Simulada ({mailboxEmails.length})
                </button>
              </>
            )}
          </nav>

          <div className="flex items-center gap-3 shrink-0">
            {user ? (
              <button
                type="button"
                onClick={handleSignOut}
                className="rounded-lg bg-slate-900 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
              >
                Encerrar Sessão
              </button>
            ) : (
              <button
                type="button"
                disabled={demoLoading}
                onClick={handleDemoLogin}
                className="rounded-lg bg-blue-700 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-800 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0"
              >
                {demoLoading ? 'Entrando...' : 'Acesso Demo'}
              </button>
            )}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1">
        {user && token ? (
          <SecurityDashboard
            user={user}
            token={token}
            activeTab={dashboardTab}
            onChangeTab={setDashboardTab}
            onUpdateSession={(nextToken, nextUser) => {
              setToken(nextToken);
              setUser(nextUser);
            }}
            onOpenMailbox={() => {
              void refreshMailbox();
              setMailboxOpen(true);
            }}
            onRefreshMailbox={() => void refreshMailbox()}
          />
        ) : (
          <AuthPortal
            screen={authScreen}
            onChangeScreen={setAuthScreen}
            pendingEmail={pendingEmail}
            onChangePendingEmail={setPendingEmail}
            resetTokenPrefill={resetTokenPrefill}
            onResetTokenPrefillChange={setResetTokenPrefill}
            onAuthenticated={handleAuthenticated}
            onOpenMailbox={() => {
              void refreshMailbox();
              setMailboxOpen(true);
            }}
            onRefreshMailbox={() => void refreshMailbox()}
            mailboxCount={mailboxEmails.length}
          />
        )}
      </div>

      {/* Quiet footer */}
      <footer className="border-t border-slate-200 bg-white">
        <div className="mx-auto max-w-7xl px-6 py-4 flex flex-wrap items-center justify-between gap-4 text-xs text-slate-500">
          <span>Vértice Auth · Autenticação JWT, bcrypt, Validação de E-mail e 2FA</span>
          <span>Express.js · Cloud SQL PostgreSQL · Firebase Auth</span>
        </div>
      </footer>

      <PreviewMailboxModal
        open={mailboxOpen}
        onClose={() => setMailboxOpen(false)}
        emails={mailboxEmails}
        loading={mailboxLoading}
        smtpConfigured={smtpConfigured}
        onRefresh={() => void refreshMailbox()}
        onClear={() => void handleClearMailbox()}
        onUseVerificationEmail={handleUseVerificationEmail}
        onUseResetEmail={handleUseResetEmail}
      />
    </div>
  );
}
