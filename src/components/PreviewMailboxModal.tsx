import { Check, Copy, Mail, RefreshCw, Trash2, X } from 'lucide-react';
import { useState } from 'react';
import { PreviewEmail } from '../types/auth';

interface PreviewMailboxModalProps {
  open: boolean;
  onClose: () => void;
  emails: PreviewEmail[];
  loading: boolean;
  smtpConfigured: boolean;
  onRefresh: () => void;
  onClear: () => void;
  onUseVerificationEmail: (email: PreviewEmail) => void;
  onUseResetEmail: (email: PreviewEmail) => void;
}

export function PreviewMailboxModal({
  open,
  onClose,
  emails,
  loading,
  smtpConfigured,
  onRefresh,
  onClear,
  onUseVerificationEmail,
  onUseResetEmail,
}: PreviewMailboxModalProps) {
  const [copiedId, setCopiedId] = useState<number | null>(null);

  if (!open) return null;

  const handleCopyCode = async (mail: PreviewEmail) => {
    try {
      await navigator.clipboard.writeText(mail.actionCode);
      setCopiedId(mail.id);
      setTimeout(() => setCopiedId(null), 1800);
    } catch {
      // Clipboard fallback ignored cleanly
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/45 p-4 backdrop-blur-[2px]"
      role="dialog"
      aria-modal="true"
      aria-labelledby="mailbox-modal-title"
    >
      <div className="w-full max-w-2xl rounded-xl border border-slate-200 bg-white shadow-xl">
        <div className="flex items-center justify-between gap-4 border-b border-slate-200 px-6 py-4">
          <div>
            <h2
              id="mailbox-modal-title"
              className="text-base font-semibold text-slate-900"
            >
              Caixa de Entrada Simulada
            </h2>
            <p className="mt-0.5 text-xs text-slate-500">
              {smtpConfigured
                ? 'Servidor SMTP ativo: novos envios seguem pelo provedor configurado.'
                : 'Ambiente sem SMTP externo: mensagens desta sessão aparecem aqui para teste imediato.'}
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={onRefresh}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 whitespace-nowrap"
              aria-label="Atualizar caixa de entrada simulada"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
              <span>Atualizar</span>
            </button>
            {emails.length > 0 && (
              <button
                type="button"
                onClick={onClear}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 whitespace-nowrap"
                aria-label="Limpar mensagens simuladas"
              >
                <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Limpar</span>
              </button>
            )}
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-900"
              aria-label="Fechar caixa de entrada simulada"
            >
              <X className="w-4 h-4" aria-hidden="true" />
            </button>
          </div>
        </div>

        <div className="max-h-[70vh] overflow-y-auto p-6">
          {loading && emails.length === 0 ? (
            <div className="space-y-3 py-4">
              <div className="h-20 rounded-lg bg-slate-100 animate-pulse" />
              <div className="h-20 rounded-lg bg-slate-100 animate-pulse" />
            </div>
          ) : emails.length === 0 ? (
            <div className="py-10 text-center">
              <Mail className="mx-auto h-8 w-8 text-slate-300" aria-hidden="true" />
              <p className="mt-3 text-sm font-medium text-slate-900">
                Nenhuma mensagem nesta sessão
              </p>
              <p className="mt-1 text-xs text-slate-500 max-w-md mx-auto">
                Cadastre uma nova conta ou solicite uma recuperação de senha para visualizar o código e o link de confirmação aqui.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-slate-200">
              {emails.map((mail) => (
                <article key={mail.id} className="py-4 first:pt-0 last:pb-0">
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <h3 className="text-sm font-semibold text-slate-900">{mail.subject}</h3>
                    <time className="text-xs font-mono text-slate-500">
                      {new Date(mail.createdAt).toLocaleString('pt-BR')}
                    </time>
                  </div>

                  <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                    <span>Para: {mail.recipientEmail}</span>
                    <span aria-hidden="true">·</span>
                    <span>
                      {mail.category === 'verification'
                        ? 'Validação de e-mail'
                        : 'Recuperação de senha'}
                    </span>
                  </div>

                  <p className="mt-2.5 text-sm text-slate-600 leading-relaxed">
                    {mail.bodyPreview}
                  </p>

                  <div className="mt-3.5 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-slate-500">Código:</span>
                      <span className="font-mono text-base font-semibold tracking-wider text-slate-900">
                        {mail.actionCode}
                      </span>
                      <button
                        type="button"
                        onClick={() => handleCopyCode(mail)}
                        className="inline-flex items-center gap-1 text-xs font-medium text-blue-700 hover:text-blue-800 whitespace-nowrap"
                        aria-label={`Copiar código ${mail.actionCode}`}
                      >
                        {copiedId === mail.id ? (
                          <>
                            <Check className="w-3.5 h-3.5" aria-hidden="true" />
                            <span>Copiado</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                            <span>Copiar</span>
                          </>
                        )}
                      </button>
                    </div>

                    <button
                      type="button"
                      onClick={() =>
                        mail.category === 'verification'
                          ? onUseVerificationEmail(mail)
                          : onUseResetEmail(mail)
                      }
                      className="rounded-lg bg-blue-700 px-3.5 py-1.5 text-xs font-medium text-white hover:bg-blue-800 transition-colors whitespace-nowrap shrink-0"
                    >
                      {mail.category === 'verification'
                        ? 'Confirmar e-mail agora'
                        : 'Abrir redefinição de senha'}
                    </button>
                  </div>
                </article>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
