# Vértice Auth

Sistema completo de autenticação segura construído com **Node.js + Express.js**, **React + TypeScript + Tailwind CSS**, **Cloud SQL PostgreSQL (Drizzle ORM)** e **Firebase Auth**.

## Estrutura de Pastas

```text
.
├── server.ts                          # Servidor Express.js, rotas de autenticação e Vite middleware
├── index.html                         # Ponto de entrada HTML
├── package.json                       # Dependências e scripts (dev, build, start, lint)
├── tsconfig.json                      # Configuração TypeScript
├── vite.config.ts                     # Configuração Vite + Tailwind v4
├── .env.example                       # Modelo de variáveis de ambiente (sem segredos)
├── firebase-applet-config.json        # Configuração pública do projeto Firebase Auth
└── src/
    ├── App.tsx                        # Layout principal, barra de navegação e controle de sessão JWT
    ├── main.tsx                       # Bootstrap React
    ├── index.css                      # Estilos globais Tailwind CSS v4
    ├── components/
    │   ├── AuthPortal.tsx             # Telas de login, cadastro, validação de e-mail, 2FA e recuperação
    │   ├── PasswordStrengthMeter.tsx  # Indicador em tempo real dos 5 critérios de força de senha
    │   ├── PreviewMailboxModal.tsx    # Caixa de entrada simulada da sessão para testes sem SMTP
    │   └── SecurityDashboard.tsx      # Painel autenticado: visão geral, 2FA QR/TOTP, JWT e auditoria
    ├── db/
    │   ├── drizzle.config.ts          # Configuração Drizzle Kit
    │   ├── index.ts                   # Pool de conexões PostgreSQL
    │   ├── schema.ts                  # Tabelas users, auth_tokens, auth_events e preview_emails
    │   └── authRepo.ts                # Consultas tipadas e sanitizadas ao banco
    ├── lib/
    │   ├── apiClient.ts               # Cliente HTTP com envio do token Bearer em memória
    │   ├── authCrypto.ts              # Hash bcrypt, JWT HS256, TOTP 2FA, QR Code e códigos de backup
    │   ├── authCrypto.test.ts         # Testes unitários de criptografia e tokens
    │   ├── firebase.ts                # Inicialização Firebase Client SDK (Login Google)
    │   ├── firebase-admin.ts          # Verificação de ID Token no servidor
    │   └── mailer.ts                  # Envio via SMTP (Nodemailer) ou fallback na caixa simulada
    ├── middleware/
    │   └── auth.ts                    # Middleware Express para validação do JWT Bearer
    ├── types/
    │   └── auth.ts                    # Interfaces TypeScript compartilhadas
    └── utils/
        ├── authValidation.ts          # Validações puras de e-mail, força de senha, TOTP e backup codes
        └── authValidation.test.ts     # Testes unitários de validação
```

## Recursos Implementados

- **Autenticação JWT (HS256)** mantida apenas em memória no cliente (`Authorization: Bearer`).
- **Criptografia de senhas com bcrypt** (custo 12) e bloqueio temporário após 5 falhas consecutivas.
- **Validação de e-mail** com token SHA-256 e código de 6 dígitos (expiração de 24h).
- **2FA (TOTP RFC 6238)** com QR Code, chave manual Base32 e 8 códigos de backup de uso único.
- **Recuperação de senha** com token/código de uso único (expiração de 15 min) e trilha de auditoria.

## Publicar no GitHub

```bash
git remote add origin https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git
git branch -M main
git push -u origin main
```
