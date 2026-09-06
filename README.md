# LIMPO — Universal Auth Detector

Detector universal de autenticação por URL para Cloudflare Workers.

O LIMPO separa **provider** de **mecanismo de autenticação**. Mesmo quando não reconhece Firebase/Auth0/etc., tenta identificar comportamento de login, sessão, refresh, tokens, MFA, SSO e frameworks a partir de sinais públicos.

## Estados

- `AUTH_DETECTED`: há evidência suficiente de autenticação.
- `AUTH_UNKNOWN`: existem indícios relacionados, mas não o bastante para classificar com segurança.
- `NO_AUTH_EVIDENCE`: nenhuma evidência pública suficiente foi encontrada. Não significa que o site não possua autenticação.

## Camadas

1. Recon: HTML, redirects e headers.
2. Frontend crawl: scripts, chunks relacionados e source maps públicos.
3. Signal extraction: endpoints, headers de autorização, cookies por nome, storage, tokens e formulários.
4. Behavioral detection: login, logout, sessão, refresh, cadastro, reset de senha, MFA e SSO.
5. Framework hints: Next.js, Nuxt, Angular, Vue, Svelte, Remix, Astro, Laravel, Django, Rails, Spring, ASP.NET e outros.
6. Public probes: Firebase runtime config, OIDC metadata e manifestos same-origin.
7. Provider plugins: Firebase, Supabase, Auth0, Clerk, Cognito, Keycloak, Okta, Entra, Google Identity, Auth.js e Passport.
8. Scoring/classification: evidência forte, média e fraca.

## Estrutura

```text
worker.js
src/
  auth-detector.js
  detector/
    scanner.js
    signals.js
    generic.js
    probes.js
    scoring.js
    classifier.js
  providers/
    plugin.js
    firebase.js
    supabase.js
    auth0.js
    clerk.js
    cognito.js
    keycloak.js
    okta.js
    entra.js
    google.js
    authjs.js
    passport.js
    index.js
public/
  index.html
```

Adicionar um provider novo exige apenas criar um plugin em `src/providers/` e registrá-lo em `src/providers/index.js`.

## Segurança

O scanner usa somente requisições GET públicas. Ele não envia credenciais, não tenta autenticar, não retorna valores de cookies ou tokens, limita tamanho/tempo/quantidade de recursos e bloqueia URLs locais/privadas informadas diretamente. Cookies são expostos apenas pelo nome quando visíveis nos headers.

## Cloudflare

```bash
npm install
npm run dev
npm run deploy
```

A API fica em `POST /api/analyze` com body `{ "url": "https://exemplo.com/login" }`.
