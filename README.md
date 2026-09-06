# Auth Detector

Detector de tecnologia de autenticação por URL.

## O que detecta

- Firebase Authentication
- Supabase Auth
- Auth0
- Clerk
- AWS Cognito
- Keycloak
- Okta
- Microsoft Entra / MSAL
- Google Identity
- Auth.js / NextAuth

O sistema analisa apenas sinais publicamente expostos pela página: HTML, scripts, URLs de recursos e padrões conhecidos. O resultado é probabilístico e inclui nível de confiança e evidências.

## Cloudflare

Projeto preparado para Cloudflare Workers com Static Assets.

```bash
npm install
npm run dev
```

Para publicar:

```bash
npm run deploy
```

Arquivos principais:

- `worker.js`: API `/api/analyze` e lógica de detecção.
- `public/index.html`: interface web.
- `wrangler.jsonc`: configuração do Cloudflare Worker.

## Segurança

A API aceita somente HTTP/HTTPS, bloqueia localhost e IPs privados/reservados informados diretamente, limita redirecionamentos, tamanho de resposta e tempo de análise para reduzir risco de abuso.
