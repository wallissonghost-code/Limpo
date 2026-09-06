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

## Executar

Projeto preparado para Vercel (frontend estático + função serverless Node.js).

```bash
npm install
npx vercel dev
```

Depois abra a URL local mostrada pelo Vercel CLI.

## Segurança

A API aceita somente HTTP/HTTPS, bloqueia localhost e endereços IP privados/reservados e limita tamanho e tempo de resposta para reduzir risco de SSRF e abuso.
