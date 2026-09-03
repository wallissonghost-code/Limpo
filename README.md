# LIMPO

Laboratório autorizado de estudo de autenticação e rate limiting executado em Cloudflare Workers.

## Arquitetura

- `src/auth-detector.js`: única fonte de descoberta de autenticação. Analisa HTML, JavaScript, recursos externos explicitamente carregados, endpoints, cookies por nome, storage referenciado no frontend, headers e metadados OAuth/OIDC públicos.
- `src/worker.js`: único entrypoint do Cloudflare Worker. Usa o detector para `/url-provider-detect` e `/url-auth-test`, além dos endpoints do laboratório local.
- `public/index.html`: interface do laboratório.
- `wrangler.jsonc`: configuração de deploy e Durable Object de rate limit.

Não existe detector paralelo específico para Firebase. Firebase, Supabase, Auth0, Clerk, Cognito, Okta, Entra ID, Keycloak, Auth.js, Passport, JWT customizado, OAuth2, OIDC e fluxos customizados competem pelo mesmo sistema de pontuação baseado nos sinais observados.

O único adaptador ativo de credencial atualmente é Firebase Password e ele só é acionado depois que a descoberta independente classifica o alvo como Firebase e encontra a configuração pública necessária no frontend. Fluxos desconhecidos não recebem credenciais automaticamente.

## Privacidade e limites

O LIMPO não persiste senha de alvos, não retorna tokens de sessão e não lê diretamente `localStorage`/`sessionStorage` de outros domínios. Cookies são reportados apenas por nome. JWTs privados não são coletados.

## Comandos

```bash
npm run check
npm run dev
npm run deploy
```
