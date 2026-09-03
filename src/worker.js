import { detectAuthProviders } from './auth-detector.js';

const WINDOW_MS = 10_000;
const MAX_ATTEMPTS = 5;
const LOCK_MS = 15_000;
const LAB_PIN = '042069';
const LAB_USER = 'admin@lab.local';
const LAB_PASSWORD_SHA256 = 'c5a6450e7b2225132224341bbf1f4b6de50ffbaaf0d7dabd5a6f6da69ea97778';

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Cache-Control': 'no-store',
  'Content-Type': 'application/json; charset=utf-8'
};

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...cors, ...extra } });
}

async function sha256(text) {
  const bytes = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function normalizeTarget(raw) {
  try {
    const url = new URL(String(raw || '').trim());
    if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) return null;
    return url;
  } catch { return null; }
}

function isPublicHostname(hostname) {
  const host = String(hostname || '').trim().toLowerCase().replace(/\.$/, '');
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return false;
  if (host === '0.0.0.0' || host === '::1' || host === '[::1]') return false;
  if (/^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host) || /^169\.254\./.test(host)) return false;
  const m = host.match(/^172\.(\d+)\./);
  return !(m && Number(m[1]) >= 16 && Number(m[1]) <= 31);
}

function validateAuthorizedTarget(raw, authorized) {
  const target = normalizeTarget(raw);
  if (!authorized) return { error: json({ ok:false, error:'authorization_required', classification:'indeterminate' }, 400) };
  if (!target || !isPublicHostname(target.hostname)) return { error: json({ ok:false, error:'target_not_allowed', classification:'indeterminate', message:'Use apenas uma URL HTTPS pública que você tenha autorização para testar.' }, 403) };
  return { target };
}

function summarizeDiscovery(discovery) {
  const firebaseHint = discovery?.adapterHints?.firebase;
  const activeAdapter = discovery?.provider === 'firebase' && firebaseHint?.apiKey ? 'firebase-password' : 'detection-only';
  return {
    provider: discovery?.provider || 'custom-or-unknown',
    confidence: discovery?.confidence || 'low',
    type: discovery?.type || 'authentication',
    adapter: activeAdapter,
    detections: discovery?.detections || [],
    endpoints: discovery?.endpoints || [],
    externalOrigins: discovery?.externalOrigins || [],
    cookies: discovery?.cookies || [],
    storage: discovery?.storage || { localStorage:[], sessionStorage:[] },
    jwtClaims: discovery?.jwtClaims || [],
    oidcMetadata: discovery?.oidcMetadata || [],
    responseHeaders: discovery?.responseHeaders || {},
    customAuth: discovery?.customAuth || null,
    scannedScripts: discovery?.scannedScripts || 0,
    finalOrigin: discovery?.finalOrigin || null,
    evidence: discovery?.detections?.[0]?.evidence || []
  };
}

async function discover(target) {
  return detectAuthProviders(target);
}

function classifyFirebaseError(code) {
  const value = String(code || 'AUTH_FAILED').toUpperCase();
  if (/TOO_MANY|QUOTA|RATE|TRY_LATER/.test(value)) return 'blocked';
  if (/INVALID_LOGIN_CREDENTIALS|INVALID_PASSWORD|EMAIL_NOT_FOUND/.test(value)) return 'invalid';
  return 'indeterminate';
}

async function handleProviderDetect(request) {
  let body = {};
  try { body = await request.json(); } catch {}
  const checked = validateAuthorizedTarget(body?.url, body?.authorized === true);
  if (checked.error) return checked.error;
  const started = Date.now();
  try {
    const discovery = await discover(checked.target);
    return json({
      ok:true,
      ...summarizeDiscovery(discovery),
      latencyMs:Date.now()-started,
      limitations:{
        browserStorage:'localStorage/sessionStorage de outro domínio não são lidos diretamente; somente nomes e referências expostos em conteúdo público são analisados.',
        jwt:'JWTs privados e tokens de sessão não são coletados; somente padrões e nomes de claims expostos legitimamente são analisados.'
      }
    });
  } catch (error) {
    return json({ ok:false, error:'target_unreachable', classification:'indeterminate', detail:String(error?.message || 'fetch_failed'), latencyMs:Date.now()-started }, 502);
  }
}

async function testFirebaseCredential(discovery, email, password, started) {
  const config = discovery?.adapterHints?.firebase;
  if (!config?.apiKey) return json({ ok:false, error:'adapter_configuration_missing', classification:'indeterminate', provider:'firebase', authType:'detection-only', latencyMs:Date.now()-started }, 422);

  const endpoint = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(config.apiKey)}`;
  let response, data;
  try {
    response = await fetch(endpoint, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ email, password, returnSecureToken:true })
    });
    data = await response.json().catch(()=>({}));
  } catch {
    return json({ ok:false, authenticated:false, classification:'indeterminate', provider:'firebase', authType:'firebase-password', error:'provider_unreachable', latencyMs:Date.now()-started }, 502);
  }

  const latencyMs = Date.now()-started;
  if (response.ok && data?.localId) return json({
    ok:true,
    authenticated:true,
    classification:'authenticated',
    provider:'firebase',
    authType:'firebase-password',
    providerHttpStatus:response.status,
    latencyMs
  });

  const providerCode = String(data?.error?.message || 'AUTH_FAILED');
  const classification = classifyFirebaseError(providerCode);
  const status = classification === 'blocked' ? 429 : classification === 'invalid' ? 401 : 422;
  return json({
    ok:false,
    authenticated:false,
    classification,
    provider:'firebase',
    authType:'firebase-password',
    error:classification === 'blocked' ? 'rate_limited' : classification === 'invalid' ? 'invalid_credentials' : 'indeterminate_auth_result',
    providerCode,
    providerHttpStatus:response.status,
    retryAfter:response.headers.get('retry-after') || null,
    latencyMs
  }, status);
}

async function handleUrlAuthTest(request) {
  let body = {};
  try { body = await request.json(); } catch {}
  const checked = validateAuthorizedTarget(body?.url, body?.authorized === true);
  if (checked.error) return checked.error;
  const email = String(body?.email || '').trim();
  const password = String(body?.password || '');
  if (!email || !password || email.length > 254 || password.length > 256) return json({ ok:false, error:'invalid_input', classification:'indeterminate' }, 400);

  const started = Date.now();
  let discovery;
  try { discovery = await discover(checked.target); }
  catch (error) { return json({ ok:false, error:'target_unreachable', classification:'indeterminate', detail:String(error?.message || 'fetch_failed'), latencyMs:Date.now()-started }, 502); }

  if (discovery.provider === 'firebase' && discovery?.adapterHints?.firebase?.apiKey) return testFirebaseCredential(discovery, email, password, started);

  const summary = summarizeDiscovery(discovery);
  return json({
    ok:false,
    error:'adapter_not_available',
    classification:'indeterminate',
    provider:summary.provider,
    confidence:summary.confidence,
    authType:'detection-only',
    evidence:summary.evidence,
    customAuth:summary.customAuth,
    latencyMs:Date.now()-started,
    message:summary.provider === 'custom-api'
      ? 'Fluxo customizado detectado. O LIMPO não envia credenciais automaticamente para um endpoint desconhecido.'
      : 'O provedor foi detectado, mas não existe adaptador ativo e seguro para teste de credencial neste fluxo.'
  }, 422);
}

export class LoginLimiter {
  constructor(ctx) { this.ctx = ctx; }

  async fetch(request) {
    const url = new URL(request.url);
    const mode = url.pathname.includes('/auth/') || url.pathname.includes('/lab/vulnerable/') ? 'password' : 'pin';
    const stateKey = `state:${mode}`;
    const now = Date.now();
    const stored = await this.ctx.storage.get(stateKey);
    const state = stored || { hits:[], lockedUntil:0, total:0 };

    if (state.lockedUntil > now) {
      const retryAfterMs = state.lockedUntil-now;
      return json({ ok:false, error:'locked', retryAfterMs, totalAttempts:state.total }, 429, { 'Retry-After':String(Math.ceil(retryAfterMs/1000)) });
    }

    state.hits = state.hits.filter(t=>now-t<WINDOW_MS);
    if (state.hits.length >= MAX_ATTEMPTS) {
      state.lockedUntil = now+LOCK_MS;
      state.hits = [];
      await this.ctx.storage.put(stateKey, state);
      return json({ ok:false, error:'rate_limited', retryAfterMs:LOCK_MS, totalAttempts:state.total }, 429, { 'Retry-After':String(Math.ceil(LOCK_MS/1000)) });
    }

    let body = {};
    try { body = await request.json(); } catch {}
    state.hits.push(now);
    state.total++;

    let valid = false;
    let successMessage = '';
    if (mode === 'password') {
      const username = String(body?.username ?? '').trim().toLowerCase();
      const passwordHash = await sha256(String(body?.password ?? ''));
      valid = username === LAB_USER && passwordHash === LAB_PASSWORD_SHA256;
      successMessage = 'Login fictício autorizado';
    } else {
      const pin = String(body?.pin ?? '').replace(/\D/g,'').slice(0,6);
      valid = pin === LAB_PIN;
      successMessage = 'PIN fictício correto';
    }

    if (valid) {
      state.hits = [];
      state.lockedUntil = 0;
      await this.ctx.storage.put(stateKey, state);
      return json({ ok:true, message:successMessage, totalAttempts:state.total });
    }

    await this.ctx.storage.put(stateKey, state);
    return json({ ok:false, error:mode === 'password' ? 'invalid_credentials' : 'invalid_pin', remaining:Math.max(0,MAX_ATTEMPTS-state.hits.length), totalAttempts:state.total }, 401);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { status:204, headers:cors });

    if (url.pathname === '/url-provider-detect') {
      if (request.method !== 'POST') return json({ ok:false, error:'method_not_allowed' }, 405);
      return handleProviderDetect(request);
    }
    if (url.pathname === '/url-auth-test') {
      if (request.method !== 'POST') return json({ ok:false, error:'method_not_allowed' }, 405);
      return handleUrlAuthTest(request);
    }

    const isSecureLogin = url.pathname === '/auth/login';
    const isVulnerableLogin = url.pathname === '/lab/vulnerable/login';
    const isPin = url.pathname === '/login' || url.pathname === '/api/login';
    const isApi = isSecureLogin || isVulnerableLogin || isPin;
    if (!isApi) return env.ASSETS.fetch(request);
    if (request.method !== 'POST') return json({ ok:false, error:'method_not_allowed' }, 405);

    let body = {};
    if (isVulnerableLogin) { try { body = await request.clone().json(); } catch {} }
    const ip = request.headers.get('CF-Connecting-IP') || 'lab-client';
    const clientKey = isVulnerableLogin ? `vuln:${String(body?.labClientId || 'client-a').slice(0,64)}` : `secure:${ip}`;
    const id = env.LOGIN_LIMITER.idFromName(clientKey);
    return env.LOGIN_LIMITER.get(id).fetch(request);
  }
};
