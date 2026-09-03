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
  let url;
  try { url = new URL(String(raw || '').trim()); } catch { return null; }
  if (url.protocol !== 'https:') return null;
  if (url.username || url.password) return null;
  if (url.port && url.port !== '443') return null;
  return url;
}

function isPublicHostname(hostname) {
  const host = String(hostname || '').trim().toLowerCase().replace(/\.$/, '');
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return false;
  if (host === '0.0.0.0' || host === '::1' || host === '[::1]') return false;
  if (/^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host)) return false;
  const m = host.match(/^172\.(\d+)\./);
  if (m && Number(m[1]) >= 16 && Number(m[1]) <= 31) return false;
  if (/^169\.254\./.test(host)) return false;
  return true;
}

function validateAuthorizedTarget(raw, authorized) {
  const target = normalizeTarget(raw);
  if (!authorized) return { error: json({ ok: false, error: 'authorization_required', classification: 'indeterminate' }, 400) };
  if (!target || !isPublicHostname(target.hostname)) {
    return { error: json({ ok: false, error: 'target_not_allowed', classification: 'indeterminate', message: 'Use apenas uma URL HTTPS pública que você tenha autorização para testar.' }, 403) };
  }
  return { target };
}

function extractFirebaseConfig(text) {
  const source = String(text || '');
  const apiKey = source.match(/apiKey\s*[:=]\s*["'`]([^"'`]+)["'`]/i)?.[1] || '';
  const authDomain = source.match(/authDomain\s*[:=]\s*["'`]([^"'`]+)["'`]/i)?.[1] || '';
  const projectId = source.match(/projectId\s*[:=]\s*["'`]([^"'`]+)["'`]/i)?.[1] || '';
  return { apiKey, authDomain, projectId };
}

function extractModuleUrls(text, baseUrl) {
  const found = new Set();
  const source = String(text || '');
  const patterns = [
    /<script[^>]+src=["']([^"']+)["'][^>]*>/gi,
    /(?:import\s+(?:[^"']+?\s+from\s+)?|import\s*\()["']([^"']+)["']/g
  ];
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(source))) {
      try {
        const u = new URL(match[1], baseUrl);
        if (u.origin === baseUrl.origin && u.protocol === 'https:' && isPublicHostname(u.hostname)) found.add(u.href);
      } catch {}
    }
  }
  return [...found];
}

async function readTextLimited(url) {
  const response = await fetch(url, {
    redirect: 'follow',
    headers: { 'User-Agent': 'LIMPO-Authorized-Auth-Audit/2.1' }
  });
  if (!response.ok) throw new Error(`target_http_${response.status}`);
  const finalUrl = new URL(response.url || url.href || String(url));
  if (!isPublicHostname(finalUrl.hostname) || finalUrl.protocol !== 'https:') throw new Error('unsafe_redirect');
  const length = Number(response.headers.get('content-length') || 0);
  if (length > 1_500_000) throw new Error('target_too_large');
  return { text: (await response.text()).slice(0, 1_500_000), finalUrl };
}

function extractCustomAuthHints(text, baseUrl) {
  const s = String(text || '');
  const hints = [];
  const endpoints = new Set();
  const fields = new Set();

  const endpointPatterns = [
    /fetch\s*\(\s*["'`]([^"'`]*(?:login|signin|sign-in|auth|session|token)[^"'`]*)["'`]/gi,
    /axios\.(?:post|put)\s*\(\s*["'`]([^"'`]*(?:login|signin|sign-in|auth|session|token)[^"'`]*)["'`]/gi,
    /(?:url|endpoint|baseURL)\s*[:=]\s*["'`]([^"'`]*(?:login|signin|sign-in|auth|session|token)[^"'`]*)["'`]/gi,
    /["'`]((?:\/|https:\/\/)[^"'`]{0,140}\/(?:api\/)?(?:auth\/)?(?:login|signin|sign-in|session|token)[^"'`]*)["'`]/gi
  ];

  for (const pattern of endpointPatterns) {
    let m;
    while ((m = pattern.exec(s)) && endpoints.size < 12) {
      try {
        const u = new URL(m[1], baseUrl);
        if (u.protocol === 'https:' && isPublicHostname(u.hostname)) endpoints.add(u.href);
      } catch {
        if (String(m[1]).startsWith('/')) endpoints.add(String(m[1]));
      }
    }
  }

  const fieldPatterns = [
    /\b(email|username|user|login|identifier)\b\s*[:=]/gi,
    /\b(password|senha|pass)\b\s*[:=]/gi
  ];
  for (const pattern of fieldPatterns) {
    let m;
    while ((m = pattern.exec(s)) && fields.size < 8) fields.add(String(m[1]).toLowerCase());
  }

  const hasCredentialFields = [...fields].some(x => ['email','username','user','login','identifier'].includes(x)) &&
    [...fields].some(x => ['password','senha','pass'].includes(x));
  const hasSubmitCode = /fetch\s*\(|axios\.(?:post|put)\s*\(|XMLHttpRequest|graphql|mutation\s+[A-Za-z0-9_]*(?:login|signin|auth)/i.test(s);

  if (endpoints.size) hints.push({ provider: 'custom-api', evidence: `Fluxo de login customizado; endpoint(s): ${[...endpoints].slice(0, 3).join(', ')}` });
  if (hasCredentialFields) hints.push({ provider: 'custom-api', evidence: `Campos de credencial detectados: ${[...fields].join(', ')}` });
  if (hasSubmitCode) hints.push({ provider: 'custom-api', evidence: 'Código cliente envia autenticação por API/GraphQL/XHR' });

  return { hints, endpoints: [...endpoints].slice(0, 8), fields: [...fields].slice(0, 8) };
}

function providerSignals(text, baseUrl) {
  const s = String(text || '');
  const low = s.toLowerCase();
  const hits = [];
  const add = (provider, evidence) => hits.push({ provider, evidence });

  if (/firebase\/auth|firebase-auth|identitytoolkit\.googleapis\.com|authdomain\s*[:=]|initializeapp\s*\(/i.test(s)) add('firebase', 'Firebase Auth / Identity Toolkit');
  if (/\.supabase\.co|supabase-js|createclient\s*\(/i.test(s) && /supabase/i.test(s)) add('supabase', 'Supabase client/auth');
  if (/auth0\.com|@auth0|createauth0client|auth0client/i.test(s)) add('auth0', 'Auth0 SDK/domain');
  if (/cognito-idp|amazoncognito|cognitouserpool|aws-amplify\/auth|userpoolid/i.test(s)) add('cognito', 'Amazon Cognito / Amplify Auth');
  if (/clerk\.com|@clerk|clerkpublishablekey|clerk-js/i.test(s)) add('clerk', 'Clerk SDK/domain');
  if (/accounts\.google\.com\/gsi|google\.accounts\.id|google-signin-client_id/i.test(s)) add('google-identity', 'Google Identity Services');
  if (/next-auth|nextauth|\/api\/auth\/(signin|session)|authjs/i.test(s)) add('authjs', 'Auth.js / NextAuth');
  if (/wordpress|wp-login\.php|wp-json/i.test(low)) add('wordpress', 'WordPress');

  const custom = extractCustomAuthHints(s, baseUrl);
  hits.push(...custom.hints);
  return { hits, custom };
}

function chooseProvider(allSignals, firebaseConfig) {
  if (firebaseConfig?.apiKey) return { provider: 'firebase', confidence: 'high', adapter: 'firebase-password' };
  const order = ['supabase', 'auth0', 'cognito', 'clerk', 'google-identity', 'authjs', 'wordpress'];
  for (const provider of order) {
    if (allSignals.some(x => x.provider === provider)) return { provider, confidence: 'medium', adapter: 'detection-only' };
  }
  const customCount = allSignals.filter(x => x.provider === 'custom-api').length;
  if (customCount >= 2) return { provider: 'custom-api', confidence: 'medium', adapter: 'detection-only' };
  if (customCount === 1) return { provider: 'custom-api', confidence: 'low', adapter: 'detection-only' };
  return { provider: 'custom-or-unknown', confidence: 'low', adapter: 'detection-only' };
}

async function discoverAuth(target) {
  const first = await readTextLimited(target);
  let firebaseConfig = extractFirebaseConfig(first.text);
  const firstSignals = providerSignals(first.text, first.finalUrl);
  const signals = [...firstSignals.hits];
  const customEndpoints = new Set(firstSignals.custom.endpoints);
  const customFields = new Set(firstSignals.custom.fields);
  const queue = extractModuleUrls(first.text, first.finalUrl).slice(0, 12).map(href => ({ href, depth: 0 }));
  const visited = new Set();

  while (queue.length && visited.size < 20) {
    const item = queue.shift();
    if (!item || visited.has(item.href)) continue;
    visited.add(item.href);
    try {
      const moduleUrl = new URL(item.href);
      if (moduleUrl.origin !== first.finalUrl.origin || !isPublicHostname(moduleUrl.hostname)) continue;
      const loaded = await readTextLimited(moduleUrl);
      const cfg = extractFirebaseConfig(loaded.text);
      if (!firebaseConfig.apiKey && cfg.apiKey) firebaseConfig = cfg;
      const found = providerSignals(loaded.text, loaded.finalUrl);
      signals.push(...found.hits);
      found.custom.endpoints.forEach(x => customEndpoints.add(x));
      found.custom.fields.forEach(x => customFields.add(x));
      if (item.depth < 2) {
        for (const href of extractModuleUrls(loaded.text, loaded.finalUrl).slice(0, 10)) {
          if (!visited.has(href)) queue.push({ href, depth: item.depth + 1 });
        }
      }
    } catch {}
  }

  const chosen = chooseProvider(signals, firebaseConfig);
  const evidence = [...new Set(signals
    .filter(x => chosen.provider === 'custom-or-unknown' || x.provider === chosen.provider)
    .map(x => x.evidence))].slice(0, 8);

  return {
    ...chosen,
    evidence,
    firebaseConfig,
    customAuth: {
      endpoints: [...customEndpoints].slice(0, 8),
      fields: [...customFields].slice(0, 8)
    },
    scannedScripts: visited.size,
    finalOrigin: first.finalUrl.origin
  };
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
    const discovery = await discoverAuth(checked.target);
    return json({
      ok: true,
      provider: discovery.provider,
      confidence: discovery.confidence,
      adapter: discovery.adapter,
      evidence: discovery.evidence,
      customAuth: discovery.customAuth,
      scannedScripts: discovery.scannedScripts,
      finalOrigin: discovery.finalOrigin,
      latencyMs: Date.now() - started
    });
  } catch (error) {
    return json({ ok: false, error: 'target_unreachable', classification: 'indeterminate', detail: String(error?.message || 'fetch_failed'), latencyMs: Date.now() - started }, 502);
  }
}

async function handleUrlAuthTest(request) {
  let body = {};
  try { body = await request.json(); } catch {}

  const checked = validateAuthorizedTarget(body?.url, body?.authorized === true);
  if (checked.error) return checked.error;
  const target = checked.target;
  const email = String(body?.email || '').trim();
  const password = String(body?.password || '');

  if (!email || !password || email.length > 254 || password.length > 256) {
    return json({ ok: false, error: 'invalid_input', classification: 'indeterminate' }, 400);
  }

  const started = Date.now();
  let discovery;
  try {
    discovery = await discoverAuth(target);
  } catch (error) {
    return json({ ok: false, error: 'target_unreachable', classification: 'indeterminate', detail: String(error?.message || 'fetch_failed') }, 502);
  }

  if (discovery.provider !== 'firebase' || !discovery.firebaseConfig?.apiKey) {
    return json({
      ok: false,
      error: 'adapter_not_available',
      classification: 'indeterminate',
      provider: discovery.provider,
      confidence: discovery.confidence,
      authType: discovery.adapter,
      evidence: discovery.evidence,
      customAuth: discovery.customAuth,
      latencyMs: Date.now() - started,
      message: discovery.provider === 'custom-api'
        ? 'Fluxo de autenticação customizado detectado, mas o LIMPO ainda não executa credenciais automaticamente nesse endpoint.'
        : 'Provedor detectado, mas o LIMPO ainda não possui adaptador ativo para testar credencial/rate limit deste fluxo.'
    }, 422);
  }

  const config = discovery.firebaseConfig;
  const endpoint = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(config.apiKey)}`;
  let authResponse;
  let data;
  try {
    authResponse = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, returnSecureToken: true })
    });
    data = await authResponse.json().catch(() => ({}));
  } catch {
    return json({ ok: false, authenticated: false, classification: 'indeterminate', provider: 'firebase', authType: 'firebase-password', error: 'provider_unreachable', latencyMs: Date.now() - started }, 502);
  }

  const latencyMs = Date.now() - started;
  if (authResponse.ok && data?.localId) {
    return json({
      ok: true,
      authenticated: true,
      classification: 'authenticated',
      provider: 'firebase',
      authType: 'firebase-password',
      projectId: config.projectId || null,
      authDomain: config.authDomain || null,
      providerHttpStatus: authResponse.status,
      latencyMs
    });
  }

  const firebaseCode = String(data?.error?.message || 'AUTH_FAILED');
  const classification = classifyFirebaseError(firebaseCode);
  const status = classification === 'blocked' ? 429 : classification === 'invalid' ? 401 : 422;
  const retryAfter = authResponse.headers.get('retry-after');

  return json({
    ok: false,
    authenticated: false,
    classification,
    provider: 'firebase',
    authType: 'firebase-password',
    projectId: config.projectId || null,
    authDomain: config.authDomain || null,
    error: classification === 'blocked' ? 'rate_limited' : classification === 'invalid' ? 'invalid_credentials' : 'indeterminate_auth_result',
    providerCode: firebaseCode,
    providerHttpStatus: authResponse.status,
    retryAfter: retryAfter || null,
    latencyMs
  }, status);
}

export class LoginLimiter {
  constructor(ctx) {
    this.ctx = ctx;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const mode = url.pathname.includes('/auth/') || url.pathname.includes('/lab/vulnerable/') ? 'password' : 'pin';
    const stateKey = `state:${mode}`;
    const now = Date.now();
    const stored = await this.ctx.storage.get(stateKey);
    const state = stored || { hits: [], lockedUntil: 0, total: 0 };

    if (state.lockedUntil > now) {
      const retryAfterMs = state.lockedUntil - now;
      return json({ ok: false, error: 'locked', retryAfterMs, totalAttempts: state.total }, 429, {
        'Retry-After': String(Math.ceil(retryAfterMs / 1000))
      });
    }

    state.hits = state.hits.filter(t => now - t < WINDOW_MS);
    if (state.hits.length >= MAX_ATTEMPTS) {
      state.lockedUntil = now + LOCK_MS;
      state.hits = [];
      await this.ctx.storage.put(stateKey, state);
      return json({ ok: false, error: 'rate_limited', retryAfterMs: LOCK_MS, totalAttempts: state.total }, 429, {
        'Retry-After': String(Math.ceil(LOCK_MS / 1000))
      });
    }

    let body = {};
    try { body = await request.json(); } catch {}
    state.hits.push(now);
    state.total++;

    let valid = false;
    let successMessage = '';

    if (mode === 'password') {
      const username = String(body?.username ?? '').trim().toLowerCase();
      const password = String(body?.password ?? '');
      const passwordHash = await sha256(password);
      valid = username === LAB_USER && passwordHash === LAB_PASSWORD_SHA256;
      successMessage = 'Login fictício autorizado';
    } else {
      const pin = String(body?.pin ?? '').replace(/\D/g, '').slice(0, 6);
      valid = pin === LAB_PIN;
      successMessage = 'PIN fictício correto';
    }

    if (valid) {
      state.hits = [];
      state.lockedUntil = 0;
      await this.ctx.storage.put(stateKey, state);
      return json({ ok: true, message: successMessage, totalAttempts: state.total });
    }

    await this.ctx.storage.put(stateKey, state);
    return json({
      ok: false,
      error: mode === 'password' ? 'invalid_credentials' : 'invalid_pin',
      remaining: Math.max(0, MAX_ATTEMPTS - state.hits.length),
      totalAttempts: state.total
    }, 401);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    if (url.pathname === '/url-provider-detect') {
      if (request.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);
      return handleProviderDetect(request);
    }

    if (url.pathname === '/url-auth-test') {
      if (request.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);
      return handleUrlAuthTest(request);
    }

    const isSecureLogin = url.pathname === '/auth/login';
    const isVulnerableLogin = url.pathname === '/lab/vulnerable/login';
    const isPin = url.pathname === '/login' || url.pathname === '/api/login';
    const isApi = isSecureLogin || isVulnerableLogin || isPin;
    if (!isApi) return env.ASSETS.fetch(request);
    if (request.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);

    let body = {};
    if (isVulnerableLogin) {
      try { body = await request.clone().json(); } catch {}
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'lab-client';
    const clientKey = isVulnerableLogin
      ? `vuln:${String(body?.labClientId || 'client-a').slice(0, 64)}`
      : `secure:${ip}`;

    const id = env.LOGIN_LIMITER.idFromName(clientKey);
    const stub = env.LOGIN_LIMITER.get(id);
    return stub.fetch(request);
  }
};
