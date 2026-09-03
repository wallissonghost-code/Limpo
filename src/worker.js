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

function isAuthorizedLabHost(hostname) {
  const host = String(hostname || '').toLowerCase();
  return host === 'wallissonghost-code.github.io' || host === 'limpo.wallissonghost.workers.dev';
}

function extractFirebaseConfig(text) {
  const source = String(text || '');
  const apiKey = source.match(/apiKey\s*:\s*["'`]([^"'`]+)["'`]/)?.[1] || '';
  const authDomain = source.match(/authDomain\s*:\s*["'`]([^"'`]+)["'`]/)?.[1] || '';
  const projectId = source.match(/projectId\s*:\s*["'`]([^"'`]+)["'`]/)?.[1] || '';
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
        if (u.origin === baseUrl.origin && /^https:$/.test(u.protocol)) found.add(u.href);
      } catch {}
    }
  }
  return [...found];
}

async function readTextLimited(url) {
  const response = await fetch(url, {
    redirect: 'follow',
    headers: { 'User-Agent': 'LIMPO-Authorized-Auth-Test/1.0' }
  });
  if (!response.ok) throw new Error(`target_http_${response.status}`);
  const length = Number(response.headers.get('content-length') || 0);
  if (length > 1_500_000) throw new Error('target_too_large');
  return (await response.text()).slice(0, 1_500_000);
}

async function discoverFirebase(target) {
  const first = await readTextLimited(target);
  let config = extractFirebaseConfig(first);
  if (config.apiKey) return config;

  const queue = extractModuleUrls(first, target).slice(0, 12).map(href => ({ href, depth: 0 }));
  const visited = new Set();

  while (queue.length && visited.size < 20) {
    const item = queue.shift();
    if (!item || visited.has(item.href)) continue;
    visited.add(item.href);
    try {
      const moduleUrl = new URL(item.href);
      if (!isAuthorizedLabHost(moduleUrl.hostname)) continue;
      const text = await readTextLimited(moduleUrl);
      config = extractFirebaseConfig(text);
      if (config.apiKey) return config;
      if (item.depth < 2) {
        for (const href of extractModuleUrls(text, moduleUrl).slice(0, 10)) {
          if (!visited.has(href)) queue.push({ href, depth: item.depth + 1 });
        }
      }
    } catch {}
  }

  return config;
}

async function handleUrlAuthTest(request) {
  let body = {};
  try { body = await request.json(); } catch {}

  const target = normalizeTarget(body?.url);
  const email = String(body?.email || '').trim();
  const password = String(body?.password || '');
  const authorized = body?.authorized === true;

  if (!authorized) return json({ ok: false, error: 'authorization_required' }, 400);
  if (!target || !isAuthorizedLabHost(target.hostname)) {
    return json({ ok: false, error: 'target_not_allowed', message: 'Este modo aceita apenas os domínios autorizados do laboratório.' }, 403);
  }
  if (!email || !password || email.length > 254 || password.length > 256) {
    return json({ ok: false, error: 'invalid_input' }, 400);
  }

  const started = Date.now();
  let config;
  try {
    config = await discoverFirebase(target);
  } catch (error) {
    return json({ ok: false, error: 'target_unreachable', detail: String(error?.message || 'fetch_failed') }, 502);
  }

  if (!config?.apiKey) {
    return json({ ok: false, error: 'firebase_not_detected', authType: 'unknown', latencyMs: Date.now() - started }, 422);
  }

  const endpoint = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(config.apiKey)}`;
  const authResponse = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, returnSecureToken: true })
  });
  const data = await authResponse.json().catch(() => ({}));
  const latencyMs = Date.now() - started;

  if (authResponse.ok && data?.localId) {
    return json({
      ok: true,
      authenticated: true,
      authType: 'firebase-password',
      projectId: config.projectId || null,
      authDomain: config.authDomain || null,
      email: data.email || email,
      latencyMs
    });
  }

  const firebaseCode = String(data?.error?.message || 'AUTH_FAILED');
  const rateLimited = /TOO_MANY|QUOTA|RATE/i.test(firebaseCode);
  return json({
    ok: false,
    authenticated: false,
    authType: 'firebase-password',
    projectId: config.projectId || null,
    authDomain: config.authDomain || null,
    error: rateLimited ? 'rate_limited' : 'invalid_credentials',
    providerCode: firebaseCode,
    latencyMs
  }, rateLimited ? 429 : 401);
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
