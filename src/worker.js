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

export class LoginLimiter {
  constructor(ctx) {
    this.ctx = ctx;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const mode = url.pathname === '/auth/login' ? 'password' : 'pin';
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

    const isApi = url.pathname === '/login' || url.pathname === '/api/login' || url.pathname === '/auth/login';
    if (!isApi) return env.ASSETS.fetch(request);
    if (request.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);

    const client = request.headers.get('CF-Connecting-IP') || 'lab-client';
    const id = env.LOGIN_LIMITER.idFromName(client);
    const stub = env.LOGIN_LIMITER.get(id);
    return stub.fetch(request);
  }
};
