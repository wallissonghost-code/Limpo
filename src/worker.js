const WINDOW_MS = 10_000;
const MAX_ATTEMPTS = 5;
const LOCK_MS = 15_000;
const LAB_PIN = '042069';

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

export class LoginLimiter {
  constructor(ctx) {
    this.ctx = ctx;
  }

  async fetch(request) {
    const now = Date.now();
    const stored = await this.ctx.storage.get('state');
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
      await this.ctx.storage.put('state', state);
      return json({ ok: false, error: 'rate_limited', retryAfterMs: LOCK_MS, totalAttempts: state.total }, 429, {
        'Retry-After': String(Math.ceil(LOCK_MS / 1000))
      });
    }

    let body = {};
    try { body = await request.json(); } catch {}
    const pin = String(body?.pin ?? '').replace(/\D/g, '').slice(0, 6);

    state.hits.push(now);
    state.total++;

    if (pin === LAB_PIN) {
      state.hits = [];
      state.lockedUntil = 0;
      await this.ctx.storage.put('state', state);
      return json({ ok: true, message: 'PIN fictício correto', totalAttempts: state.total });
    }

    await this.ctx.storage.put('state', state);
    return json({
      ok: false,
      error: 'invalid_pin',
      remaining: Math.max(0, MAX_ATTEMPTS - state.hits.length),
      totalAttempts: state.total
    }, 401);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    if (url.pathname !== '/login' && url.pathname !== '/api/login') {
      return env.ASSETS.fetch(request);
    }

    if (request.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);

    const client = request.headers.get('CF-Connecting-IP') || 'lab-client';
    const id = env.LOGIN_LIMITER.idFromName(client);
    const stub = env.LOGIN_LIMITER.get(id);
    return stub.fetch(request);
  }
};
