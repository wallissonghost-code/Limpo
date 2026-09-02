// Endpoint educacional isolado para o laboratório Limpo.
// Usa apenas um PIN fictício e não autentica contas reais.

const attempts = new Map();
const WINDOW_MS = 10_000;
const MAX_ATTEMPTS = 5;
const LOCK_MS = 15_000;
const LAB_PIN = '042069';

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ ok:false, error:'method_not_allowed' });

  const now = Date.now();
  const forwarded = req.headers['x-forwarded-for'];
  const client = (Array.isArray(forwarded) ? forwarded[0] : forwarded || 'lab-client').split(',')[0].trim();
  let state = attempts.get(client) || { hits: [], lockedUntil: 0, total: 0 };

  if (state.lockedUntil > now) {
    const retryAfterMs = state.lockedUntil - now;
    res.setHeader('Retry-After', Math.ceil(retryAfterMs / 1000));
    return res.status(429).json({ ok:false, error:'locked', retryAfterMs, totalAttempts:state.total });
  }

  state.hits = state.hits.filter(t => now - t < WINDOW_MS);
  if (state.hits.length >= MAX_ATTEMPTS) {
    state.lockedUntil = now + LOCK_MS;
    state.hits = [];
    attempts.set(client, state);
    res.setHeader('Retry-After', Math.ceil(LOCK_MS / 1000));
    return res.status(429).json({ ok:false, error:'rate_limited', retryAfterMs:LOCK_MS, totalAttempts:state.total });
  }

  const pin = String(req.body?.pin ?? '').replace(/\D/g, '').slice(0, 6);
  state.hits.push(now);
  state.total++;
  attempts.set(client, state);

  if (pin === LAB_PIN) {
    state.hits = [];
    state.lockedUntil = 0;
    attempts.set(client, state);
    return res.status(200).json({ ok:true, message:'PIN fictício correto', totalAttempts:state.total });
  }

  return res.status(401).json({ ok:false, error:'invalid_pin', remaining:Math.max(0,MAX_ATTEMPTS-state.hits.length), totalAttempts:state.total });
}
