import baseWorker, { LoginLimiter } from './worker.js';
import { detectAuthProviders } from './auth-detector.js';

export { LoginLimiter };

const headers = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Cache-Control': 'no-store',
  'Content-Type': 'application/json; charset=utf-8'
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers });
}

function normalizeTarget(raw) {
  try {
    const u = new URL(String(raw || '').trim());
    if (u.protocol !== 'https:' || u.username || u.password || (u.port && u.port !== '443')) return null;
    return u;
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

async function handleProviderDetect(request) {
  let body = {};
  try { body = await request.json(); } catch {}
  if (body?.authorized !== true) return json({ ok:false, error:'authorization_required' }, 400);
  const target = normalizeTarget(body?.url);
  if (!target || !isPublicHostname(target.hostname)) return json({ ok:false, error:'target_not_allowed' }, 403);

  const started = Date.now();
  try {
    const result = await detectAuthProviders(target);
    return json({
      ok:true,
      ...result,
      adapter: result.provider === 'firebase' ? 'firebase-password' : 'detection-only',
      evidence: result.detections?.[0]?.evidence || [],
      latencyMs: Date.now() - started,
      limitations: {
        browserStorage: 'localStorage/sessionStorage de outro domínio não podem ser lidos pelo LIMPO por Same-Origin Policy; apenas referências encontradas em HTML/JS público são reportadas.',
        jwt: 'JWTs não são coletados de sessões privadas; somente nomes de claims/sinais expostos legitimamente em conteúdo público são analisados.'
      }
    });
  } catch (error) {
    return json({ ok:false, error:'target_unreachable', detail:String(error?.message || 'fetch_failed'), latencyMs:Date.now()-started }, 502);
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/url-provider-detect') {
      if (request.method === 'OPTIONS') return new Response(null, { status:204, headers });
      if (request.method !== 'POST') return json({ ok:false, error:'method_not_allowed' }, 405);
      return handleProviderDetect(request);
    }
    return baseWorker.fetch(request, env, ctx);
  }
};
