import legacyWorker, { LoginLimiter } from './worker.js';
import { detectAuthProviders } from './auth-detector.js';
import { resolveAdapter } from './adapters/index.js';

export { LoginLimiter };

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Cache-Control': 'no-store',
  'Content-Type': 'application/json; charset=utf-8'
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers:cors });
}

function normalizePublicTarget(raw) {
  try {
    const url = new URL(String(raw || '').trim());
    if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) return null;
    const host = url.hostname.toLowerCase().replace(/\.$/, '');
    if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return null;
    if (host === '0.0.0.0' || host === '::1' || host === '[::1]' || /^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host) || /^169\.254\./.test(host)) return null;
    const m = host.match(/^172\.(\d+)\./);
    if (m && Number(m[1]) >= 16 && Number(m[1]) <= 31) return null;
    return url;
  } catch { return null; }
}

function summarize(discovery) {
  const resolved = resolveAdapter(discovery);
  const diagnostics = discovery?.diagnostics || {};
  return {
    provider:discovery?.provider || 'custom-or-unknown',
    confidence:discovery?.confidence || 'low',
    type:discovery?.type || 'authentication',
    detected:true,
    adapter:resolved.adapter || 'detection-only',
    testAvailable:resolved.testAvailable === true,
    unavailableReason:resolved.unavailableReason || null,
    detections:discovery?.detections || [],
    evidence:discovery?.detections?.[0]?.evidence || [],
    endpoints:discovery?.endpoints || [],
    externalOrigins:discovery?.externalOrigins || [],
    scannedScripts:discovery?.scannedScripts || 0,
    finalOrigin:discovery?.finalOrigin || null,
    diagnostics:{
      initialStatus:diagnostics.initialStatus ?? null,
      initialContentType:diagnostics.initialContentType || '',
      initialBytes:diagnostics.initialBytes || 0,
      initialTruncated:diagnostics.initialTruncated === true,
      initialResources:diagnostics.initialResources || [],
      manifestProbes:diagnostics.manifestProbes || [],
      scannedResources:diagnostics.scannedResources || [],
      failedResources:diagnostics.failedResources || [],
      firebaseRuntimeProbe:diagnostics.firebaseRuntimeProbe || null
    }
  };
}

async function parseAuthorizedRequest(request, requireCredential = false) {
  let body;
  try { body = await request.clone().json(); }
  catch { return { error:json({ ok:false, error:'unprocessable_input', classification:'indeterminate', message:'Corpo JSON inválido.' }, 422) }; }

  if (body?.authorized !== true) return { error:json({ ok:false, error:'authorization_required', classification:'indeterminate' }, 400) };
  const target = normalizePublicTarget(body?.url);
  if (!target) return { error:json({ ok:false, error:'unprocessable_input', classification:'indeterminate', message:'Informe uma URL HTTPS pública válida.' }, 422) };

  if (requireCredential) {
    const email = String(body?.email || '').trim();
    const password = String(body?.password || '');
    if (!email || !password || email.length > 254 || password.length > 256) {
      return { error:json({ ok:false, error:'unprocessable_input', classification:'indeterminate', message:'E-mail ou senha ausente/inválido.' }, 422) };
    }
  }
  return { body, target };
}

async function detectOnly(request) {
  const checked = await parseAuthorizedRequest(request, false);
  if (checked.error) return checked.error;
  const started = Date.now();
  try {
    const discovery = await detectAuthProviders(checked.target);
    return json({
      ok:true,
      ...summarize(discovery),
      latencyMs:Date.now()-started,
      limitations:{
        browserStorage:'localStorage/sessionStorage de outro domínio não são lidos diretamente; somente nomes e referências expostos em conteúdo público são analisados.',
        jwt:'JWTs privados e tokens de sessão não são coletados; somente padrões e nomes de claims expostos legitimamente são analisados.'
      }
    }, 200);
  } catch (error) {
    return json({ ok:false, detected:false, error:'target_unreachable', classification:'indeterminate', detail:String(error?.message || 'fetch_failed'), latencyMs:Date.now()-started }, 502);
  }
}

async function authTest(request, env) {
  const checked = await parseAuthorizedRequest(request, true);
  if (checked.error) return checked.error;
  const started = Date.now();
  let discovery;
  try { discovery = await detectAuthProviders(checked.target); }
  catch (error) { return json({ ok:false, detected:false, error:'target_unreachable', classification:'indeterminate', detail:String(error?.message || 'fetch_failed'), latencyMs:Date.now()-started }, 502); }

  const summary = summarize(discovery);
  if (!summary.testAvailable) {
    return json({
      ok:true,
      ...summary,
      tested:false,
      authenticated:null,
      classification:'not_tested',
      authType:'detection-only',
      latencyMs:Date.now()-started,
      message:'Tecnologia detectada com sucesso, mas este provedor ainda não possui adaptador compatível para teste de credencial.'
    }, 200);
  }

  return legacyWorker.fetch(request, env);
}

async function withDiagnosticsModule(request, env) {
  const response = await legacyWorker.fetch(request, env);
  const type = String(response.headers.get('content-type') || '').toLowerCase();
  if (request.method !== 'GET' || !type.includes('text/html') || !response.ok) return response;
  const text = await response.text();
  if (text.includes('/url-diagnostics.js')) return new Response(text, response);
  const injected = text.replace('</body>', '<script src="/url-diagnostics.js"></script>\n</body>');
  const headers = new Headers(response.headers);
  headers.delete('content-length');
  return new Response(injected, { status:response.status, statusText:response.statusText, headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { status:204, headers:cors });
    if (url.pathname === '/url-provider-detect') {
      if (request.method !== 'POST') return json({ ok:false, error:'method_not_allowed' }, 405);
      return detectOnly(request);
    }
    if (url.pathname === '/url-auth-test') {
      if (request.method !== 'POST') return json({ ok:false, error:'method_not_allowed' }, 405);
      return authTest(request, env);
    }
    return withDiagnosticsModule(request, env);
  }
};
