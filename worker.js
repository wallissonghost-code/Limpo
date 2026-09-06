const HTML_MAX_BYTES = 1_200_000;
const SCRIPT_SLICE_BYTES = 420_000;
const MAX_SCRIPTS = 10;
const MAX_TOTAL_SCRIPT_BYTES = 3_200_000;
const TIMEOUT_MS = 8_000;
const MAX_REDIRECTS = 5;

const PROVIDERS = {
  firebase: { name: 'Firebase Authentication' },
  supabase: { name: 'Supabase Auth' },
  auth0: { name: 'Auth0' },
  clerk: { name: 'Clerk' },
  cognito: { name: 'AWS Cognito' },
  keycloak: { name: 'Keycloak' },
  okta: { name: 'Okta' },
  entra: { name: 'Microsoft Entra / MSAL' },
  google: { name: 'Google Identity' },
  authjs: { name: 'Auth.js / NextAuth' }
};

const SIGNATURES = [
  // Firebase — strong network/runtime indicators
  ['firebase','strong',10,/identitytoolkit\.googleapis\.com/i,'Identity Toolkit endpoint'],
  ['firebase','strong',10,/securetoken\.googleapis\.com/i,'Secure Token endpoint'],
  ['firebase','strong',10,/firebaseinstallations\.googleapis\.com/i,'Firebase Installations endpoint'],
  ['firebase','strong',10,/googleapis\.com\/identitytoolkit/i,'Identity Toolkit API path'],
  ['firebase','strong',10,/accounts:(?:signInWithPassword|signUp|lookup|update)/i,'Firebase Auth REST action'],
  ['firebase','medium',6,/firebase\/auth|firebase-auth|@firebase\/auth/i,'Firebase Auth SDK'],
  ['firebase','medium',6,/signInWithEmailAndPassword|onAuthStateChanged|initializeAuth\s*\(|getAuth\s*\(/i,'Firebase Auth API'],
  ['firebase','medium',5,/authDomain\s*[:=]|firebaseConfig/i,'Firebase public config'],
  ['firebase','weak',3,/\.firebaseapp\.com|\.web\.app|\.firebaseio\.com|\.firebasedatabase\.app/i,'Firebase domain'],

  // Supabase
  ['supabase','strong',10,/\.supabase\.(?:co|in)\/auth\/v1(?:\/|\b)/i,'Supabase Auth endpoint'],
  ['supabase','strong',9,/\.supabase\.(?:co|in)\/rest\/v1(?:\/|\b)/i,'Supabase REST endpoint'],
  ['supabase','strong',9,/\.supabase\.(?:co|in)\/(?:realtime|storage)\/v1(?:\/|\b)/i,'Supabase service endpoint'],
  ['supabase','strong',10,/\/auth\/v1\/(?:token|authorize|signup|user)/i,'Supabase Auth API path'],
  ['supabase','medium',6,/@supabase\/supabase-js|supabase-js/i,'Supabase JS SDK'],
  ['supabase','medium',6,/signInWithPassword|signInWithOtp|supabase\.auth/i,'Supabase Auth API'],
  ['supabase','medium',5,/createClient\s*\([^)]*supabase/i,'Supabase client initialization'],
  ['supabase','weak',3,/\.supabase\.(?:co|in)/i,'Supabase project domain'],

  // Other providers
  ['auth0','strong',10,/[a-z0-9.-]+\.auth0\.com\/authorize/i,'Auth0 authorize endpoint'],
  ['auth0','medium',6,/@auth0\/|createAuth0Client|auth0-spa-js/i,'Auth0 SDK'],
  ['auth0','weak',3,/\.auth0\.com/i,'Auth0 domain'],

  ['clerk','strong',10,/\.clerk\.accounts|accounts\.clerk\.com/i,'Clerk account endpoint'],
  ['clerk','medium',6,/@clerk\/|ClerkProvider|clerk-js/i,'Clerk SDK'],
  ['clerk','weak',3,/clerk\.com/i,'Clerk domain'],

  ['cognito','strong',10,/cognito-idp\.[a-z0-9-]+\.amazonaws\.com/i,'Cognito IdP endpoint'],
  ['cognito','strong',9,/\.auth\.[a-z0-9-]+\.amazoncognito\.com/i,'Cognito hosted UI'],
  ['cognito','medium',6,/amazon-cognito-identity-js|CognitoUserPool/i,'Cognito SDK'],
  ['cognito','weak',3,/amazoncognito\.com/i,'Cognito domain'],

  ['keycloak','strong',10,/\/realms\/[^/]+\/protocol\/openid-connect\//i,'Keycloak OIDC endpoint'],
  ['keycloak','medium',6,/keycloak-js|new\s+Keycloak|keycloak\.init/i,'Keycloak SDK'],
  ['keycloak','weak',3,/\/realms\//i,'Keycloak realm path'],

  ['okta','strong',10,/\.okta\.com\/oauth2\/[^/]+\/v1\/(?:authorize|token)/i,'Okta OAuth endpoint'],
  ['okta','medium',6,/okta-auth-js|@okta\/|OktaAuth/i,'Okta SDK'],
  ['okta','weak',3,/\.okta\.com/i,'Okta domain'],

  ['entra','strong',10,/login\.microsoftonline\.com\/[a-z0-9-]+\/oauth2\/v2\.0/i,'Microsoft Entra OAuth endpoint'],
  ['entra','medium',6,/@azure\/msal|msal-browser|PublicClientApplication/i,'MSAL SDK'],
  ['entra','weak',3,/login\.microsoftonline\.com/i,'Microsoft login domain'],

  ['google','strong',10,/accounts\.google\.com\/gsi\//i,'Google Identity Services endpoint'],
  ['google','medium',6,/google\.accounts\.id|g_id_onload/i,'Google Identity API'],

  ['authjs','strong',9,/\/api\/auth\/(?:session|signin|callback|providers)/i,'Auth.js API route'],
  ['authjs','medium',6,/next-auth|@auth\/|SessionProvider/i,'Auth.js / NextAuth SDK']
];

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer'
    }
  });
}

function isBlockedHostname(hostname) {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h === '0.0.0.0' || h === '::1') return true;
  const ipv4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const p = ipv4.slice(1).map(Number);
    if (p.some(n => n > 255)) return true;
    return p[0] === 10 || p[0] === 127 || p[0] === 0 || p[0] >= 224 ||
      (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168);
  }
  return h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe8') || h.startsWith('fe9') || h.startsWith('fea') || h.startsWith('feb');
}

function parseTarget(raw) {
  let url;
  try { url = new URL(raw); } catch { throw new Error('URL inválida.'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Use apenas URLs HTTP ou HTTPS.');
  if (url.username || url.password) throw new Error('URL com credenciais não é permitida.');
  if (isBlockedHostname(url.hostname)) throw new Error('Endereço local, privado ou reservado não permitido.');
  return url;
}

async function fetchWithTimeout(url, options = {}, timeout = TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function fetchTarget(startUrl, extraHeaders = {}) {
  let current = startUrl;
  const redirectChain = [];
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const response = await fetchWithTimeout(current.toString(), {
      redirect: 'manual',
      headers: {
        'user-agent': 'AuthTechnologyDetector/3.0 (+public-signature-analysis)',
        'accept': 'text/html,application/xhtml+xml,text/plain,application/javascript,application/json,*/*;q=0.5',
        ...extraHeaders
      }
    });
    redirectChain.push({ url: current.toString(), status: response.status, location: response.headers.get('location') });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const loc = response.headers.get('location');
      if (!loc) return { response, finalUrl: current, redirectChain };
      current = parseTarget(new URL(loc, current).toString());
      continue;
    }
    return { response, finalUrl: current, redirectChain };
  }
  throw new Error('Redirecionamentos demais.');
}

async function readLimited(response, maxBytes) {
  const reader = response.body?.getReader();
  if (!reader) return { text: '', bytes: 0, truncated: false };
  const chunks = [];
  let total = 0;
  let truncated = false;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const remaining = maxBytes - total;
    if (remaining <= 0) { truncated = true; break; }
    if (value.byteLength > remaining) {
      chunks.push(value.slice(0, remaining));
      total += remaining;
      truncated = true;
      break;
    }
    chunks.push(value);
    total += value.byteLength;
  }
  try { await reader.cancel(); } catch {}
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { merged.set(chunk, offset); offset += chunk.byteLength; }
  return { text: new TextDecoder().decode(merged), bytes: total, truncated };
}

function extractAssetUrls(html, baseUrl) {
  const found = new Set();
  const patterns = [
    /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi,
    /<link\b[^>]*\bhref\s*=\s*["']([^"']+\.m?js(?:\?[^"']*)?)["'][^>]*>/gi,
    /["']([^"']+\.(?:m?js)(?:\?[^"']*)?)["']/gi
  ];
  for (const regex of patterns) {
    let m;
    while ((m = regex.exec(html)) && found.size < 30) {
      try {
        const u = new URL(m[1], baseUrl);
        if (['http:', 'https:'].includes(u.protocol) && !isBlockedHostname(u.hostname)) found.add(u.toString());
      } catch {}
    }
  }
  return [...found];
}

function extractEndpointLikeStrings(text, baseUrl) {
  const out = new Set();
  const absolute = /https?:\\?\/\\?\/[a-z0-9._~:/?#\[\]@!$&'()*+,;=%\\-]+/gi;
  let m;
  while ((m = absolute.exec(text)) && out.size < 250) {
    const raw = m[0].replace(/\\\//g, '/').replace(/\\u002F/gi, '/');
    try { out.add(new URL(raw).toString()); } catch {}
  }
  const paths = /["'`](\/(?:api\/auth|auth\/v1|rest\/v1|realtime\/v1|storage\/v1|realms\/|v1\/accounts:)[^"'`\s<]*)/gi;
  while ((m = paths.exec(text)) && out.size < 300) {
    try { out.add(new URL(m[1], baseUrl).toString()); } catch {}
  }
  return [...out];
}

function createEvidenceStore() {
  const map = new Map();
  for (const id of Object.keys(PROVIDERS)) map.set(id, []);
  return map;
}

function addEvidence(store, provider, strength, weight, label, source, detail = '') {
  if (!store.has(provider)) return;
  const list = store.get(provider);
  const key = `${strength}|${label}|${detail}`;
  if (list.some(e => e.key === key)) return;
  list.push({ key, strength, weight, label, source, detail: detail ? detail.slice(0, 220) : '' });
}

function scanText(store, text, source) {
  if (!text) return;
  for (const [provider, strength, weight, regex, label] of SIGNATURES) {
    const match = text.match(regex);
    if (match) addEvidence(store, provider, strength, weight, label, source, match[0]);
  }
}

function scanUrl(store, url, source) {
  scanText(store, url, source);
}

async function inspectScript(scriptUrl, store) {
  const url = parseTarget(scriptUrl);
  let totalBytes = 0;
  let partial = false;
  const sources = [];

  // Head slice
  let response;
  try {
    response = await fetchWithTimeout(url.toString(), {
      redirect: 'manual',
      headers: {
        'user-agent': 'AuthTechnologyDetector/3.0 (+public-signature-analysis)',
        'accept': 'application/javascript,text/javascript,*/*;q=0.5',
        'range': `bytes=0-${SCRIPT_SLICE_BYTES - 1}`
      }
    }, 6_000);
  } catch {
    return { url: url.toString(), bytes: 0, partial: true, status: 0, sources: ['fetch-failed'] };
  }

  if ([301,302,303,307,308].includes(response.status)) {
    const loc = response.headers.get('location');
    if (loc) {
      try { return await inspectScript(new URL(loc, url).toString(), store); } catch {}
    }
  }

  const head = await readLimited(response, SCRIPT_SLICE_BYTES);
  totalBytes += head.bytes;
  partial = head.truncated || response.status === 206;
  scanText(store, head.text, `bundle:${url.pathname}:head`);
  sources.push(response.status === 206 ? 'range-head' : 'head');

  const contentLength = Number(response.headers.get('content-length') || 0);
  const contentRange = response.headers.get('content-range') || '';
  const rangeTotal = Number((contentRange.match(/\/(\d+)$/) || [])[1] || 0);
  const knownTotal = rangeTotal || contentLength;

  // For large assets, sample the tail as well. This improves coverage without downloading multi-MB bundles in full.
  if (knownTotal > SCRIPT_SLICE_BYTES * 1.5) {
    try {
      const tailResponse = await fetchWithTimeout(url.toString(), {
        redirect: 'manual',
        headers: {
          'user-agent': 'AuthTechnologyDetector/3.0 (+public-signature-analysis)',
          'accept': 'application/javascript,text/javascript,*/*;q=0.5',
          'range': `bytes=-${SCRIPT_SLICE_BYTES}`
        }
      }, 6_000);
      const tail = await readLimited(tailResponse, SCRIPT_SLICE_BYTES);
      totalBytes += tail.bytes;
      scanText(store, tail.text, `bundle:${url.pathname}:tail`);
      sources.push('range-tail');
      partial = true;
    } catch {
      sources.push('tail-failed');
    }
  }

  return { url: url.toString(), bytes: totalBytes, partial, status: response.status, sources };
}

async function probeFirebaseRuntime(origin, store) {
  const results = [];
  for (const path of ['/__/firebase/init.json', '/__/firebase/init.js']) {
    const url = new URL(path, origin);
    try {
      const response = await fetchWithTimeout(url.toString(), {
        redirect: 'manual',
        headers: { 'user-agent': 'AuthTechnologyDetector/3.0 (+public-signature-analysis)', 'accept': 'application/json,text/javascript,text/plain,*/*;q=0.5' }
      }, 4_000);
      const contentType = response.headers.get('content-type') || '';
      const body = await readLimited(response, 120_000);
      const looksLikeFirebase = response.ok && (/firebase/i.test(body.text) || /apiKey|authDomain|projectId/.test(body.text));
      if (looksLikeFirebase) {
        addEvidence(store, 'firebase', 'strong', 10, 'Firebase runtime config', `probe:${path}`, path);
        if (/apiKey\s*[":=]/i.test(body.text)) addEvidence(store, 'firebase', 'medium', 6, 'Firebase apiKey in runtime config', `probe:${path}`, 'apiKey');
        if (/authDomain\s*[":=]/i.test(body.text)) addEvidence(store, 'firebase', 'medium', 6, 'Firebase authDomain in runtime config', `probe:${path}`, 'authDomain');
      }
      results.push({ path, status: response.status, contentType, matched: looksLikeFirebase });
    } catch {
      results.push({ path, status: 0, matched: false });
    }
  }
  return results;
}

function summarize(store) {
  const ranked = [...store.entries()].map(([id, evidence]) => {
    const score = evidence.reduce((sum, e) => sum + e.weight, 0);
    const strong = evidence.filter(e => e.strength === 'strong').length;
    const medium = evidence.filter(e => e.strength === 'medium').length;
    const weak = evidence.filter(e => e.strength === 'weak').length;
    // Weak-only matches never confirm a provider.
    const detected = strong >= 1 || (score >= 12 && medium >= 2) || (score >= 16 && medium >= 1 && weak >= 1);
    let confidence = 0;
    if (detected) {
      confidence = Math.min(99, 58 + strong * 18 + medium * 8 + weak * 3 + Math.min(10, Math.floor(score / 8)));
    } else if (score > 0) {
      confidence = Math.min(59, 20 + medium * 12 + weak * 5 + Math.floor(score / 5));
    }
    return { id, provider: PROVIDERS[id].name, score, strong, medium, weak, detected, confidence, evidence };
  }).filter(x => x.score > 0).sort((a, b) => (Number(b.detected) - Number(a.detected)) || b.score - a.score);

  const best = ranked[0];
  if (!best || !best.detected) {
    return {
      detected: false,
      provider: 'Não identificado com segurança',
      confidence: best?.confidence || 0,
      score: best?.score || 0,
      evidence: best?.evidence || [],
      alternatives: ranked.slice(0, 4).map(x => ({ provider: x.provider, score: x.score, confidence: x.confidence, detected: x.detected })),
      note: best
        ? 'Há indícios, mas eles não atingem o nível necessário para confirmar um provedor. Ausência de evidência pública não significa ausência da tecnologia.'
        : 'Nenhuma evidência pública suficiente foi encontrada. O provedor pode estar oculto em backend próprio, proxy ou bundle não observável.'
    };
  }

  return {
    detected: true,
    provider: best.provider,
    providerId: best.id,
    confidence: best.confidence,
    score: best.score,
    evidence: best.evidence.sort((a,b) => b.weight - a.weight),
    alternatives: ranked.slice(1, 4).map(x => ({ provider: x.provider, score: x.score, confidence: x.confidence, detected: x.detected })),
    note: best.strong > 0
      ? 'Provedor sustentado por pelo menos uma evidência forte observável publicamente.'
      : 'Provedor inferido por combinação consistente de evidências médias. O resultado continua probabilístico.'
  };
}

async function analyze(request) {
  if (request.method !== 'POST') return json({ error: 'Use POST.' }, 405);
  try {
    const data = await request.json().catch(() => ({}));
    if (!data.url) return json({ error: 'Informe uma URL.' }, 400);
    const target = parseTarget(String(data.url).trim());
    const store = createEvidenceStore();

    const { response, finalUrl, redirectChain } = await fetchTarget(target);
    const type = (response.headers.get('content-type') || '').toLowerCase();
    if (type && !type.includes('text/html') && !type.includes('text/plain') && !type.includes('javascript') && !type.includes('json')) {
      return json({ error: `Conteúdo não analisável: ${type}` }, 415);
    }

    const htmlRead = await readLimited(response, HTML_MAX_BYTES);
    const html = htmlRead.text;
    const selectedHeaders = {
      server: response.headers.get('server'),
      'www-authenticate': response.headers.get('www-authenticate'),
      'x-powered-by': response.headers.get('x-powered-by'),
      location: response.headers.get('location'),
      'set-cookie': response.headers.get('set-cookie')
    };

    scanText(store, html, 'html');
    scanText(store, JSON.stringify(selectedHeaders), 'headers');
    scanUrl(store, finalUrl.toString(), 'final-url');
    for (const step of redirectChain) {
      scanUrl(store, step.url, 'redirect');
      if (step.location) scanText(store, step.location, 'redirect-location');
    }

    const endpointLikes = extractEndpointLikeStrings(html, finalUrl);
    for (const ep of endpointLikes) scanUrl(store, ep, 'html-endpoint');

    const discoveredScripts = extractAssetUrls(html, finalUrl);
    const scriptResults = [];
    let scriptBytes = 0;
    for (const scriptUrl of discoveredScripts.slice(0, MAX_SCRIPTS)) {
      if (scriptBytes >= MAX_TOTAL_SCRIPT_BYTES) break;
      scanUrl(store, scriptUrl, 'script-url');
      const result = await inspectScript(scriptUrl, store);
      scriptResults.push(result);
      scriptBytes += result.bytes;
    }

    const firebaseProbes = await probeFirebaseRuntime(finalUrl.origin, store);
    const result = summarize(store);

    const partialScripts = scriptResults.filter(x => x.partial).length;
    return json({
      ok: true,
      requestedUrl: target.toString(),
      finalUrl: finalUrl.toString(),
      httpStatus: response.status,
      analyzedBytes: htmlRead.bytes + scriptBytes,
      coverage: {
        htmlBytes: htmlRead.bytes,
        htmlTruncated: htmlRead.truncated,
        scriptsDiscovered: discoveredScripts.length,
        scriptsAnalyzed: scriptResults.length,
        partialScripts,
        scriptBytes,
        endpointCandidates: endpointLikes.length,
        redirects: redirectChain.length - 1,
        firebaseRuntimeProbes: firebaseProbes
      },
      ...result
    });
  } catch (error) {
    const message = error?.name === 'AbortError' ? 'A análise excedeu o tempo limite.' : (error?.message || 'Falha ao analisar a URL.');
    return json({ error: message }, 400);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/analyze') return analyze(request);
    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response('Auth Detector', { status: 200 });
  }
};
