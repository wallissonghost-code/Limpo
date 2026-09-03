const MAX_TEXT = 1_500_000;
const MAX_SCRIPTS = 28;

function isPublicHostname(hostname) {
  const host = String(hostname || '').trim().toLowerCase().replace(/\.$/, '');
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return false;
  if (host === '0.0.0.0' || host === '::1' || host === '[::1]') return false;
  if (/^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host) || /^169\.254\./.test(host)) return false;
  const m = host.match(/^172\.(\d+)\./);
  if (m && Number(m[1]) >= 16 && Number(m[1]) <= 31) return false;
  return true;
}

function safeUrl(raw, base) {
  try {
    const u = new URL(String(raw || ''), base);
    if (u.protocol !== 'https:' || !isPublicHostname(u.hostname)) return null;
    return u;
  } catch { return null; }
}

async function fetchText(url) {
  const r = await fetch(url, { redirect: 'follow', headers: { 'User-Agent': 'LIMPO-Auth-Detector/3.0' } });
  const finalUrl = safeUrl(r.url || url.href || String(url));
  if (!finalUrl) throw new Error('unsafe_redirect');
  const length = Number(r.headers.get('content-length') || 0);
  if (length > MAX_TEXT) throw new Error('target_too_large');
  const text = r.ok ? (await r.text()).slice(0, MAX_TEXT) : '';
  const headers = {};
  for (const name of ['server','via','x-powered-by','www-authenticate','set-cookie','location','cf-ray','x-vercel-id','x-amz-cf-id']) {
    const v = r.headers.get(name); if (v) headers[name] = v.slice(0, 1000);
  }
  return { ok: r.ok, status: r.status, text, finalUrl, headers };
}

function extractScripts(text, baseUrl) {
  const out = new Set();
  const patterns = [/<script[^>]+src=["']([^"']+)["'][^>]*>/gi,/(?:import\s+(?:[^"']+?\s+from\s+)?|import\s*\()["']([^"']+)["']/g];
  for (const p of patterns) {
    let m;
    while ((m = p.exec(String(text || ''))) && out.size < MAX_SCRIPTS) {
      const u = safeUrl(m[1], baseUrl);
      if (u && u.origin === baseUrl.origin) out.add(u.href);
    }
  }
  return [...out];
}

function extractEndpoints(text, baseUrl) {
  const s = String(text || '');
  const out = new Set();
  const pats = [
    /["'`]((?:https:\/\/|\/)[^"'`\s]{0,220}(?:\/auth|\/oauth|\/authorize|\/token|\/userinfo|\/login|\/signin|\/session|\/callback)[^"'`\s]{0,160})["'`]/gi,
    /(?:issuer|authorization_endpoint|token_endpoint|userinfo_endpoint|jwks_uri|baseURL|apiURL|apiUrl)\s*[:=]\s*["'`]([^"'`]+)["'`]/gi
  ];
  for (const p of pats) {
    let m;
    while ((m = p.exec(s)) && out.size < 30) {
      const u = safeUrl(m[1], baseUrl);
      if (u) out.add(u.href);
    }
  }
  return [...out];
}

function extractStorage(text) {
  const s = String(text || '');
  const local = new Set(), session = new Set(), cookies = new Set(), jwtClaims = new Set();
  for (const m of s.matchAll(/localStorage\.(?:setItem|getItem|removeItem)\s*\(\s*["'`]([^"'`]+)["'`]/gi)) local.add(m[1]);
  for (const m of s.matchAll(/sessionStorage\.(?:setItem|getItem|removeItem)\s*\(\s*["'`]([^"'`]+)["'`]/gi)) session.add(m[1]);
  for (const m of s.matchAll(/document\.cookie\s*=\s*["'`]([^=;"'`]{1,80})=/gi)) cookies.add(m[1]);
  for (const m of s.matchAll(/\b(sub|iss|aud|exp|iat|nbf|azp|scope|roles|role|permissions|email|preferred_username|tenant|tid)\b\s*[:=]/gi)) jwtClaims.add(m[1]);
  return { localStorage: [...local].slice(0,20), sessionStorage: [...session].slice(0,20), cookies: [...cookies].slice(0,20), jwtClaims: [...jwtClaims].slice(0,20) };
}

const PROVIDERS = [
  ['firebase', [/firebase\/auth|firebase-auth|identitytoolkit\.googleapis\.com/i, /authDomain\s*[:=]|initializeApp\s*\(/i]],
  ['supabase', [/\.supabase\.co|supabase-js|createClient\s*\(/i, /auth\.signInWithPassword|signInWithOtp/i]],
  ['auth0', [/auth0\.com|@auth0|createAuth0Client|Auth0Client/i, /\/authorize|\/oauth\/token/i]],
  ['clerk', [/clerk\.com|@clerk|clerkpublishablekey|clerk-js/i, /__clerk|clerkClient/i]],
  ['cognito', [/cognito-idp|amazoncognito|CognitoUserPool|aws-amplify\/auth|UserPoolId/i, /amazonaws\.com\/.+oauth2\/(authorize|token)/i]],
  ['okta', [/okta\.com|@okta|OktaAuth|okta-auth-js/i, /\/oauth2\/(?:default\/)?v1\/(authorize|token|userinfo)/i]],
  ['entra-id', [/login\.microsoftonline\.com|@azure\/msal|PublicClientApplication|ConfidentialClientApplication/i, /oauth2\/v2\.0\/(authorize|token)|openid-configuration/i]],
  ['keycloak', [/keycloak-js|new\s+Keycloak|\/realms\//i, /protocol\/openid-connect\/(auth|token|userinfo|certs)/i]],
  ['authjs', [/next-auth|nextauth|authjs|\/api\/auth\/(signin|session|callback)/i, /AUTH_SECRET|NEXTAUTH_URL/i]],
  ['passport', [/passport\.authenticate|passport-local|passport-jwt|passport-oauth2/i, /serializeUser|deserializeUser/i]],
  ['jwt-custom', [/Authorization\s*[:=]\s*["'`]Bearer|Bearer\s+\$\{|jwt\.sign|jwt\.verify|jsonwebtoken/i, /access[_-]?token|refresh[_-]?token/i]],
  ['oauth2', [/grant_type|client_id|redirect_uri|response_type|code_challenge|code_verifier/i, /\/oauth(?:2)?\/|\/authorize|\/token/i]],
  ['oidc', [/openid-configuration|openid-connect|id_token|nonce|jwks_uri|userinfo_endpoint/i, /scope[^\n]{0,80}openid/i]]
];

function scoreText(text, source, scoreMap, evidenceMap) {
  const s = String(text || '');
  for (const [provider, patterns] of PROVIDERS) {
    let hits = 0;
    for (const p of patterns) if (p.test(s)) hits++;
    if (!hits) continue;
    scoreMap.set(provider, (scoreMap.get(provider) || 0) + hits * 2);
    const arr = evidenceMap.get(provider) || [];
    if (arr.length < 8) arr.push(`${source}: ${hits} sinal(is)`);
    evidenceMap.set(provider, arr);
  }
}

function scoreEndpoint(endpoint, scoreMap, evidenceMap) {
  const e = String(endpoint || '').toLowerCase();
  const rules = [
    ['auth0', /auth0\.com/],['clerk', /clerk\./],['cognito', /amazoncognito|cognito-idp|amazonaws\.com\/.*oauth2/],['okta', /okta\.com/],['entra-id', /login\.microsoftonline\.com/],['keycloak', /\/realms\/|openid-connect/],['firebase', /identitytoolkit\.googleapis\.com/],['supabase', /\.supabase\.co/]
  ];
  for (const [p,re] of rules) if (re.test(e)) {
    scoreMap.set(p,(scoreMap.get(p)||0)+4);
    const arr=evidenceMap.get(p)||[]; if(arr.length<8) arr.push(`endpoint: ${endpoint}`); evidenceMap.set(p,arr);
  }
  if (/\/authorize|\/token|\/userinfo|openid-configuration/.test(e)) {
    for (const p of ['oauth2','oidc']) { scoreMap.set(p,(scoreMap.get(p)||0)+1); const arr=evidenceMap.get(p)||[]; if(arr.length<8) arr.push(`endpoint padrão: ${endpoint}`); evidenceMap.set(p,arr); }
  }
}

async function probeOidc(baseUrl, endpoints) {
  const candidates = new Set();
  candidates.add(new URL('/.well-known/openid-configuration', baseUrl).href);
  for (const ep of endpoints) {
    try {
      const u = new URL(ep);
      if (/\/realms\//i.test(u.pathname)) {
        const idx = u.pathname.indexOf('/protocol/');
        const root = idx > 0 ? u.pathname.slice(0, idx) : u.pathname;
        candidates.add(`${u.origin}${root}/.well-known/openid-configuration`);
      }
      if (/login\.microsoftonline\.com|okta\.com|auth0\.com|amazoncognito|keycloak/i.test(u.hostname + u.pathname)) candidates.add(new URL('/.well-known/openid-configuration', u.origin).href);
    } catch {}
  }
  const results=[];
  for (const href of [...candidates].slice(0,4)) {
    try {
      const u = safeUrl(href); if(!u) continue;
      const r = await fetch(u, { redirect:'follow', headers:{'User-Agent':'LIMPO-Auth-Detector/3.0'} });
      if(!r.ok) continue;
      const data = await r.json().catch(()=>null);
      if(data && (data.issuer || data.authorization_endpoint || data.token_endpoint)) results.push({url:u.href, issuer:data.issuer||null, authorization_endpoint:data.authorization_endpoint||null, token_endpoint:data.token_endpoint||null, userinfo_endpoint:data.userinfo_endpoint||null, jwks_uri:data.jwks_uri||null});
    } catch {}
  }
  return results;
}

export async function detectAuthProviders(target) {
  const first = await fetchText(target);
  if (!first.ok) throw new Error(`target_http_${first.status}`);
  const scoreMap = new Map(), evidenceMap = new Map();
  const endpoints = new Set(extractEndpoints(first.text, first.finalUrl));
  const storage = extractStorage(first.text);
  scoreText(first.text, 'html', scoreMap, evidenceMap);

  const scripts = extractScripts(first.text, first.finalUrl);
  let scannedScripts = 0;
  for (const href of scripts.slice(0, MAX_SCRIPTS)) {
    try {
      const loaded = await fetchText(new URL(href));
      if (!loaded.ok) continue;
      scannedScripts++;
      scoreText(loaded.text, `script:${new URL(href).pathname.split('/').pop() || 'bundle'}`, scoreMap, evidenceMap);
      extractEndpoints(loaded.text, loaded.finalUrl).forEach(x=>endpoints.add(x));
      const st=extractStorage(loaded.text);
      st.localStorage.forEach(x=>storage.localStorage.includes(x)||storage.localStorage.push(x));
      st.sessionStorage.forEach(x=>storage.sessionStorage.includes(x)||storage.sessionStorage.push(x));
      st.cookies.forEach(x=>storage.cookies.includes(x)||storage.cookies.push(x));
      st.jwtClaims.forEach(x=>storage.jwtClaims.includes(x)||storage.jwtClaims.push(x));
    } catch {}
  }

  const setCookie = first.headers['set-cookie'] || '';
  for (const m of setCookie.matchAll(/(?:^|,\s*)([^=;,\s]+)=/g)) if (!storage.cookies.includes(m[1])) storage.cookies.push(m[1]);
  for (const ep of endpoints) scoreEndpoint(ep, scoreMap, evidenceMap);

  const oidcMetadata = await probeOidc(first.finalUrl, [...endpoints]);
  for (const meta of oidcMetadata) {
    scoreMap.set('oidc',(scoreMap.get('oidc')||0)+4);
    const arr=evidenceMap.get('oidc')||[]; if(arr.length<8) arr.push(`metadado OIDC público: ${meta.url}`); evidenceMap.set('oidc',arr);
    const issuer=String(meta.issuer||'');
    for (const [p,re] of [['auth0',/auth0\.com/i],['okta',/okta\.com/i],['entra-id',/microsoftonline\.com/i],['cognito',/amazoncognito/i],['keycloak',/\/realms\//i]]) if(re.test(issuer)){scoreMap.set(p,(scoreMap.get(p)||0)+5);const a=evidenceMap.get(p)||[];if(a.length<8)a.push(`issuer OIDC: ${issuer}`);evidenceMap.set(p,a);}
  }

  if (storage.jwtClaims.length >= 2 || /access[_-]?token|refresh[_-]?token/i.test(first.text)) {
    scoreMap.set('jwt-custom',(scoreMap.get('jwt-custom')||0)+2);
    const arr=evidenceMap.get('jwt-custom')||[]; if(arr.length<8) arr.push(`claims/chaves JWT observados: ${storage.jwtClaims.slice(0,8).join(', ')}`); evidenceMap.set('jwt-custom',arr);
  }

  const detections=[...scoreMap.entries()].map(([provider,score])=>({
    provider,
    type:'authentication',
    confidence: score >= 8 ? 'high' : score >= 4 ? 'medium' : 'low',
    score,
    evidence:evidenceMap.get(provider)||[]
  })).sort((a,b)=>b.score-a.score);

  return {
    detections,
    provider: detections[0]?.provider || 'custom-or-unknown',
    confidence: detections[0]?.confidence || 'low',
    type:'authentication',
    endpoints:[...endpoints].slice(0,30),
    cookies:storage.cookies.slice(0,20),
    storage:{localStorage:storage.localStorage.slice(0,20),sessionStorage:storage.sessionStorage.slice(0,20)},
    jwtClaims:storage.jwtClaims.slice(0,20),
    oidcMetadata,
    responseHeaders:first.headers,
    scannedScripts,
    finalOrigin:first.finalUrl.origin
  };
}
