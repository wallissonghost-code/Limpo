const MAX_TEXT = 1_500_000;
const MAX_RESOURCES = 36;
const MAX_DEPTH = 2;
const MAX_REDIRECTS = 4;

function isPublicHostname(hostname) {
  const host = String(hostname || '').trim().toLowerCase().replace(/\.$/, '');
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return false;
  if (host === '0.0.0.0' || host === '::1' || host === '[::1]') return false;
  if (/^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host) || /^169\.254\./.test(host)) return false;
  const m = host.match(/^172\.(\d+)\./);
  return !(m && Number(m[1]) >= 16 && Number(m[1]) <= 31);
}

function safeUrl(raw, base) {
  try {
    const u = new URL(String(raw || ''), base);
    if (u.protocol !== 'https:' || u.username || u.password || !isPublicHostname(u.hostname)) return null;
    if (u.port && u.port !== '443') return null;
    return u;
  } catch { return null; }
}

async function safeFetch(url, init = {}) {
  let current = safeUrl(url?.href || url);
  if (!current) throw new Error('unsafe_url');
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const response = await fetch(current, { ...init, redirect: 'manual' });
    if (![301,302,303,307,308].includes(response.status)) return { response, finalUrl: current };
    const location = response.headers.get('location');
    const next = safeUrl(location, current);
    if (!next) throw new Error('unsafe_redirect');
    current = next;
  }
  throw new Error('too_many_redirects');
}

function cookieNames(raw) {
  const out = new Set();
  const s = String(raw || '');
  for (const m of s.matchAll(/(?:^|,\s*)([^=;,\s]+)=/g)) out.add(m[1]);
  return [...out].slice(0, 20);
}

function sanitizeHeaders(headers) {
  const out = {};
  for (const name of ['server','via','x-powered-by','www-authenticate','location','cf-ray','x-vercel-id','x-amz-cf-id','content-security-policy']) {
    const value = headers.get(name);
    if (value) out[name] = value.slice(0, 2500);
  }
  const setCookie = headers.get('set-cookie');
  if (setCookie) out['set-cookie-names'] = cookieNames(setCookie);
  return out;
}

async function fetchText(url) {
  const { response, finalUrl } = await safeFetch(url, { headers: { 'User-Agent': 'LIMPO-Auth-Detector/4.0' } });
  const length = Number(response.headers.get('content-length') || 0);
  if (length > MAX_TEXT) throw new Error('target_too_large');
  const type = String(response.headers.get('content-type') || '').toLowerCase();
  const readable = !type || /(text|javascript|json|html|xml|css)/.test(type);
  const text = response.ok && readable ? (await response.text()).slice(0, MAX_TEXT) : '';
  return { ok: response.ok, status: response.status, text, finalUrl, headers: sanitizeHeaders(response.headers) };
}

function addResource(out, raw, baseUrl) {
  const u = safeUrl(raw, baseUrl);
  if (!u) return;
  const hint = u.pathname + u.search;
  if (/\.(?:js|mjs|cjs)(?:$|\?)/i.test(hint) || /(?:script|chunk|bundle|auth|oauth|login|identity|sdk)/i.test(u.href)) out.add(u.href);
}

function extractResources(text, baseUrl) {
  const source = String(text || '');
  const out = new Set();
  let m;
  for (const re of [/<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi, /(?:import\s+(?:[^"']+?\s+from\s+)?|import\s*\()["']([^"']+)["']/g, /new\s+Worker\s*\(\s*["']([^"']+)["']/g]) {
    while ((m = re.exec(source)) && out.size < MAX_RESOURCES * 2) addResource(out, m[1], baseUrl);
  }
  const linkRe = /<link\b([^>]+)>/gi;
  while ((m = linkRe.exec(source)) && out.size < MAX_RESOURCES * 2) {
    const tag = m[1];
    const rel = tag.match(/\brel=["']([^"']+)["']/i)?.[1] || '';
    if (!/(?:^|\s)(modulepreload|preload|prefetch)(?:\s|$)/i.test(rel)) continue;
    const as = tag.match(/\bas=["']([^"']+)["']/i)?.[1] || '';
    const href = tag.match(/\bhref=["']([^"']+)["']/i)?.[1];
    if (href && (!as || /script/i.test(as) || /modulepreload/i.test(rel))) addResource(out, href, baseUrl);
  }
  return [...out];
}

function extractEndpoints(text, baseUrl) {
  const source = String(text || '');
  const out = new Set();
  const patterns = [
    /["'`]((?:https:\/\/|\/)[^"'`\s]{0,220}(?:\/auth|\/oauth|\/authorize|\/token|\/userinfo|\/login|\/signin|\/session|\/callback|\/sso|\/identity)[^"'`\s]{0,160})["'`]/gi,
    /(?:issuer|authorization_endpoint|token_endpoint|userinfo_endpoint|jwks_uri|end_session_endpoint|baseURL|apiURL|apiUrl|authUrl|authURL)\s*[:=]\s*["'`]([^"'`]+)["'`]/gi,
    /https:\/\/[A-Za-z0-9._-]+(?:\.auth0\.com|\.okta\.com|\.supabase\.co|\.clerk\.accounts|\.amazoncognito\.com|\.microsoftonline\.com)[^"'`\s)]*/gi
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(source)) && out.size < 40) {
      const u = safeUrl(m[1] || m[0], baseUrl);
      if (u) out.add(u.href);
    }
  }
  return [...out];
}

function extractFirebaseConfig(text) {
  const source = String(text || '');
  return {
    apiKey: source.match(/\bapiKey\s*[:=]\s*["'`]([^"'`]{10,200})["'`]/i)?.[1] || '',
    authDomain: source.match(/\bauthDomain\s*[:=]\s*["'`]([^"'`]{3,200})["'`]/i)?.[1] || '',
    projectId: source.match(/\bprojectId\s*[:=]\s*["'`]([^"'`]{2,160})["'`]/i)?.[1] || ''
  };
}

function extractStorage(text) {
  const s = String(text || '');
  const localStorage = new Set(), sessionStorage = new Set(), cookies = new Set(), jwtClaims = new Set();
  const localPatterns = [/localStorage\.(?:setItem|getItem|removeItem)\s*\(\s*["'`]([^"'`]+)["'`]/gi, /localStorage\s*\[\s*["'`]([^"'`]+)["'`]\s*\]/gi];
  const sessionPatterns = [/sessionStorage\.(?:setItem|getItem|removeItem)\s*\(\s*["'`]([^"'`]+)["'`]/gi, /sessionStorage\s*\[\s*["'`]([^"'`]+)["'`]\s*\]/gi];
  for (const re of localPatterns) for (const m of s.matchAll(re)) localStorage.add(m[1]);
  for (const re of sessionPatterns) for (const m of s.matchAll(re)) sessionStorage.add(m[1]);
  for (const m of s.matchAll(/document\.cookie\s*=\s*["'`]([^=;"'`]{1,80})=/gi)) cookies.add(m[1]);
  for (const m of s.matchAll(/\b(sub|iss|aud|exp|iat|nbf|azp|scope|roles|role|permissions|email|preferred_username|tenant|tid|client_id|nonce)\b\s*[:=]/gi)) jwtClaims.add(m[1]);
  for (const m of s.matchAll(/["'`]([^"'`]{1,100}(?:auth|token|session|jwt)[^"'`]{0,80})["'`]/gi)) {
    const key = m[1];
    if (/localstorage/i.test(s.slice(Math.max(0, m.index - 100), m.index + 150))) localStorage.add(key);
    if (/sessionstorage/i.test(s.slice(Math.max(0, m.index - 100), m.index + 150))) sessionStorage.add(key);
  }
  return { localStorage:[...localStorage].slice(0,20), sessionStorage:[...sessionStorage].slice(0,20), cookies:[...cookies].slice(0,20), jwtClaims:[...jwtClaims].slice(0,20) };
}

function mergeUnique(target, source, max = 20) {
  for (const value of source || []) if (!target.includes(value) && target.length < max) target.push(value);
}

function detectCustomApi(text, baseUrl) {
  const s = String(text || '');
  const endpoints = new Set(), fields = new Set(), methods = new Set(), transports = new Set();
  const addEndpoint = raw => { const u = safeUrl(raw, baseUrl); if (u) endpoints.add(u.href); };
  let m;
  const callPatterns = [
    { re:/fetch\s*\(\s*["'`]([^"'`]{1,220})["'`]\s*(?:,\s*\{([\s\S]{0,700}?)\})?/gi, transport:'fetch' },
    { re:/(?:axios\.|[A-Za-z_$][\w$]*\.)(post|put|patch|get)\s*\(\s*["'`]([^"'`]{1,220})["'`]/gi, transport:'axios/wrapper' }
  ];
  while ((m = callPatterns[0].re.exec(s)) && endpoints.size < 16) {
    if (!/(login|signin|sign-in|auth|session|token)/i.test(m[1])) continue;
    addEndpoint(m[1]); transports.add('fetch');
    methods.add((m[2]?.match(/method\s*:\s*["'`](POST|PUT|PATCH|GET)["'`]/i)?.[1] || 'GET').toUpperCase());
  }
  while ((m = callPatterns[1].re.exec(s)) && endpoints.size < 16) {
    if (!/(login|signin|sign-in|auth|session|token)/i.test(m[2])) continue;
    methods.add(m[1].toUpperCase()); addEndpoint(m[2]); transports.add('axios/wrapper');
  }
  for (const fm of s.matchAll(/\b(email|username|user|login|identifier|password|senha|pass)\b\s*[:=]/gi)) fields.add(fm[1].toLowerCase());
  for (const fm of s.matchAll(/["'](email|username|user|login|identifier|password|senha|pass)["']\s*:/gi)) fields.add(fm[1].toLowerCase());
  if (/mutation\s+[A-Za-z0-9_]*(?:login|signin|auth)/i.test(s)) { methods.add('POST'); transports.add('graphql'); }
  const hasUser = [...fields].some(x => ['email','username','user','login','identifier'].includes(x));
  const hasPass = [...fields].some(x => ['password','senha','pass'].includes(x));
  const score = (endpoints.size ? 3 : 0) + (methods.size ? 1 : 0) + (hasUser && hasPass ? 2 : 0) + (transports.size ? 1 : 0);
  return { endpoints:[...endpoints].slice(0,16), fields:[...fields].slice(0,12), methods:[...methods].slice(0,8), transports:[...transports].slice(0,8), score };
}

const PROVIDERS = {
  firebase: { specific:[/firebase\/auth|firebase-auth|identitytoolkit\.googleapis\.com|firebaseapp\.com/i,/\bauthDomain\s*[:=]|signInWithEmailAndPassword|onAuthStateChanged/i] },
  supabase: { specific:[/\.supabase\.co|@supabase\/supabase-js|supabase-js/i,/auth\.signInWithPassword|signInWithOtp|signInWithOAuth/i] },
  auth0: { specific:[/\.auth0\.com|@auth0|createAuth0Client|Auth0Client/i] },
  clerk: { specific:[/clerk\.com|clerk\.accounts|@clerk|clerkpublishablekey|clerk-js|clerkClient/i] },
  cognito: { specific:[/cognito-idp|amazoncognito|CognitoUserPool|aws-amplify\/auth|UserPoolId|amazoncognito\.com/i] },
  okta: { specific:[/\.okta\.com|@okta|OktaAuth|okta-auth-js/i] },
  'entra-id': { specific:[/login\.microsoftonline\.com|@azure\/msal|PublicClientApplication|ConfidentialClientApplication/i] },
  keycloak: { specific:[/keycloak-js|new\s+Keycloak|\/realms\/[^/]+\/protocol\/openid-connect/i] },
  authjs: { specific:[/next-auth|nextauth|authjs|\/api\/auth\/(signin|session|callback)|AUTH_SECRET|NEXTAUTH_URL/i] },
  passport: { specific:[/passport\.authenticate|passport-local|passport-jwt|passport-oauth2|serializeUser|deserializeUser/i] },
  'jwt-custom': { specific:[/Authorization\s*[:=]\s*["'`]Bearer|Bearer\s+\$\{|jwt\.sign|jwt\.verify|jsonwebtoken|access[_-]?token|refresh[_-]?token/i] },
  oauth2: { generic:[/grant_type|client_id|redirect_uri|response_type|code_challenge|code_verifier|\/oauth(?:2)?\/|\/authorize|\/token/i] },
  oidc: { generic:[/openid-configuration|openid-connect|id_token|jwks_uri|userinfo_endpoint|scope[^\n]{0,80}openid/i] }
};

function addScore(scoreMap, evidenceMap, provider, points, evidence) {
  scoreMap.set(provider, (scoreMap.get(provider) || 0) + points);
  const list = evidenceMap.get(provider) || [];
  if (evidence && !list.includes(evidence) && list.length < 10) list.push(evidence);
  evidenceMap.set(provider, list);
}

function scoreText(text, source, scoreMap, evidenceMap) {
  const s = String(text || '');
  for (const [provider, config] of Object.entries(PROVIDERS)) {
    for (const re of config.specific || []) if (re.test(s)) addScore(scoreMap, evidenceMap, provider, 4, `${source}: sinal específico`);
    for (const re of config.generic || []) if (re.test(s)) addScore(scoreMap, evidenceMap, provider, 2, `${source}: padrão de protocolo`);
  }
}

function scoreEndpoint(endpoint, scoreMap, evidenceMap) {
  const e = String(endpoint || '').toLowerCase();
  const rules = [
    ['firebase',/identitytoolkit\.googleapis\.com|firebaseapp\.com/],['supabase',/\.supabase\.co/],['auth0',/\.auth0\.com/],['clerk',/clerk\./],
    ['cognito',/amazoncognito|cognito-idp|amazonaws\.com\/.*oauth2/],['okta',/\.okta\.com/],['entra-id',/login\.microsoftonline\.com/],['keycloak',/\/realms\/|openid-connect/]
  ];
  for (const [provider,re] of rules) if (re.test(e)) addScore(scoreMap,evidenceMap,provider,5,`endpoint/origem: ${endpoint}`);
  if (/\/authorize|\/token|\/userinfo|openid-configuration/.test(e)) {
    addScore(scoreMap,evidenceMap,'oauth2',1,`endpoint padrão: ${endpoint}`);
    addScore(scoreMap,evidenceMap,'oidc',1,`endpoint padrão: ${endpoint}`);
  }
}

function scoreCookieNames(names, scoreMap, evidenceMap) {
  for (const name of names) {
    const n = String(name).toLowerCase();
    if (/next-auth\.session-token|authjs\.session-token/.test(n)) addScore(scoreMap,evidenceMap,'authjs',5,`cookie: ${name}`);
    if (/^sb-.*-auth-token$/.test(n)) addScore(scoreMap,evidenceMap,'supabase',5,`cookie: ${name}`);
    if (/clerk|__session/.test(n)) addScore(scoreMap,evidenceMap,'clerk',3,`cookie: ${name}`);
    if (/okta/.test(n)) addScore(scoreMap,evidenceMap,'okta',4,`cookie: ${name}`);
    if (/keycloak/.test(n)) addScore(scoreMap,evidenceMap,'keycloak',4,`cookie: ${name}`);
  }
}

async function probeOidc(baseUrl, endpoints) {
  const candidates = new Set([new URL('/.well-known/openid-configuration', baseUrl).href]);
  for (const ep of endpoints) {
    try {
      const u = new URL(ep);
      if (/\/realms\//i.test(u.pathname)) {
        const idx = u.pathname.indexOf('/protocol/');
        const root = idx > 0 ? u.pathname.slice(0, idx) : u.pathname;
        candidates.add(`${u.origin}${root}/.well-known/openid-configuration`);
      }
      if (/microsoftonline\.com|okta\.com|auth0\.com|amazoncognito|keycloak/i.test(u.hostname + u.pathname)) candidates.add(new URL('/.well-known/openid-configuration', u.origin).href);
    } catch {}
  }
  const results = [];
  for (const href of [...candidates].slice(0,6)) {
    try {
      const u = safeUrl(href); if (!u) continue;
      const { response, finalUrl } = await safeFetch(u, { headers:{'User-Agent':'LIMPO-Auth-Detector/4.0'} });
      if (!response.ok) continue;
      const type = String(response.headers.get('content-type') || '');
      if (type && !/json/i.test(type)) continue;
      const data = await response.json().catch(()=>null);
      if (data && (data.issuer || data.authorization_endpoint || data.token_endpoint)) results.push({url:finalUrl.href,issuer:data.issuer||null,authorization_endpoint:data.authorization_endpoint||null,token_endpoint:data.token_endpoint||null,userinfo_endpoint:data.userinfo_endpoint||null,jwks_uri:data.jwks_uri||null});
    } catch {}
  }
  return results;
}

export async function detectAuthProviders(target) {
  const first = await fetchText(target);
  if (!first.ok) throw new Error(`target_http_${first.status}`);

  const scoreMap = new Map(), evidenceMap = new Map();
  const endpoints = new Set(extractEndpoints(first.text, first.finalUrl));
  const externalOrigins = new Set();
  const storage = extractStorage(first.text);
  const custom = { endpoints:[], fields:[], methods:[], transports:[], score:0 };
  let firebaseConfig = extractFirebaseConfig(first.text);

  scoreText(first.text, 'html', scoreMap, evidenceMap);
  scoreText(JSON.stringify(first.headers), 'headers', scoreMap, evidenceMap);
  scoreCookieNames(first.headers['set-cookie-names'] || [], scoreMap, evidenceMap);

  const firstCustom = detectCustomApi(first.text, first.finalUrl);
  for (const key of ['endpoints','fields','methods','transports']) mergeUnique(custom[key], firstCustom[key], key === 'endpoints' ? 16 : 12);
  custom.score = Math.max(custom.score, firstCustom.score);

  const queue = extractResources(first.text, first.finalUrl).map(href => ({href,depth:0}));
  const visited = new Set();
  while (queue.length && visited.size < MAX_RESOURCES) {
    const item = queue.shift();
    if (!item || visited.has(item.href)) continue;
    visited.add(item.href);
    try {
      const resourceUrl = safeUrl(item.href); if (!resourceUrl) continue;
      if (resourceUrl.origin !== first.finalUrl.origin) externalOrigins.add(resourceUrl.origin);
      const loaded = await fetchText(resourceUrl);
      if (!loaded.ok || !loaded.text) continue;
      const source = `${resourceUrl.origin === first.finalUrl.origin ? 'script' : 'external'}:${resourceUrl.hostname}${resourceUrl.pathname}`.slice(0,180);
      scoreText(loaded.text, source, scoreMap, evidenceMap);
      scoreText(JSON.stringify(loaded.headers), `headers:${resourceUrl.hostname}`, scoreMap, evidenceMap);
      scoreCookieNames(loaded.headers['set-cookie-names'] || [], scoreMap, evidenceMap);
      extractEndpoints(loaded.text, loaded.finalUrl).forEach(x=>endpoints.add(x));
      const st = extractStorage(loaded.text);
      for (const key of ['localStorage','sessionStorage','cookies','jwtClaims']) mergeUnique(storage[key], st[key]);
      const cfg = extractFirebaseConfig(loaded.text);
      if (!firebaseConfig.apiKey && cfg.apiKey) firebaseConfig = cfg;
      const c = detectCustomApi(loaded.text, loaded.finalUrl);
      for (const key of ['endpoints','fields','methods','transports']) mergeUnique(custom[key], c[key], key === 'endpoints' ? 16 : 12);
      custom.score = Math.max(custom.score, c.score);
      if (item.depth < MAX_DEPTH) for (const child of extractResources(loaded.text, loaded.finalUrl)) if (!visited.has(child) && queue.length < MAX_RESOURCES * 2) queue.push({href:child,depth:item.depth+1});
    } catch {}
  }

  for (const ep of custom.endpoints) endpoints.add(ep);
  for (const ep of endpoints) scoreEndpoint(ep, scoreMap, evidenceMap);
  for (const origin of externalOrigins) scoreEndpoint(origin, scoreMap, evidenceMap);
  scoreCookieNames(storage.cookies, scoreMap, evidenceMap);

  if (custom.score >= 6) addScore(scoreMap,evidenceMap,'custom-api',6,'fluxo cliente/API de autenticação detectado');
  else if (custom.score >= 3) addScore(scoreMap,evidenceMap,'custom-api',3,'possível fluxo cliente/API de autenticação');

  const oidcMetadata = await probeOidc(first.finalUrl, [...endpoints]);
  for (const meta of oidcMetadata) {
    addScore(scoreMap,evidenceMap,'oidc',5,`metadado OIDC público: ${meta.url}`);
    const issuer = String(meta.issuer || '');
    for (const [p,re] of [['auth0',/auth0\.com/i],['okta',/okta\.com/i],['entra-id',/microsoftonline\.com/i],['cognito',/amazoncognito/i],['keycloak',/\/realms\//i]]) if (re.test(issuer)) addScore(scoreMap,evidenceMap,p,6,`issuer OIDC: ${issuer}`);
  }

  if (firebaseConfig.apiKey) addScore(scoreMap,evidenceMap,'firebase',6,'configuração Firebase pública encontrada no frontend');
  if (storage.jwtClaims.length >= 2) addScore(scoreMap,evidenceMap,'jwt-custom',2,`claims JWT observados: ${storage.jwtClaims.slice(0,8).join(', ')}`);

  const detections = [...scoreMap.entries()].map(([provider,score])=>({provider,type:'authentication',confidence:score>=10?'high':score>=5?'medium':'low',score,evidence:evidenceMap.get(provider)||[]})).sort((a,b)=>b.score-a.score);
  const primary = detections[0] || {provider:'custom-or-unknown',confidence:'low'};

  return {
    provider: primary.provider,
    confidence: primary.confidence,
    type: 'authentication',
    detections,
    endpoints:[...endpoints].slice(0,40),
    externalOrigins:[...externalOrigins].slice(0,20),
    cookies:storage.cookies.slice(0,20),
    storage:{localStorage:storage.localStorage.slice(0,20),sessionStorage:storage.sessionStorage.slice(0,20)},
    jwtClaims:storage.jwtClaims.slice(0,20),
    oidcMetadata,
    responseHeaders:first.headers,
    scannedScripts:visited.size,
    finalOrigin:first.finalUrl.origin,
    customAuth:custom,
    adapterHints:{ firebase: firebaseConfig.apiKey ? firebaseConfig : null }
  };
}
