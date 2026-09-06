export const WEIGHTS = {
  explicitSdk: 10,
  knownProviderDomain: 9,
  oidcMetadata: 10,
  authEndpoint: 3,
  bearerToken: 3,
  refreshToken: 4,
  sessionCookie: 3,
  loginForm: 2,
  storageToken: 4,
  frameworkHint: 1,
  mfaSignal: 4,
  sourceMapHint: 2
};

const FLOW_PATTERNS = {
  login: [/\/login\b/i,/\/signin\b/i,/\/sign-in\b/i,/\/authenticate\b/i,/\/auth\/login\b/i,/signinwithpassword/i],
  logout: [/\/logout\b/i,/\/signout\b/i,/\/sign-out\b/i],
  session: [/\/session\b/i,/\/me\b/i,/\/current-user\b/i,/\/currentuser\b/i,/\/user\b/i],
  refresh: [/\/refresh\b/i,/\/token\/refresh\b/i,/\/auth\/refresh\b/i,/refresh_token/i],
  registration: [/\/register\b/i,/\/signup\b/i,/\/sign-up\b/i,/accounts:signup/i],
  passwordReset: [/forgot[-_/]?password/i,/reset[-_/]?password/i,/password[-_/]?reset/i],
  mfa: [/\/mfa\b/i,/\/2fa\b/i,/\/otp\b/i,/\/totp\b/i,/verify[-_/]?code/i,/challenge/i,/webauthn/i,/passkey/i],
  sso: [/\/sso\b/i,/saml/i,/openid-connect/i,/oauth2?\/authorize/i]
};

const FRAMEWORK_PATTERNS = {
  nextjs: [/__NEXT_DATA__/i,/_next\/static/i],
  nuxt: [/__NUXT__/i,/_nuxt\//i],
  angular: [/ng-version=/i,/runtime\.[a-z0-9]+\.js/i],
  vue: [/__VUE__/i,/vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js/i],
  svelte: [/_app\/immutable/i,/svelte(?:kit)?/i],
  remix: [/__remixContext/i,/\/build\/_assets\//i],
  astro: [/astro-island/i,/_astro\//i],
  laravel: [/laravel_session/i,/XSRF-TOKEN/i],
  django: [/csrftoken/i,/django/i],
  rails: [/_rails_session/i,/csrf-param/i],
  spring: [/JSESSIONID/i,/spring-security/i],
  aspnet: [/ASP\.NET_SessionId/i,/\.AspNetCore\./i],
  express: [/connect\.sid/i,/express/i],
  fastapi: [/fastapi/i,/\/docs(?:\b|\/)/i],
  nestjs: [/nestjs/i,/@nestjs\//i]
};

const REQUEST_PATTERNS = [
  /\bfetch\s*\(\s*["'`]([^"'`]+)["'`]/gi,
  /\baxios\.(?:get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]/gi,
  /\.request\s*\(\s*\{[\s\S]{0,500}?url\s*:\s*["'`]([^"'`]+)["'`]/gi,
  /XMLHttpRequest[\s\S]{0,500}?\.open\s*\(\s*["'`][A-Z]+["'`]\s*,\s*["'`]([^"'`]+)["'`]/gi
];

export function addSignal(ctx, signal) {
  const key = `${signal.type}|${signal.value || ''}|${signal.source || ''}`;
  if (ctx._signalKeys.has(key)) return;
  ctx._signalKeys.add(key);
  ctx.signals.push({ weight: 1, strength: 'weak', ...signal });
}

export function extractRequestUrls(text, baseUrl) {
  const out = new Set();
  for (const re of REQUEST_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) && out.size < 250) {
      try { out.add(new URL(m[1], baseUrl).toString()); } catch {}
    }
  }
  const absolute = /https?:\\?\/\\?\/[a-z0-9._~:/?#\[\]@!$&'()*+,;=%\\-]+/gi;
  let m;
  while ((m = absolute.exec(text)) && out.size < 400) {
    const raw = m[0].replace(/\\\//g,'/').replace(/\\u002f/gi,'/');
    try { out.add(new URL(raw).toString()); } catch {}
  }
  return [...out];
}

export function inspectBehavior(ctx, text, source, baseUrl) {
  if (!text) return;
  const requestUrls = extractRequestUrls(text, baseUrl);
  for (const url of requestUrls) {
    ctx.endpoints.add(url);
    for (const [flow, patterns] of Object.entries(FLOW_PATTERNS)) {
      if (patterns.some(re => re.test(url))) {
        ctx.flow[flow] = true;
        addSignal(ctx,{type:`${flow}_endpoint`,value:url,source,weight:flow==='refresh'?WEIGHTS.refreshToken:WEIGHTS.authEndpoint,strength:'medium'});
      }
    }
  }

  if (/\bAuthorization\b|['"]authorization['"]\s*:/i.test(text)) addSignal(ctx,{type:'authorization_header',source,weight:WEIGHTS.bearerToken,strength:'medium'});
  if (/\bBearer\s+|Bearer['"`]\s*\+/i.test(text)) { ctx.authentication.token='bearer'; addSignal(ctx,{type:'bearer_auth',source,weight:WEIGHTS.bearerToken,strength:'medium'}); }
  if (/\baccess_token\b/i.test(text)) addSignal(ctx,{type:'access_token',source,weight:WEIGHTS.storageToken,strength:'medium'});
  if (/\brefresh_token\b/i.test(text)) { ctx.flow.refresh=true; addSignal(ctx,{type:'refresh_token',source,weight:WEIGHTS.refreshToken,strength:'medium'}); }
  if (/\bid_token\b/i.test(text)) addSignal(ctx,{type:'id_token',source,weight:WEIGHTS.storageToken,strength:'medium'});
  if (/credentials\s*:\s*["'`]include["'`]/i.test(text)|/withCredentials\s*=\s*true/i.test(text)) { ctx.authentication.session='cookie'; addSignal(ctx,{type:'credentialed_requests',source,weight:WEIGHTS.sessionCookie,strength:'medium'}); }
  if (/localStorage[\s\S]{0,120}(token|auth|session)/i.test(text)) { ctx.authentication.session=ctx.authentication.session||'browser-storage'; addSignal(ctx,{type:'auth_storage',source,weight:WEIGHTS.storageToken,strength:'medium'}); }
  if (/<form\b[\s\S]{0,1200}type=["']password["']/i.test(text)) { ctx.authentication.type='password'; ctx.flow.login=true; addSignal(ctx,{type:'login_form',source,weight:WEIGHTS.loginForm,strength:'weak'}); }

  for (const [name, patterns] of Object.entries(FRAMEWORK_PATTERNS)) {
    if (patterns.some(re => re.test(text))) {
      ctx.frameworks.add(name);
      addSignal(ctx,{type:'framework_hint',value:name,source,weight:WEIGHTS.frameworkHint,strength:'weak'});
    }
  }

  const mfaMethods=[];
  if (/webauthn|passkey/i.test(text)) mfaMethods.push('webauthn/passkey');
  if (/\btotp\b/i.test(text)) mfaMethods.push('totp');
  if (/\botp\b|verify[-_ ]?code/i.test(text)) mfaMethods.push('otp');
  if (mfaMethods.length) {
    ctx.flow.mfa=true;
    for (const method of new Set(mfaMethods)) ctx.mfa.methods.add(method);
    addSignal(ctx,{type:'mfa_signal',value:[...new Set(mfaMethods)].join(','),source,weight:WEIGHTS.mfaSignal,strength:'medium'});
  }

  if (/\.well-known\/openid-configuration|openid-connect|\boidc\b/i.test(text)) { ctx.authentication.protocol='oidc'; addSignal(ctx,{type:'oidc',source,weight:WEIGHTS.oidcMetadata,strength:'strong'}); }
  else if (/oauth2?|authorization_code|code_challenge|pkce/i.test(text)) { ctx.authentication.protocol='oauth2'; addSignal(ctx,{type:'oauth2',source,weight:4,strength:'medium'}); }
  if (/eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}|jwt|jsonwebtoken/i.test(text)) { ctx.authentication.token='jwt'; addSignal(ctx,{type:'jwt',source,weight:3,strength:'medium'}); }
}

export function inspectHeaders(ctx, headers, source='headers') {
  const cookie = headers.get?.('set-cookie') || '';
  if (cookie) {
    const names = [...cookie.matchAll(/(?:^|,\s*)([^=;,\s]+)=/g)].map(m=>m[1]).slice(0,20);
    for (const name of names) ctx.cookieNames.add(name);
    ctx.authentication.session='cookie';
    addSignal(ctx,{type:'session_cookie',value:names.join(','),source,weight:WEIGHTS.sessionCookie,strength:'medium'});
    if (/httponly/i.test(cookie)) addSignal(ctx,{type:'httponly_cookie',source,weight:2,strength:'weak'});
    if (/samesite/i.test(cookie)) addSignal(ctx,{type:'samesite_cookie',source,weight:1,strength:'weak'});
  }
  const www = headers.get?.('www-authenticate') || '';
  if (/bearer/i.test(www)) { ctx.authentication.token='bearer'; addSignal(ctx,{type:'www_authenticate_bearer',source,weight:4,strength:'medium'}); }
}
