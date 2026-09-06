import { addSignal } from './signals.js';

const GENERIC_ENDPOINTS={
  login:[/\/api\/(?:auth\/)?login\b/gi,/\/auth\/login\b/gi,/\/signin\b/gi,/\/authenticate\b/gi,/\/token\b/gi],
  logout:[/\/api\/(?:auth\/)?logout\b/gi,/\/auth\/logout\b/gi,/\/signout\b/gi],
  session:[/\/api\/(?:auth\/)?session\b/gi,/\/api\/me\b/gi,/\/current-user\b/gi,/\/currentuser\b/gi],
  refresh:[/\/api\/(?:auth\/)?refresh\b/gi,/\/auth\/refresh\b/gi,/\/token\/refresh\b/gi],
  registration:[/\/api\/(?:auth\/)?(?:register|signup)\b/gi,/\/auth\/(?:register|signup)\b/gi],
  passwordReset:[/(?:forgot|reset)[-_/]?password\b/gi,/password[-_/]?reset\b/gi],
  mfa:[/\/(?:mfa|2fa|otp|totp)(?:\/|\b)/gi,/verify[-_/]?code\b/gi,/webauthn/gi,/passkey/gi],
  sso:[/\/sso(?:\/|\b)/gi,/\/oauth2?\/authorize\b/gi,/openid-connect/gi]
};

export function detectGenericAuth(ctx){
  const corpus=ctx.corpus.join('\n');
  let genericSignals=0;
  for(const [flow,patterns] of Object.entries(GENERIC_ENDPOINTS)){
    for(const re of patterns){
      re.lastIndex=0;let m;
      while((m=re.exec(corpus))&&genericSignals<80){
        const value=m[0];
        ctx.flow[flow]=true;
        try{ctx.endpoints.add(new URL(value,ctx.finalUrl).toString());}catch{}
        addSignal(ctx,{type:`${flow}_endpoint`,value,source:'generic-corpus',weight:flow==='refresh'?4:3,strength:'medium'});
        genericSignals++;
        if(re.lastIndex===m.index)re.lastIndex++;
      }
    }
  }

  if(/csrf|xsrf|X-CSRF-TOKEN|X-XSRF-TOKEN/i.test(corpus))addSignal(ctx,{type:'csrf_protection',source:'generic-corpus',weight:2,strength:'weak'});
  if(/HttpOnly|SameSite=(?:Lax|Strict|None)/i.test(corpus))addSignal(ctx,{type:'cookie_session_hints',source:'generic-corpus',weight:2,strength:'weak'});
  if(/\baccess[_-]?token\b/i.test(corpus)&&/\brefresh[_-]?token\b/i.test(corpus))addSignal(ctx,{type:'token_pair',source:'generic-corpus',weight:5,strength:'medium'});
  if(/Authorization["'`\s:]+Bearer/i.test(corpus))addSignal(ctx,{type:'bearer_auth',source:'generic-corpus',weight:3,strength:'medium'});

  ctx.coverage.endpointCandidates=ctx.endpoints.size;
}
