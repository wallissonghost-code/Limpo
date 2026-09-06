function corpus(ctx){return String((ctx?.corpus||[]).join('\n'));}

function absoluteUrl(raw,base){try{return new URL(raw,base).toString();}catch{return null;}}

function scoreEndpoint(url){let s=0;if(/\/api\//i.test(url))s+=2;if(/auth|identity|account/i.test(url))s+=3;if(/login|signin|sign-in|authenticate|session|token/i.test(url))s+=7;if(/logout|refresh|register|signup/i.test(url))s-=2;return s;}

function genericPasswordRequest(text,base){
  const found=[];const add=(url,transport,contentType,userField='email',passField='password',confidence=0)=>{const abs=absoluteUrl(url,base);if(!abs||!/^https:/i.test(abs))return;found.push({kind:'password',transport,endpoint:abs,method:'POST',contentType,userField,passField,confidence:Math.min(100,confidence+scoreEndpoint(abs))});};
  let m;
  const fetchJson=/fetch\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*\{[\s\S]{0,1200}?method\s*:\s*["'`]POST["'`][\s\S]{0,1200}?body\s*:\s*JSON\.stringify\s*\(\s*\{([\s\S]{0,800}?)\}\s*\)/gi;
  while((m=fetchJson.exec(text))){const body=m[2];const uf=(body.match(/([A-Za-z_$][\w$]*)\s*:\s*(?:email|username|user\b)/i)||[])[1]||(/email/i.test(body)?'email':/username|user/i.test(body)?'username':'email');const pf=(body.match(/([A-Za-z_$][\w$]*)\s*:\s*password\b/i)||[])[1]||(/password/i.test(body)?'password':'password');if(/password/i.test(body)&&/(email|username|user)/i.test(body))add(m[1],'javascript-api','application/json',uf,pf,86);}
  const axios=/axios\.post\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*\{([\s\S]{0,800}?)\}/gi;
  while((m=axios.exec(text))){const body=m[2];if(!/password/i.test(body)||!/(email|username|user)/i.test(body))continue;const uf=(body.match(/([A-Za-z_$][\w$]*)\s*:\s*(?:email|username|user\b)/i)||[])[1]||'email';const pf=(body.match(/([A-Za-z_$][\w$]*)\s*:\s*password\b/i)||[])[1]||'password';add(m[1],'javascript-api','application/json',uf,pf,84);}
  const xhr=/\.open\s*\(\s*["'`]POST["'`]\s*,\s*["'`]([^"'`]+)["'`]/gi;while((m=xhr.exec(text)))add(m[1],'xhr','unknown','email','password',55);
  return found.sort((a,b)=>b.confidence-a.confidence)[0]||null;
}

function providerModel(providerId,text,base,runtime){
  if(providerId==='firebase'){
    const cfg=runtime?.firebase||{};return{provider:'firebase',password:{detected:/signInWithEmailAndPassword|accounts:signInWithPassword/i.test(text),ready:Boolean(cfg.apiKey),transport:'firebase-rest',endpoint:'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword',requirements:{apiKey:Boolean(cfg.apiKey)}}};
  }
  if(providerId==='supabase'){
    const cfg=runtime?.supabase||{};return{provider:'supabase',password:{detected:/signInWithPassword|grant_type=password/i.test(text),ready:Boolean(cfg.url&&cfg.anonKey),transport:'supabase-auth-rest',endpoint:cfg.url?`${cfg.url.replace(/\/$/,'')}/auth/v1/token?grant_type=password`:null,requirements:{url:Boolean(cfg.url),anonKey:Boolean(cfg.anonKey)}}};
  }
  if(providerId==='auth0'){
    const domain=(text.match(/(?:domain|issuer)\s*[:=]\s*["'`](https?:\/\/)?([a-z0-9.-]+\.auth0\.com)["'`]/i)||[])[2]||null;const clientId=(text.match(/clientId\s*[:=]\s*["'`]([A-Za-z0-9_-]{8,})["'`]/i)||[])[1]||null;return{provider:'auth0',password:{detected:/password-realm|grant_type.?password/i.test(text),ready:false,transport:'auth0',requirements:{domain:Boolean(domain),clientId:Boolean(clientId)}},interactive:{oauth:/authorize|loginWithRedirect|loginWithPopup/i.test(text)}};
  }
  if(providerId==='cognito'){
    const pool=(text.match(/["'`]([a-z]{2}-[a-z]+-\d_[A-Za-z0-9]+)["'`]/i)||[])[1]||null;const client=(text.match(/(?:clientId|ClientId|userPoolWebClientId)\s*[:=]\s*["'`]([A-Za-z0-9]{10,})["'`]/i)||[])[1]||null;return{provider:'cognito',password:{detected:/USER_PASSWORD_AUTH|InitiateAuth|signIn/i.test(text),ready:false,transport:'cognito',requirements:{userPoolId:Boolean(pool),clientId:Boolean(client)}}};
  }
  if(providerId==='clerk'){
    const publishable=(text.match(/\b(pk_(?:test|live)_[A-Za-z0-9_-]{20,})\b/)||[])[1]||null;return{provider:'clerk',password:{detected:/password/i.test(text)&&/clerk/i.test(text),ready:false,transport:'clerk',requirements:{publishableKey:Boolean(publishable)}}};
  }
  const generic=genericPasswordRequest(text,base);return{provider:providerId||'custom',password:generic?{detected:true,ready:generic.confidence>=80,...generic}:{detected:/password/i.test(text),ready:false,transport:'unknown',requirements:{requestShape:false}}};
}

export function reconstructFlowModel(providerId,ctx,runtime={}){
  const text=corpus(ctx);const base=ctx?.finalUrl||ctx?.requestedUrl||'https://invalid.local/';const model=providerModel(providerId,text,base,runtime);
  model.interactive={...(model.interactive||{}),oauth:/oauth2?|authorization_endpoint|loginWithRedirect|loginWithPopup|signInWithRedirect/i.test(text),oidc:/openid|oidc|\.well-known\/openid-configuration/i.test(text),magicLink:/magic.?link|signInWithOtp|email.?link/i.test(text),webauthn:/webauthn|passkey|PublicKeyCredential/i.test(text),mfa:/\bmfa\b|\btotp\b|\b2fa\b|multi.?factor/i.test(text)};
  return model;
}

export function publicFlowSummary(model={}){
  const p=model.password||{};return{provider:model.provider||'unknown',password:{detected:Boolean(p.detected),ready:Boolean(p.ready),transport:p.transport||'unknown',endpoint:p.endpoint||null,confidence:p.confidence||null,requirements:p.requirements||{}},interactive:model.interactive||{}};
}
