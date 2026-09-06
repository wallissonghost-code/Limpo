const MAX_BYTES = 1_500_000;
const TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 5;

const PROVIDERS = [
  { id:'firebase', name:'Firebase Authentication', patterns:[['identitytoolkit.googleapis.com',40],['securetoken.googleapis.com',35],['firebase-auth',30],['firebaseapp.com',18],['firebaseconfig',15],['initializeauth(',20],['getauth(',15],['signinwithemailandpassword',25],['signinwithpopup',18]] },
  { id:'supabase', name:'Supabase Auth', patterns:[['supabase.co/auth/v1',45],['/auth/v1/token',35],['@supabase/supabase-js',30],['createclient(',12],['supabase.auth',30]] },
  { id:'auth0', name:'Auth0', patterns:[['auth0.com',35],['cdn.auth0.com',30],['@auth0/',25],['createauth0client',30],['authorize?',8]] },
  { id:'clerk', name:'Clerk', patterns:[['clerk.com',30],['clerk.accounts',35],['@clerk/',30],['clerkprovider',25],['clerk-js',25]] },
  { id:'cognito', name:'AWS Cognito', patterns:[['amazoncognito.com',40],['cognito-idp.',35],['amazon-cognito-identity-js',35],['cognitouserpool',30],['auth.signin',18]] },
  { id:'keycloak', name:'Keycloak', patterns:[['/realms/',20],['/protocol/openid-connect/',45],['keycloak-js',35],['new keycloak',30],['keycloak.init',25]] },
  { id:'okta', name:'Okta', patterns:[['okta.com',35],['okta-auth-js',35],['@okta/',30],['oktaauth',30]] },
  { id:'entra', name:'Microsoft Entra / MSAL', patterns:[['login.microsoftonline.com',45],['@azure/msal',35],['msal-browser',30],['publicclientapplication',30]] },
  { id:'google', name:'Google Identity', patterns:[['accounts.google.com/gsi',45],['google.accounts.id',40],['g_id_onload',30]] },
  { id:'authjs', name:'Auth.js / NextAuth', patterns:[['/api/auth/session',35],['/api/auth/signin',35],['next-auth',35],['sessionprovider',20],['getsession(',15]] }
];

function json(data, status=200) {
  return new Response(JSON.stringify(data), {
    status,
    headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer'}
  });
}

function isBlockedHostname(hostname) {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h === '0.0.0.0' || h === '::1') return true;
  const ipv4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const p = ipv4.slice(1).map(Number);
    if (p.some(n => n > 255)) return true;
    return p[0]===10 || p[0]===127 || p[0]===0 || p[0]>=224 || (p[0]===169&&p[1]===254) || (p[0]===172&&p[1]>=16&&p[1]<=31) || (p[0]===192&&p[1]===168);
  }
  return h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe8') || h.startsWith('fe9') || h.startsWith('fea') || h.startsWith('feb');
}

function parseTarget(raw) {
  let url;
  try { url = new URL(raw); } catch { throw new Error('URL inválida.'); }
  if (!['http:','https:'].includes(url.protocol)) throw new Error('Use apenas URLs HTTP ou HTTPS.');
  if (isBlockedHostname(url.hostname)) throw new Error('Endereço local, privado ou reservado não permitido.');
  return url;
}

function confidence(score) {
  if(score>=80)return 99;if(score>=60)return 94;if(score>=45)return 88;if(score>=30)return 78;if(score>=18)return 66;return Math.max(20,Math.min(60,score*3));
}

function detect(body, finalUrl, headers) {
  const lower = `${finalUrl}\n${body}\n${JSON.stringify(headers)}`.toLowerCase();
  const matches = PROVIDERS.map(p=>{
    let score=0; const evidence=[];
    for(const [pattern,weight] of p.patterns){ if(lower.includes(pattern)){ score+=weight; evidence.push(pattern); } }
    return {...p,score,evidence};
  }).filter(x=>x.score>0).sort((a,b)=>b.score-a.score);

  if(!matches.length) return {detected:false,provider:'Não identificado',confidence:0,evidence:[],alternatives:[],note:'Nenhuma assinatura pública forte foi encontrada. O login pode usar autenticação própria ou ocultar o provedor no backend.'};
  const best=matches[0];
  return {detected:true,provider:best.name,providerId:best.id,confidence:confidence(best.score),score:best.score,evidence:best.evidence.slice(0,8),alternatives:matches.slice(1,4).map(x=>({provider:x.name,score:x.score,evidence:x.evidence.slice(0,4)})),note:'Resultado baseado somente em indícios públicos expostos pelo frontend.'};
}

async function fetchTarget(startUrl) {
  let current = startUrl;
  for(let i=0;i<=MAX_REDIRECTS;i++) {
    const controller = new AbortController();
    const timer = setTimeout(()=>controller.abort(), TIMEOUT_MS);
    let response;
    try {
      response = await fetch(current.toString(), {
        redirect:'manual',
        signal:controller.signal,
        headers:{'user-agent':'AuthTechnologyDetector/2.0 (+public-signature-analysis)','accept':'text/html,application/xhtml+xml,text/plain,application/javascript,*/*;q=0.5'}
      });
    } finally { clearTimeout(timer); }

    if ([301,302,303,307,308].includes(response.status)) {
      const loc=response.headers.get('location');
      if(!loc) return {response,finalUrl:current};
      current=parseTarget(new URL(loc,current).toString());
      continue;
    }
    return {response,finalUrl:current};
  }
  throw new Error('Redirecionamentos demais.');
}

async function analyze(request) {
  if(request.method!=='POST') return json({error:'Use POST.'},405);
  try {
    const data=await request.json().catch(()=>({}));
    if(!data.url) return json({error:'Informe uma URL.'},400);
    const target=parseTarget(String(data.url).trim());
    const {response,finalUrl}=await fetchTarget(target);
    const type=(response.headers.get('content-type')||'').toLowerCase();
    if(type && !type.includes('text/html') && !type.includes('text/plain') && !type.includes('javascript') && !type.includes('json')) return json({error:`Conteúdo não analisável: ${type}`},415);

    const reader=response.body?.getReader();
    const chunks=[]; let total=0;
    if(reader){
      while(true){
        const {done,value}=await reader.read(); if(done)break;
        const remaining=MAX_BYTES-total; if(remaining<=0)break;
        const chunk=value.byteLength>remaining?value.slice(0,remaining):value;
        chunks.push(chunk); total+=chunk.byteLength; if(total>=MAX_BYTES)break;
      }
      try{reader.cancel();}catch{}
    }
    const merged=new Uint8Array(total); let offset=0;
    for(const chunk of chunks){merged.set(chunk,offset);offset+=chunk.byteLength;}
    const body=new TextDecoder().decode(merged);
    const headers={server:response.headers.get('server'),'www-authenticate':response.headers.get('www-authenticate'),'x-powered-by':response.headers.get('x-powered-by')};
    const result=detect(body,finalUrl.toString(),headers);
    return json({ok:true,requestedUrl:target.toString(),finalUrl:finalUrl.toString(),httpStatus:response.status,analyzedBytes:total,...result});
  } catch(error) {
    const message=error?.name==='AbortError'?'A análise excedeu o tempo limite.':(error?.message||'Falha ao analisar a URL.');
    return json({error:message},400);
  }
}

export default {
  async fetch(request, env) {
    const url=new URL(request.url);
    if(url.pathname==='/api/analyze') return analyze(request);
    if(env.ASSETS) return env.ASSETS.fetch(request);
    return new Response('Auth Detector', {status:200});
  }
};
