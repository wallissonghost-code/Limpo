import { parseTarget } from '../detector/scanner.js';

const TIMEOUT=5000;
const MAX_BYTES=320_000;
const BUNDLE_SLICE=240_000;
const BUNDLE_BUDGET=6_000_000;
const MAP_BYTES=800_000;
const MAX_MAPS=6;
const MAX_CONFIG_ENDPOINTS=12;

function decodeEscapes(text=''){
  return String(text)
    .replace(/\\u002[fF]/g,'/')
    .replace(/\\u003[aA]/g,':')
    .replace(/\\u0026/g,'&')
    .replace(/\\x2[fF]/g,'/')
    .replace(/\\\//g,'/')
    .replace(/\\"/g,'"')
    .replace(/\\'/g,"'");
}

function foldLiteralConcats(text){
  let out=text;
  for(let i=0;i<6;i++){
    const next=out.replace(/(["'`])([^"'`\n]{0,220})\1\s*\+\s*(["'`])([^"'`\n]{0,220})\3/g,(_,q,a,_q2,b)=>`${q}${a}${b}${q}`);
    if(next===out)break;
    out=next;
  }
  return out;
}

function extractConstants(text){
  const vars=new Map();
  const re=/(?:const|let|var)\s+([A-Za-z_$][\w$]{0,80})\s*=\s*(["'`])([^"'`\n]{0,300})\2/g;let m;
  while((m=re.exec(text))&&vars.size<2500)vars.set(m[1],m[3]);
  return vars;
}

function foldVariableConcats(text){
  const vars=extractConstants(text);
  if(!vars.size)return text;
  let synthetic='';
  const re=/(?:const|let|var)\s+([A-Za-z_$][\w$]{0,80})\s*=\s*([^;\n]{1,800})/g;let m;
  const evalExpr=expr=>{
    const parts=expr.split(/\s*\+\s*/);if(parts.length<2||parts.length>12)return null;let out='';
    for(const p0 of parts){const p=p0.trim();const q=p.match(/^(["'`])([^"'`]*)\1$/);if(q){out+=q[2];continue;}if(vars.has(p)){out+=vars.get(p);continue;}return null;}return out;
  };
  let rounds=0;
  while(rounds++<4){let changed=false;re.lastIndex=0;while((m=re.exec(text))){if(vars.has(m[1]))continue;const value=evalExpr(m[2]);if(value!=null&&value.length<=800){vars.set(m[1],value);changed=true;}}if(!changed)break;}
  for(const [k,v] of vars)synthetic+=`\n${k}="${v.replace(/"/g,'\\"')}";`;
  return text+synthetic;
}

function normalize(text=''){
  return foldVariableConcats(foldLiteralConcats(decodeEscapes(text)));
}

function first(text,patterns){for(const re of patterns){const m=text.match(re);if(m?.[1])return m[1];}return null;}

function firebaseApiKey(text){
  const explicit=first(text,[
    /[?&]key=([A-Za-z0-9_\-]{20,})/i,
    /\b(?:apiKey|firebaseApiKey|FIREBASE_API_KEY|NEXT_PUBLIC_FIREBASE_API_KEY|VITE_FIREBASE_API_KEY|REACT_APP_FIREBASE_API_KEY|NUXT_PUBLIC_FIREBASE_API_KEY|PUBLIC_FIREBASE_API_KEY)\b\s*[:=]\s*["'`]([A-Za-z0-9_\-]{20,})["'`]/i,
    /["'](?:apiKey|firebaseApiKey|FIREBASE_API_KEY|NEXT_PUBLIC_FIREBASE_API_KEY|VITE_FIREBASE_API_KEY|REACT_APP_FIREBASE_API_KEY|PUBLIC_FIREBASE_API_KEY)["']\s*:\s*["']([A-Za-z0-9_\-]{20,})["']/i,
    /accounts:signInWithPassword[^\n]{0,1400}?[?&]key=([A-Za-z0-9_\-]{20,})/i,
    /identitytoolkit\.googleapis\.com[^\n]{0,1400}?[?&]key=([A-Za-z0-9_\-]{20,})/i
  ]);
  if(explicit)return explicit;

  const candidates=[...new Set(text.match(/AIza[0-9A-Za-z_\-]{30,}/g)||[])];
  if(candidates.length===1)return candidates[0];
  for(const key of candidates){const i=text.indexOf(key);const around=text.slice(Math.max(0,i-3500),Math.min(text.length,i+3500));if(/firebase|initializeApp|getAuth|firebaseapp\.com|identitytoolkit|securetoken|authDomain|projectId|signInWithEmailAndPassword|signInWithPassword/i.test(around))return key;}
  return null;
}

function mergeFirebase(base={},found={},source){return{apiKey:base.apiKey||found.apiKey||null,authDomain:base.authDomain||found.authDomain||null,projectId:base.projectId||found.projectId||null,passwordFlow:Boolean(base.passwordFlow||found.passwordFlow),source:(base.apiKey?base.source:null)||(found.apiKey?source||found.source:null)||base.source||found.source||'none'};}

function firebaseConfig(corpus){
  const text=normalize(corpus);const apiKey=firebaseApiKey(text);
  let authDomain=first(text,[/\b(?:authDomain|FIREBASE_AUTH_DOMAIN|NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN|VITE_FIREBASE_AUTH_DOMAIN|REACT_APP_FIREBASE_AUTH_DOMAIN|PUBLIC_FIREBASE_AUTH_DOMAIN)\b\s*[:=]\s*["'`]([^"'`\s]+)["'`]/i,/["']authDomain["']\s*:\s*["']([^"']+)["']/i,/https?:\/\/([a-z0-9-]+\.firebaseapp\.com)/i,/\b([a-z0-9-]+\.firebaseapp\.com)\b/i]);
  let projectId=first(text,[/\b(?:projectId|FIREBASE_PROJECT_ID|NEXT_PUBLIC_FIREBASE_PROJECT_ID|VITE_FIREBASE_PROJECT_ID|REACT_APP_FIREBASE_PROJECT_ID|PUBLIC_FIREBASE_PROJECT_ID)\b\s*[:=]\s*["'`]([^"'`\s]+)["'`]/i,/["']projectId["']\s*:\s*["']([^"']+)["']/i,/https?:\/\/([a-z0-9-]+)\.firebaseio\.com/i,/https?:\/\/([a-z0-9-]+)\.firebasedatabase\.app/i,/https?:\/\/([a-z0-9-]+)\.firebaseapp\.com/i]);
  if(!projectId&&authDomain?.endsWith('.firebaseapp.com'))projectId=authDomain.slice(0,-'.firebaseapp.com'.length);if(!authDomain&&projectId)authDomain=`${projectId}.firebaseapp.com`;
  const passwordFlow=/signInWithEmailAndPassword|accounts:signInWithPassword|EMAIL_PASSWORD_SIGN_IN|signInWithPassword|passwordSignIn/i.test(text);
  return{apiKey,authDomain,projectId,passwordFlow,source:apiKey?'corpus':'none'};
}

function supabaseConfig(corpus){
  const text=normalize(corpus);const url=first(text,[/\b(?:supabaseUrl|SUPABASE_URL|NEXT_PUBLIC_SUPABASE_URL|VITE_SUPABASE_URL|REACT_APP_SUPABASE_URL)\s*[:=]\s*["'`](https:\/\/[^"'`\s]+)["'`]/i,/(https:\/\/[a-z0-9-]+\.supabase\.co)/i]);
  const anonKey=first(text,[/\b(?:supabaseAnonKey|SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_ANON_KEY|VITE_SUPABASE_ANON_KEY|REACT_APP_SUPABASE_ANON_KEY)\s*[:=]\s*["'`]([^"'`\s]{40,})["'`]/i,/\b(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b/]);
  return{url,anonKey,passwordFlow:/signInWithPassword|grant_type=password/i.test(text),source:(url||anonKey)?'corpus':'none'};
}

async function readLimited(response,max=MAX_BYTES){const reader=response.body?.getReader();if(!reader)return'';const chunks=[];let total=0;while(true){const{done,value}=await reader.read();if(done)break;const left=max-total;if(left<=0)break;const part=value.byteLength>left?value.slice(0,left):value;chunks.push(part);total+=part.byteLength;if(value.byteLength>left)break;}try{await reader.cancel();}catch{}const out=new Uint8Array(total);let off=0;for(const c of chunks){out.set(c,off);off+=c.byteLength;}return new TextDecoder().decode(out);}

async function safeFetch(url,headers={}){let target;try{target=parseTarget(url);}catch{return null;}if(target.protocol!=='https:')return null;const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),TIMEOUT);try{return await fetch(target.toString(),{redirect:'follow',signal:controller.signal,headers:{'user-agent':'LIMPO-Auth-Engine/2.0',...headers}});}catch{return null;}finally{clearTimeout(timer);}}
async function fetchPublicConfig(url,max=MAX_BYTES){const r=await safeFetch(url,{'accept':'application/json,text/javascript,text/plain,*/*;q=0.4'});if(!r?.ok)return null;return(await readLimited(r,max))||null;}

async function enrichFirebaseFromHost(initial,ctx){if(initial.apiKey)return initial;const hosts=[];try{hosts.push(new URL(ctx?.finalUrl||ctx?.requestedUrl).hostname);}catch{}if(initial.authDomain)hosts.push(initial.authDomain);if(initial.projectId)hosts.push(`${initial.projectId}.firebaseapp.com`);let current={...initial};for(const host of [...new Set(hosts)].slice(0,3))for(const path of ['/__/firebase/init.json','/__/firebase/init.js']){const text=await fetchPublicConfig(`https://${host}${path}`);if(!text)continue;current=mergeFirebase(current,firebaseConfig(text),'firebase-runtime-probe');if(current.apiKey)return current;}return current;}
async function bundleTotal(url){const r=await safeFetch(url,{'accept':'application/javascript,text/javascript,*/*;q=0.4','range':'bytes=0-0'});if(!r?.ok&&r?.status!==206)return 0;const cr=r.headers.get('content-range')||'';const total=Number((cr.match(/\/(\d+)$/)||[])[1]||r.headers.get('content-length')||0);try{await r.body?.cancel();}catch{}return total;}
async function fetchBundleRange(url,start,end){const r=await safeFetch(url,{'accept':'application/javascript,text/javascript,*/*;q=0.4','range':`bytes=${start}-${end}`});if(!r?.ok&&r?.status!==206)return'';return await readLimited(r,BUNDLE_SLICE);}
function orderedScripts(ctx){const scripts=[...new Set(ctx?.resources?.scripts||[])];const score=x=>(/auth|login|identity|account|firebase|config|runtime/i.test(x)?3:0)+(/main|app|index/i.test(x)?1:0);return scripts.sort((a,b)=>score(b)-score(a)).slice(0,14);}
async function enrichFirebaseFromBundles(initial,ctx){if(initial.apiKey)return initial;let spent=0,current={...initial};for(const url of orderedScripts(ctx)){const total=await bundleTotal(url);if(!total)continue;let starts=[];if(total<=2_000_000){for(let s=0;s<total;s+=BUNDLE_SLICE)starts.push(s);}else{const slots=10;for(let i=0;i<slots;i++)starts.push(Math.max(0,Math.floor((total-BUNDLE_SLICE)*(i/(slots-1)))));}for(const start of [...new Set(starts)]){if(spent>=BUNDLE_BUDGET)return current;const end=Math.min(total-1,start+BUNDLE_SLICE-1);const text=await fetchBundleRange(url,start,end);spent+=Math.max(0,end-start+1);if(!text)continue;current=mergeFirebase(current,firebaseConfig(text),'targeted-bundle-scan');if(current.apiKey)return current;}}return current;}
function candidateMapUrls(ctx){const out=new Set(ctx?.resources?.sourceMaps||[]);for(const script of ctx?.resources?.scripts||[])try{const u=new URL(script);if(/\.m?js(?:$|\?)/i.test(u.pathname+u.search))out.add(script.replace(/(\.m?js)(\?.*)?$/i,'$1.map$2'));}catch{}return[...out].slice(0,MAX_MAPS);}
async function enrichFirebaseFromSourceMaps(initial,ctx){if(initial.apiKey)return initial;let current={...initial};for(const url of candidateMapUrls(ctx)){const text=await fetchPublicConfig(url,MAP_BYTES);if(!text)continue;let searchable=text;try{const map=JSON.parse(text);searchable=[...(map.sources||[]),...(map.sourcesContent||[])].join('\n');}catch{}current=mergeFirebase(current,firebaseConfig(searchable),'source-map');if(current.apiKey)return current;}return current;}
function configEndpointCandidates(ctx){const out=new Set();const corpus=normalize((ctx?.corpus||[]).join('\n'));const add=raw=>{try{const u=parseTarget(String(raw));if(u.protocol==='https:'&&!/login|signin|password|session|token/i.test(u.pathname))out.add(u.toString());}catch{}};for(const raw of ctx?.endpoints||[]){try{const u=new URL(raw);if(/(?:^|\/)(?:config|configuration|runtime|settings|environment|env|firebase|public-config|app-config)(?:[./?_-]|$)|\.json(?:\?|$)/i.test(u.pathname+u.search))add(u.toString());}catch{}}const abs=/https:\/\/[^"'`\s<>]+/gi;let m;while((m=abs.exec(corpus))&&out.size<50)if(/config|env|settings|runtime|firebase|\.json/i.test(m[0]))add(m[0]);try{const base=new URL(ctx?.finalUrl||ctx?.requestedUrl);const rel=/["'`]([^"'`\s]{1,180}(?:config|env|settings|runtime|firebase)[^"'`\s]{0,120}(?:\.json|\.js)?(?:\?[^"'`]*)?)["'`]/gi;while((m=rel.exec(corpus))&&out.size<50)try{add(new URL(m[1],base).toString());}catch{}}catch{}return[...out].slice(0,MAX_CONFIG_ENDPOINTS);}
async function enrichFirebaseFromConfigEndpoints(initial,ctx){if(initial.apiKey)return initial;let current={...initial};for(const url of configEndpointCandidates(ctx)){const text=await fetchPublicConfig(url);if(!text)continue;current=mergeFirebase(current,firebaseConfig(text),'public-config-endpoint');if(current.apiKey)return current;}return current;}

export function extractRuntimeConfig(providerId,ctx){const corpus=(ctx?.corpus||[]).join('\n');if(providerId==='firebase')return{firebase:firebaseConfig(corpus)};if(providerId==='supabase')return{supabase:supabaseConfig(corpus)};return{};}
export async function reconstructRuntimeConfig(providerId,ctx){const runtime=extractRuntimeConfig(providerId,ctx);if(providerId==='firebase'&&runtime.firebase){runtime.firebase=await enrichFirebaseFromHost(runtime.firebase,ctx);runtime.firebase=await enrichFirebaseFromConfigEndpoints(runtime.firebase,ctx);runtime.firebase=await enrichFirebaseFromBundles(runtime.firebase,ctx);runtime.firebase=await enrichFirebaseFromSourceMaps(runtime.firebase,ctx);runtime.firebase=await enrichFirebaseFromHost(runtime.firebase,ctx);}return runtime;}
export function publicRuntimeSummary(runtime={}){const out={};if(runtime.firebase)out.firebase={apiKey:Boolean(runtime.firebase.apiKey),authDomain:Boolean(runtime.firebase.authDomain),projectId:Boolean(runtime.firebase.projectId),passwordFlow:Boolean(runtime.firebase.passwordFlow),source:runtime.firebase.source||'none'};if(runtime.supabase)out.supabase={url:Boolean(runtime.supabase.url),anonKey:Boolean(runtime.supabase.anonKey),passwordFlow:Boolean(runtime.supabase.passwordFlow),source:runtime.supabase.source||'none'};return out;}
