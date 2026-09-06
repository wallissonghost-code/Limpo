import { parseTarget } from '../detector/scanner.js';

const TIMEOUT=4500;
const MAX_BYTES=220_000;
const BUNDLE_SLICE=180_000;
const BUNDLE_BUDGET=2_400_000;

function normalize(text=''){
  return String(text)
    .replace(/\\u002[fF]/g,'/')
    .replace(/\\u003[aA]/g,':')
    .replace(/\\u0026/g,'&')
    .replace(/\\\//g,'/')
    .replace(/\\"/g,'"')
    .replace(/\\'/g,"'");
}

function first(text,patterns){
  for(const re of patterns){const m=text.match(re);if(m?.[1])return m[1];}
  return null;
}

function firebaseApiKey(text){
  const explicit=first(text,[
    /[?&]key=([A-Za-z0-9_\-]{20,})/i,
    /\b(?:apiKey|firebaseApiKey|FIREBASE_API_KEY|NEXT_PUBLIC_FIREBASE_API_KEY|VITE_FIREBASE_API_KEY|REACT_APP_FIREBASE_API_KEY|NUXT_PUBLIC_FIREBASE_API_KEY)\b\s*[:=]\s*["'`]([A-Za-z0-9_\-]{20,})["'`]/i,
    /["'](?:apiKey|firebaseApiKey|FIREBASE_API_KEY|NEXT_PUBLIC_FIREBASE_API_KEY|VITE_FIREBASE_API_KEY|REACT_APP_FIREBASE_API_KEY)["']\s*:\s*["']([A-Za-z0-9_\-]{20,})["']/i
  ]);
  if(explicit)return explicit;
  const re=/AIza[0-9A-Za-z_\-]{30,}/g;let m;
  while((m=re.exec(text))){
    const around=text.slice(Math.max(0,m.index-1200),Math.min(text.length,m.index+1200));
    if(/firebase|initializeApp|firebaseapp\.com|identitytoolkit|securetoken|authDomain|projectId|signInWithEmailAndPassword/i.test(around))return m[0];
  }
  return null;
}

function firebaseConfig(corpus){
  const text=normalize(corpus);
  const apiKey=firebaseApiKey(text);
  let authDomain=first(text,[
    /\b(?:authDomain|FIREBASE_AUTH_DOMAIN|NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN|VITE_FIREBASE_AUTH_DOMAIN|REACT_APP_FIREBASE_AUTH_DOMAIN)\b\s*[:=]\s*["'`]([^"'`\s]+)["'`]/i,
    /["']authDomain["']\s*:\s*["']([^"']+)["']/i,
    /https?:\/\/([a-z0-9-]+\.firebaseapp\.com)/i,
    /\b([a-z0-9-]+\.firebaseapp\.com)\b/i
  ]);
  let projectId=first(text,[
    /\b(?:projectId|FIREBASE_PROJECT_ID|NEXT_PUBLIC_FIREBASE_PROJECT_ID|VITE_FIREBASE_PROJECT_ID|REACT_APP_FIREBASE_PROJECT_ID)\b\s*[:=]\s*["'`]([^"'`\s]+)["'`]/i,
    /["']projectId["']\s*:\s*["']([^"']+)["']/i,
    /https?:\/\/([a-z0-9-]+)\.firebaseio\.com/i,
    /https?:\/\/([a-z0-9-]+)\.firebasedatabase\.app/i
  ]);
  if(!projectId&&authDomain?.endsWith('.firebaseapp.com'))projectId=authDomain.slice(0,-'.firebaseapp.com'.length);
  if(!authDomain&&projectId)authDomain=`${projectId}.firebaseapp.com`;
  const passwordFlow=/signInWithEmailAndPassword|accounts:signInWithPassword|EMAIL_PASSWORD_SIGN_IN/i.test(text);
  return {apiKey,authDomain,projectId,passwordFlow,source:apiKey?'corpus':'none'};
}

function supabaseConfig(corpus){
  const text=normalize(corpus);
  const url=first(text,[
    /\b(?:supabaseUrl|SUPABASE_URL|NEXT_PUBLIC_SUPABASE_URL|VITE_SUPABASE_URL|REACT_APP_SUPABASE_URL)\s*[:=]\s*["'`](https:\/\/[^"'`\s]+)["'`]/i,
    /(https:\/\/[a-z0-9-]+\.supabase\.co)/i
  ]);
  const anonKey=first(text,[
    /\b(?:supabaseAnonKey|SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_ANON_KEY|VITE_SUPABASE_ANON_KEY|REACT_APP_SUPABASE_ANON_KEY)\s*[:=]\s*["'`]([^"'`\s]{40,})["'`]/i
  ]);
  return {url,anonKey,passwordFlow:/signInWithPassword|grant_type=password/i.test(text),source:(url||anonKey)?'corpus':'none'};
}

async function readLimited(response,max=MAX_BYTES){
  const reader=response.body?.getReader();if(!reader)return'';
  const chunks=[];let total=0;
  while(true){const {done,value}=await reader.read();if(done)break;const left=max-total;if(left<=0)break;const part=value.byteLength>left?value.slice(0,left):value;chunks.push(part);total+=part.byteLength;if(value.byteLength>left)break;}
  try{await reader.cancel();}catch{}
  const out=new Uint8Array(total);let off=0;for(const c of chunks){out.set(c,off);off+=c.byteLength;}
  return new TextDecoder().decode(out);
}

async function safeFetch(url,headers={}){
  let target;try{target=parseTarget(url);}catch{return null;}
  if(target.protocol!=='https:')return null;
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),TIMEOUT);
  try{return await fetch(target.toString(),{redirect:'follow',signal:controller.signal,headers:{'user-agent':'LIMPO-Auth-Engine/1.2',...headers}});}catch{return null;}finally{clearTimeout(timer);}
}

async function fetchPublicConfig(url){
  const r=await safeFetch(url,{'accept':'application/json,text/javascript,text/plain,*/*;q=0.4'});
  if(!r?.ok)return null;const text=await readLimited(r);return text||null;
}

async function enrichFirebaseFromHost(initial){
  if(initial.apiKey)return initial;
  const hosts=[];
  if(initial.authDomain)hosts.push(initial.authDomain);
  if(initial.projectId)hosts.push(`${initial.projectId}.firebaseapp.com`);
  for(const host of [...new Set(hosts)].slice(0,2)){
    for(const path of ['/__/firebase/init.json','/__/firebase/init.js']){
      const text=await fetchPublicConfig(`https://${host}${path}`);if(!text)continue;
      const found=firebaseConfig(text);
      if(found.apiKey)return {apiKey:found.apiKey,authDomain:found.authDomain||initial.authDomain,projectId:found.projectId||initial.projectId,passwordFlow:initial.passwordFlow||found.passwordFlow,source:'firebase-runtime-probe'};
    }
  }
  return initial;
}

async function bundleTotal(url){
  const r=await safeFetch(url,{'accept':'application/javascript,text/javascript,*/*;q=0.4','range':'bytes=0-0'});if(!r?.ok&&r?.status!==206)return 0;
  const cr=r.headers.get('content-range')||'';const total=Number((cr.match(/\/(\d+)$/)||[])[1]||r.headers.get('content-length')||0);
  try{await r.body?.cancel();}catch{}
  return total;
}

async function fetchBundleRange(url,start,end){
  const r=await safeFetch(url,{'accept':'application/javascript,text/javascript,*/*;q=0.4','range':`bytes=${start}-${end}`});
  if(!r?.ok&&r?.status!==206)return'';return await readLimited(r,BUNDLE_SLICE);
}

async function enrichFirebaseFromBundles(initial,ctx){
  if(initial.apiKey)return initial;
  const scripts=[...new Set(ctx?.resources?.scripts||[])].slice(0,8);let spent=0;
  for(const url of scripts){
    const total=await bundleTotal(url);if(!total)continue;
    const starts=total<=BUNDLE_SLICE*3
      ? [0]
      : [0,Math.floor(total*.2),Math.floor(total*.4),Math.floor(total*.6),Math.max(0,total-BUNDLE_SLICE)];
    for(const rawStart of [...new Set(starts)]){
      if(spent+BUNDLE_SLICE>BUNDLE_BUDGET)return initial;
      const start=Math.max(0,Math.min(rawStart,total-1));const end=Math.min(total-1,start+BUNDLE_SLICE-1);
      const text=await fetchBundleRange(url,start,end);spent+=BUNDLE_SLICE;if(!text)continue;
      const found=firebaseConfig(text);
      if(found.apiKey)return {apiKey:found.apiKey,authDomain:found.authDomain||initial.authDomain,projectId:found.projectId||initial.projectId,passwordFlow:initial.passwordFlow||found.passwordFlow,source:'targeted-bundle-scan'};
      if(!initial.authDomain&&found.authDomain)initial.authDomain=found.authDomain;
      if(!initial.projectId&&found.projectId)initial.projectId=found.projectId;
    }
  }
  return initial;
}

export function extractRuntimeConfig(providerId,ctx){
  const corpus=(ctx?.corpus||[]).join('\n');
  if(providerId==='firebase')return {firebase:firebaseConfig(corpus)};
  if(providerId==='supabase')return {supabase:supabaseConfig(corpus)};
  return {};
}

export async function reconstructRuntimeConfig(providerId,ctx){
  const runtime=extractRuntimeConfig(providerId,ctx);
  if(providerId==='firebase'&&runtime.firebase){
    runtime.firebase=await enrichFirebaseFromHost(runtime.firebase);
    runtime.firebase=await enrichFirebaseFromBundles(runtime.firebase,ctx);
    runtime.firebase=await enrichFirebaseFromHost(runtime.firebase);
  }
  return runtime;
}

export function publicRuntimeSummary(runtime={}){
  const out={};
  if(runtime.firebase)out.firebase={apiKey:Boolean(runtime.firebase.apiKey),authDomain:Boolean(runtime.firebase.authDomain),projectId:Boolean(runtime.firebase.projectId),passwordFlow:Boolean(runtime.firebase.passwordFlow),source:runtime.firebase.source||'none'};
  if(runtime.supabase)out.supabase={url:Boolean(runtime.supabase.url),anonKey:Boolean(runtime.supabase.anonKey),passwordFlow:Boolean(runtime.supabase.passwordFlow),source:runtime.supabase.source||'none'};
  return out;
}
