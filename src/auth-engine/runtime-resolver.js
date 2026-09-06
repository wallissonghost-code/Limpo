const MAX_CORPUS=6_000_000;

function textOf(ctx){return String((ctx?.corpus||[]).join('\n')).slice(0,MAX_CORPUS);}
function clean(v=''){return String(v).replace(/\\u002[fF]/g,'/').replace(/\\u003[aA]/g,':').replace(/\\\//g,'/').replace(/\\"/g,'"').replace(/\\'/g,"'");}

function stringBindings(text){
  const map=new Map();let m;
  const direct=/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(["'`])([^"'`\n]{0,500})\2\s*;?/g;
  while((m=direct.exec(text))&&map.size<800)map.set(m[1],clean(m[3]));
  for(let pass=0;pass<4;pass++){
    let changed=false;
    const concat=/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,700})[;\n]/g;
    while((m=concat.exec(text))&&map.size<1200){
      const parts=[...m[2].matchAll(/(["'`])([^"'`\n]*)\1|\b([A-Za-z_$][\w$]*)\b/g)];
      if(!parts.length||!/\+/.test(m[2]))continue;
      let value='',ok=true;
      for(const p of parts){if(p[2]!=null)value+=clean(p[2]);else if(map.has(p[3]))value+=map.get(p[3]);else if(!['const','let','var','true','false','null','undefined'].includes(p[3])){ok=false;break;}}
      if(ok&&value&&map.get(m[1])!==value){map.set(m[1],value);changed=true;}
    }
    if(!changed)break;
  }
  return map;
}

function resolveValue(raw,bindings){
  const s=String(raw||'').trim();
  const q=s.match(/^(["'`])([\s\S]*)\1$/);if(q)return clean(q[2]);
  if(bindings.has(s))return bindings.get(s);
  const env=s.match(/(?:process\.env\.|import\.meta\.env\.|window\.__ENV__\.?|globalThis\.__ENV__\.?)([A-Za-z0-9_$]+)/);if(env&&bindings.has(env[1]))return bindings.get(env[1]);
  return null;
}

function objectBodies(text){
  const out=new Map();let m;
  const re=/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\{([\s\S]{0,5000}?)\}\s*;?/g;
  while((m=re.exec(text))&&out.size<300)out.set(m[1],m[2]);
  return out;
}

function field(body,name,bindings){
  if(!body)return null;
  const re=new RegExp('(?:["\\\']?'+name+'["\\\']?)\\s*:\\s*([^,}\\n]{1,700})','i');
  const m=String(body).match(re);return m?resolveValue(m[1],bindings):null;
}

function firebaseResolved(text,bindings,objects){
  const candidates=[];let m;
  const call=/\b(?:firebase\.)?initializeApp\s*\(\s*([A-Za-z_$][\w$]*|\{[\s\S]{0,5000}?\})\s*\)/g;
  while((m=call.exec(text))&&candidates.length<20){
    const raw=m[1];const body=raw.startsWith('{')?raw.slice(1,-1):objects.get(raw);if(body)candidates.push(body);
  }
  for(const body of objects.values())if(/apiKey|authDomain|projectId/i.test(body))candidates.push(body);
  for(const body of candidates){
    const apiKey=field(body,'apiKey',bindings);const authDomain=field(body,'authDomain',bindings);const projectId=field(body,'projectId',bindings);
    if(apiKey||authDomain||projectId)return{apiKey,authDomain,projectId,source:'binding-trace'};
  }
  return{};
}

function supabaseResolved(text,bindings){
  let m;const re=/(?:createClient|createBrowserClient|createServerClient)\s*\(\s*([^,\n]{1,500})\s*,\s*([^,)\n]{1,1000})/g;
  while((m=re.exec(text))){const url=resolveValue(m[1],bindings);const anonKey=resolveValue(m[2],bindings);if(url||anonKey)return{url,anonKey,source:'binding-trace'};}
  return{};
}

function mergeFirebase(runtime,found){
  const base=runtime?.firebase||{};return{...runtime,firebase:{...base,apiKey:base.apiKey||found.apiKey||null,authDomain:base.authDomain||found.authDomain||null,projectId:base.projectId||found.projectId||null,source:base.apiKey?base.source:(found.apiKey?found.source:base.source)}};
}
function mergeSupabase(runtime,found){
  const base=runtime?.supabase||{};return{...runtime,supabase:{...base,url:base.url||found.url||null,anonKey:base.anonKey||found.anonKey||null,source:(base.url&&base.anonKey)?base.source:((found.url||found.anonKey)?found.source:base.source)}};
}

export function resolveRuntimeBindings(providerId,ctx,runtime={}){
  const text=textOf(ctx);if(!text)return runtime;const bindings=stringBindings(text);const objects=objectBodies(text);
  if(providerId==='firebase')return mergeFirebase(runtime,firebaseResolved(text,bindings,objects));
  if(providerId==='supabase')return mergeSupabase(runtime,supabaseResolved(text,bindings));
  return runtime;
}
