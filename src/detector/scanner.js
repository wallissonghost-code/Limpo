import { inspectBehavior, inspectHeaders } from './signals.js';

const HTML_MAX=1_000_000;
const SCRIPT_SLICE=360_000;
const MAX_SCRIPTS=24;
const MAX_TOTAL=6_000_000;
const MAX_MAPS=8;
const TIMEOUT=7000;
const MAX_REDIRECTS=5;

export function isBlockedHostname(hostname){
  const h=hostname.toLowerCase().replace(/^\[|\]$/g,'');
  if(h==='localhost'||h.endsWith('.localhost')||h.endsWith('.local')||h==='0.0.0.0'||h==='::1')return true;
  const m=h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if(m){const p=m.slice(1).map(Number);if(p.some(n=>n>255))return true;return p[0]===10||p[0]===127||p[0]===0||p[0]>=224||(p[0]===169&&p[1]===254)||(p[0]===172&&p[1]>=16&&p[1]<=31)||(p[0]===192&&p[1]===168);}
  return h.startsWith('fc')||h.startsWith('fd')||h.startsWith('fe8')||h.startsWith('fe9')||h.startsWith('fea')||h.startsWith('feb');
}

export function parseTarget(raw){
  let u;try{u=new URL(raw);}catch{throw new Error('URL inválida.');}
  if(!['http:','https:'].includes(u.protocol))throw new Error('Use apenas HTTP ou HTTPS.');
  if(u.username||u.password)throw new Error('URL com credenciais não permitida.');
  if(isBlockedHostname(u.hostname))throw new Error('Destino local, privado ou reservado não permitido.');
  return u;
}

async function timedFetch(url,options={},timeout=TIMEOUT){
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),timeout);
  try{return await fetch(url,{...options,signal:controller.signal});}finally{clearTimeout(timer);}
}

async function fetchTarget(start){
  let current=start;const redirects=[];
  for(let i=0;i<=MAX_REDIRECTS;i++){
    const r=await timedFetch(current.toString(),{redirect:'manual',headers:{'user-agent':'LIMPO-Auth-Analyzer/5.0','accept':'text/html,application/xhtml+xml,text/plain,application/javascript,application/json,*/*;q=0.5'}});
    redirects.push({url:current.toString(),status:r.status,location:r.headers.get('location')});
    if([301,302,303,307,308].includes(r.status)){
      const loc=r.headers.get('location');if(!loc)return{response:r,finalUrl:current,redirects};
      current=parseTarget(new URL(loc,current).toString());continue;
    }
    return{response:r,finalUrl:current,redirects};
  }
  throw new Error('Redirecionamentos demais.');
}

async function readLimited(response,max){
  const reader=response.body?.getReader();if(!reader)return{text:'',bytes:0,truncated:false};
  const chunks=[];let total=0,truncated=false;
  while(true){const {done,value}=await reader.read();if(done)break;const remaining=max-total;if(remaining<=0){truncated=true;break;}const part=value.byteLength>remaining?value.slice(0,remaining):value;chunks.push(part);total+=part.byteLength;if(value.byteLength>remaining){truncated=true;break;}}
  try{await reader.cancel();}catch{}
  const merged=new Uint8Array(total);let off=0;for(const c of chunks){merged.set(c,off);off+=c.byteLength;}
  return{text:new TextDecoder().decode(merged),bytes:total,truncated};
}

function addScript(out,raw,base){
  try{
    const u=new URL(raw,base);
    if(!['http:','https:'].includes(u.protocol)||isBlockedHostname(u.hostname))return;
    if(!/\.m?js(?:$|\?)/i.test(u.pathname+u.search))return;
    out.add(u.toString());
  }catch{}
}

function assetsFromHtml(html,base){
  const out=new Set();
  const patterns=[
    /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi,
    /<link\b[^>]*\b(?:rel\s*=\s*["'][^"']*(?:modulepreload|preload)[^"']*["'][^>]*\bhref|href\s*=\s*["']([^"']+)["'][^>]*\brel\s*=\s*["'][^"']*(?:modulepreload|preload)[^"']*["'])/gi,
    /["']([^"']+\.m?js(?:\?[^"']*)?)["']/gi
  ];
  for(const re of patterns){let m;while((m=re.exec(html))&&out.size<80){const raw=m[1]||m[2];if(raw)addScript(out,raw,base);}}
  return[...out];
}

function dependencyScripts(text,base){
  const out=new Set();
  const patterns=[
    /\bimport\s+(?:[^"'`]*?\s+from\s*)?["'`]([^"'`]+)["'`]/gi,
    /\bexport\s+[^"'`]*?\s+from\s*["'`]([^"'`]+)["'`]/gi,
    /\bimport\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/gi,
    /\brequire\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/gi,
    /["'`]([^"'`\s]+(?:chunk|auth|login|session|identity|account|firebase|supabase|config|runtime|env)[^"'`\s]*\.m?js(?:\?[^"'`]*)?)["'`]/gi
  ];
  for(const re of patterns){let m;while((m=re.exec(text))&&out.size<80){const raw=m[1];if(!raw||/^(?:node:|data:|blob:)/i.test(raw))continue;addScript(out,raw,base);}}
  return[...out];
}

function scriptPriority(url,rootOrigin){
  let score=0;try{const u=new URL(url);if(u.origin===rootOrigin)score+=4;}catch{}
  if(/firebase|supabase|auth|login|identity|account|session|config|runtime|env/i.test(url))score+=8;
  if(/main|app|index|bootstrap/i.test(url))score+=2;
  return score;
}

function sourceMapUrls(text,scriptUrl){
  const out=new Set();const re=/[#@]\s*sourceMappingURL=([^\s*]+)/gi;let m;
  while((m=re.exec(text))&&out.size<4){try{out.add(new URL(m[1].trim(),scriptUrl).toString());}catch{}}
  try{out.add(scriptUrl.replace(/(\.m?js)(\?.*)?$/i,'$1.map$2'));}catch{}
  return[...out];
}

async function inspectMap(url,ctx){
  try{
    const target=parseTarget(url);const r=await timedFetch(target.toString(),{redirect:'follow',headers:{'user-agent':'LIMPO-Auth-Analyzer/5.0','accept':'application/json,text/plain,*/*;q=0.3'}},4500);
    if(!r.ok)return 0;const x=await readLimited(r,650_000);if(!x.text)return 0;
    let text=x.text;try{const j=JSON.parse(x.text);text=[...(j.sources||[]),...(j.sourcesContent||[])].join('\n');}catch{}
    ctx.corpus.push(text);inspectBehavior(ctx,text,`sourcemap:${target.pathname}`,target.toString());ctx.coverage.sourceMapsAnalyzed++;ctx.resources.sourceMaps.push(target.toString());return x.bytes;
  }catch{return 0;}
}

async function inspectScript(url,ctx){
  let target;try{target=parseTarget(url);}catch{return{bytes:0,partial:true,dependencies:[],maps:[]};}
  ctx.resources.scripts.push(target.toString());
  let r;try{r=await timedFetch(target.toString(),{redirect:'follow',headers:{'user-agent':'LIMPO-Auth-Analyzer/5.0','accept':'application/javascript,text/javascript,*/*;q=0.4','range':`bytes=0-${SCRIPT_SLICE-1}`}},5000);}catch{return{bytes:0,partial:true,dependencies:[],maps:[]};}
  const head=await readLimited(r,SCRIPT_SLICE);let text=head.text;let bytes=head.bytes;let partial=head.truncated||r.status===206;
  ctx.corpus.push(text);inspectBehavior(ctx,text,`bundle:${target.pathname}:head`,target.toString());
  const dependencies=dependencyScripts(text,target.toString());const maps=sourceMapUrls(text,target.toString());
  const range=r.headers.get('content-range')||'';const total=Number((range.match(/\/(\d+)$/)||[])[1]||r.headers.get('content-length')||0);

  if(total>SCRIPT_SLICE*2.2&&total<4_000_000){
    const start=Math.max(SCRIPT_SLICE,Math.floor(total/2-SCRIPT_SLICE/2));
    const end=Math.min(total-1,start+SCRIPT_SLICE-1);
    try{const midR=await timedFetch(target.toString(),{redirect:'follow',headers:{'user-agent':'LIMPO-Auth-Analyzer/5.0','range':`bytes=${start}-${end}`}},5000);const mid=await readLimited(midR,SCRIPT_SLICE);bytes+=mid.bytes;text=mid.text;ctx.corpus.push(text);inspectBehavior(ctx,text,`bundle:${target.pathname}:middle`,target.toString());for(const c of dependencyScripts(text,target.toString()))dependencies.push(c);for(const m of sourceMapUrls(text,target.toString()))maps.push(m);partial=true;}catch{}
  }

  if(total>SCRIPT_SLICE*1.6){
    try{const tailR=await timedFetch(target.toString(),{redirect:'follow',headers:{'user-agent':'LIMPO-Auth-Analyzer/5.0','range':`bytes=-${SCRIPT_SLICE}`}},5000);const tail=await readLimited(tailR,SCRIPT_SLICE);bytes+=tail.bytes;text=tail.text;ctx.corpus.push(text);inspectBehavior(ctx,text,`bundle:${target.pathname}:tail`,target.toString());for(const c of dependencyScripts(text,target.toString()))dependencies.push(c);for(const m of sourceMapUrls(text,target.toString()))maps.push(m);partial=true;}catch{}
  }
  return{bytes,partial,dependencies:[...new Set(dependencies)],maps:[...new Set(maps)]};
}

export async function scanTarget(rawUrl){
  const target=parseTarget(rawUrl);
  const ctx={
    requestedUrl:target.toString(),finalUrl:'',httpStatus:0,corpus:[],endpoints:new Set(),frameworks:new Set(),cookieNames:new Set(),_signalKeys:new Set(),signals:[],
    resources:{scripts:[],sourceMaps:[],dependencies:[]},
    authentication:{type:'unknown',protocol:'unknown',session:'unknown',token:'unknown'},
    flow:{login:false,logout:false,session:false,refresh:false,registration:false,passwordReset:false,mfa:false,sso:false},mfa:{methods:new Set()},
    coverage:{htmlBytes:0,scriptsDiscovered:0,scriptsAnalyzed:0,dependencyScripts:0,partialScripts:0,sourceMapsAnalyzed:0,endpointCandidates:0,redirects:0,totalBytes:0}
  };
  const {response,finalUrl,redirects}=await fetchTarget(target);ctx.finalUrl=finalUrl.toString();ctx.httpStatus=response.status;ctx.coverage.redirects=Math.max(0,redirects.length-1);
  for(const x of redirects)ctx.corpus.push(`${x.url} ${x.location||''}`);
  inspectHeaders(ctx,response.headers);
  const html=await readLimited(response,HTML_MAX);ctx.coverage.htmlBytes=html.bytes;ctx.coverage.totalBytes+=html.bytes;ctx.corpus.push(html.text);inspectBehavior(ctx,html.text,'html',finalUrl.toString());

  const rootOrigin=finalUrl.origin;
  const queue=assetsFromHtml(html.text,finalUrl.toString()).map(url=>({url,dependency:false}));ctx.coverage.scriptsDiscovered=queue.length;
  const seen=new Set();const maps=[];let totalScripts=0;
  while(queue.length&&seen.size<MAX_SCRIPTS&&totalScripts<MAX_TOTAL){
    queue.sort((a,b)=>scriptPriority(b.url,rootOrigin)-scriptPriority(a.url,rootOrigin));
    const item=queue.shift();const s=item.url;if(seen.has(s))continue;seen.add(s);
    const result=await inspectScript(s,ctx);ctx.coverage.scriptsAnalyzed++;if(item.dependency)ctx.coverage.dependencyScripts++;if(result.partial)ctx.coverage.partialScripts++;totalScripts+=result.bytes;ctx.coverage.totalBytes+=result.bytes;
    for(const dep of result.dependencies){if(!seen.has(dep)&&queue.length<100){queue.push({url:dep,dependency:true});ctx.resources.dependencies.push(dep);}}
    for(const m of result.maps)maps.push(m);
  }
  for(const map of [...new Set(maps)].slice(0,MAX_MAPS))ctx.coverage.totalBytes+=await inspectMap(map,ctx);
  ctx.resources.scripts=[...new Set(ctx.resources.scripts)];ctx.resources.dependencies=[...new Set(ctx.resources.dependencies)];ctx.resources.sourceMaps=[...new Set(ctx.resources.sourceMaps)];
  ctx.coverage.scriptsDiscovered=Math.max(ctx.coverage.scriptsDiscovered,seen.size+queue.length);
  ctx.coverage.endpointCandidates=ctx.endpoints.size;
  return ctx;
}