import { inspectBehavior, inspectHeaders } from './signals.js';

const HTML_MAX=1_000_000;
const SCRIPT_SLICE=360_000;
const MAX_SCRIPTS=12;
const MAX_TOTAL=3_600_000;
const MAX_MAPS=4;
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
    const r=await timedFetch(current.toString(),{redirect:'manual',headers:{'user-agent':'LIMPO-Auth-Analyzer/4.2','accept':'text/html,application/xhtml+xml,text/plain,application/javascript,application/json,*/*;q=0.5'}});
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

function assetsFromHtml(html,base){
  const out=new Set();const patterns=[/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi,/<link\b[^>]*\bhref\s*=\s*["']([^"']+\.m?js(?:\?[^"']*)?)["']/gi,/["']([^"']+\.m?js(?:\?[^"']*)?)["']/gi];
  for(const re of patterns){let m;while((m=re.exec(html))&&out.size<40){try{const u=new URL(m[1],base);if(!isBlockedHostname(u.hostname))out.add(u.toString());}catch{}}}
  return[...out];
}

function lazyChunks(text,base){
  const out=new Set();const re=/["'`]([^"'`\s]+(?:chunk|auth|login|session|identity|account)[^"'`\s]*\.m?js(?:\?[^"'`]*)?)["'`]/gi;let m;
  while((m=re.exec(text))&&out.size<30){try{const u=new URL(m[1],base);if(!isBlockedHostname(u.hostname))out.add(u.toString());}catch{}}
  return[...out];
}

function sourceMapUrls(text,scriptUrl){
  const out=new Set();const re=/[#@]\s*sourceMappingURL=([^\s*]+)/gi;let m;
  while((m=re.exec(text))&&out.size<3){try{out.add(new URL(m[1].trim(),scriptUrl).toString());}catch{}}
  try{out.add(new URL(new URL(scriptUrl).pathname+'.map',scriptUrl).toString());}catch{}
  return[...out];
}

async function inspectMap(url,ctx){
  try{
    const target=parseTarget(url);const r=await timedFetch(target.toString(),{redirect:'follow',headers:{'user-agent':'LIMPO-Auth-Analyzer/4.2','accept':'application/json,text/plain,*/*;q=0.3'}},4500);
    if(!r.ok)return 0;const x=await readLimited(r,500_000);if(!x.text)return 0;
    let text=x.text;try{const j=JSON.parse(x.text);text=[...(j.sources||[]),...(j.sourcesContent||[])].join('\n');}catch{}
    ctx.corpus.push(text);inspectBehavior(ctx,text,`sourcemap:${target.pathname}`,target.toString());ctx.coverage.sourceMapsAnalyzed++;ctx.resources.sourceMaps.push(target.toString());return x.bytes;
  }catch{return 0;}
}

async function inspectScript(url,ctx){
  let target;try{target=parseTarget(url);}catch{return{bytes:0,partial:true,chunks:[],maps:[]};}
  ctx.resources.scripts.push(target.toString());
  let r;try{r=await timedFetch(target.toString(),{redirect:'follow',headers:{'user-agent':'LIMPO-Auth-Analyzer/4.2','accept':'application/javascript,text/javascript,*/*;q=0.4','range':`bytes=0-${SCRIPT_SLICE-1}`}},5000);}catch{return{bytes:0,partial:true,chunks:[],maps:[]};}
  const head=await readLimited(r,SCRIPT_SLICE);let text=head.text;let bytes=head.bytes;let partial=head.truncated||r.status===206;
  ctx.corpus.push(text);inspectBehavior(ctx,text,`bundle:${target.pathname}:head`,target.toString());
  const chunks=lazyChunks(text,target.toString());const maps=sourceMapUrls(text,target.toString());
  const range=r.headers.get('content-range')||'';const total=Number((range.match(/\/(\d+)$/)||[])[1]||r.headers.get('content-length')||0);

  // Sample the middle of large bundles too. Firebase/Supabase runtime config is often
  // emitted between the bootstrap and sourceMappingURL tail of minified bundles.
  if(total>SCRIPT_SLICE*2.2&&total<3_000_000){
    const start=Math.max(SCRIPT_SLICE,Math.floor(total/2-SCRIPT_SLICE/2));
    const end=Math.min(total-1,start+SCRIPT_SLICE-1);
    try{const midR=await timedFetch(target.toString(),{redirect:'follow',headers:{'user-agent':'LIMPO-Auth-Analyzer/4.2','range':`bytes=${start}-${end}`}},5000);const mid=await readLimited(midR,SCRIPT_SLICE);bytes+=mid.bytes;text=mid.text;ctx.corpus.push(text);inspectBehavior(ctx,text,`bundle:${target.pathname}:middle`,target.toString());for(const c of lazyChunks(text,target.toString()))chunks.push(c);for(const m of sourceMapUrls(text,target.toString()))maps.push(m);partial=true;}catch{}
  }

  if(total>SCRIPT_SLICE*1.6){
    try{const tailR=await timedFetch(target.toString(),{redirect:'follow',headers:{'user-agent':'LIMPO-Auth-Analyzer/4.2','range':`bytes=-${SCRIPT_SLICE}`}},5000);const tail=await readLimited(tailR,SCRIPT_SLICE);bytes+=tail.bytes;text=tail.text;ctx.corpus.push(text);inspectBehavior(ctx,text,`bundle:${target.pathname}:tail`,target.toString());for(const c of lazyChunks(text,target.toString()))chunks.push(c);for(const m of sourceMapUrls(text,target.toString()))maps.push(m);partial=true;}catch{}
  }
  return{bytes,partial,chunks:[...new Set(chunks)],maps:[...new Set(maps)]};
}

export async function scanTarget(rawUrl){
  const target=parseTarget(rawUrl);
  const ctx={
    requestedUrl:target.toString(),finalUrl:'',httpStatus:0,corpus:[],endpoints:new Set(),frameworks:new Set(),cookieNames:new Set(),_signalKeys:new Set(),signals:[],
    resources:{scripts:[],sourceMaps:[]},
    authentication:{type:'unknown',protocol:'unknown',session:'unknown',token:'unknown'},
    flow:{login:false,logout:false,session:false,refresh:false,registration:false,passwordReset:false,mfa:false,sso:false},mfa:{methods:new Set()},
    coverage:{htmlBytes:0,scriptsDiscovered:0,scriptsAnalyzed:0,partialScripts:0,sourceMapsAnalyzed:0,endpointCandidates:0,redirects:0,totalBytes:0}
  };
  const {response,finalUrl,redirects}=await fetchTarget(target);ctx.finalUrl=finalUrl.toString();ctx.httpStatus=response.status;ctx.coverage.redirects=Math.max(0,redirects.length-1);
  for(const x of redirects){ctx.corpus.push(`${x.url} ${x.location||''}`);}
  inspectHeaders(ctx,response.headers);
  const html=await readLimited(response,HTML_MAX);ctx.coverage.htmlBytes=html.bytes;ctx.coverage.totalBytes+=html.bytes;ctx.corpus.push(html.text);inspectBehavior(ctx,html.text,'html',finalUrl.toString());
  const queue=assetsFromHtml(html.text,finalUrl.toString());ctx.coverage.scriptsDiscovered=queue.length;
  const seen=new Set();const maps=[];let totalScripts=0;
  while(queue.length&&seen.size<MAX_SCRIPTS&&totalScripts<MAX_TOTAL){const s=queue.shift();if(seen.has(s))continue;seen.add(s);const result=await inspectScript(s,ctx);ctx.coverage.scriptsAnalyzed++;if(result.partial)ctx.coverage.partialScripts++;totalScripts+=result.bytes;ctx.coverage.totalBytes+=result.bytes;for(const c of result.chunks){if(!seen.has(c)&&queue.length<40)queue.push(c);}for(const m of result.maps)maps.push(m);}
  for(const map of [...new Set(maps)].slice(0,MAX_MAPS)){ctx.coverage.totalBytes+=await inspectMap(map,ctx);}
  ctx.resources.scripts=[...new Set(ctx.resources.scripts)];ctx.resources.sourceMaps=[...new Set(ctx.resources.sourceMaps)];
  ctx.coverage.scriptsDiscovered=Math.max(ctx.coverage.scriptsDiscovered,seen.size+queue.length);
  ctx.coverage.endpointCandidates=ctx.endpoints.size;
  return ctx;
}