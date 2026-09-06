import { addSignal, inspectBehavior } from './signals.js';

const MAX_PROBE_BYTES=180_000;
const PROBE_TIMEOUT=4500;

async function timedFetch(url){
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),PROBE_TIMEOUT);
  try{return await fetch(url,{redirect:'manual',signal:controller.signal,headers:{'user-agent':'LIMPO-Auth-Analyzer/4.1','accept':'application/json,text/javascript,text/plain,*/*;q=0.3'}});}finally{clearTimeout(timer);}
}

async function readText(response){
  const reader=response.body?.getReader();if(!reader)return{text:'',bytes:0};
  const chunks=[];let total=0;
  while(true){const {done,value}=await reader.read();if(done)break;const left=MAX_PROBE_BYTES-total;if(left<=0)break;const part=value.byteLength>left?value.slice(0,left):value;chunks.push(part);total+=part.byteLength;if(value.byteLength>left)break;}
  try{await reader.cancel();}catch{}
  const merged=new Uint8Array(total);let offset=0;for(const c of chunks){merged.set(c,offset);offset+=c.byteLength;}
  return{text:new TextDecoder().decode(merged),bytes:total};
}

async function probe(ctx,url,type){
  try{
    const r=await timedFetch(url);
    if(!r.ok)return 0;
    const x=await readText(r);if(!x.text)return 0;
    ctx.corpus.push(x.text);
    inspectBehavior(ctx,x.text,`probe:${type}`,url);
    ctx.coverage.probesSucceeded++;
    return x.bytes;
  }catch{return 0;}
}

function manifestUrls(html,baseUrl){
  const out=new Set();const re=/<link\b[^>]*rel=["'][^"']*manifest[^"']*["'][^>]*href=["']([^"']+)["']|<link\b[^>]*href=["']([^"']+)["'][^>]*rel=["'][^"']*manifest[^"']*["']/gi;let m;
  while((m=re.exec(html))&&out.size<3){try{const u=new URL(m[1]||m[2],baseUrl);if(u.origin===new URL(baseUrl).origin)out.add(u.toString());}catch{}}
  return[...out];
}

export async function runPublicProbes(ctx,finalUrl,html){
  ctx.coverage.probesAttempted=0;ctx.coverage.probesSucceeded=0;ctx.coverage.manifestsAnalyzed=0;
  const origin=new URL(finalUrl).origin;

  const firebase=[`${origin}/__/firebase/init.json`,`${origin}/__/firebase/init.js`];
  for(const url of firebase){
    ctx.coverage.probesAttempted++;
    try{
      const r=await timedFetch(url);if(!r.ok)continue;const x=await readText(r);if(!x.text)continue;
      if(/projectId|authDomain|apiKey|firebase/i.test(x.text)){
        ctx.corpus.push(x.text);
        addSignal(ctx,{type:'firebase_runtime_config',value:'public runtime config',source:`probe:${new URL(url).pathname}`,weight:10,strength:'strong'});
        inspectBehavior(ctx,x.text,'probe:firebase-runtime',url);ctx.coverage.probesSucceeded++;ctx.coverage.totalBytes+=x.bytes;
      }
    }catch{}
  }

  const oidc=`${origin}/.well-known/openid-configuration`;
  ctx.coverage.probesAttempted++;
  try{
    const r=await timedFetch(oidc);if(r.ok){const x=await readText(r);if(/issuer|authorization_endpoint|token_endpoint/i.test(x.text)){
      ctx.corpus.push(x.text);ctx.authentication.protocol='oidc';addSignal(ctx,{type:'oidc_metadata',value:'/.well-known/openid-configuration',source:'probe:oidc',weight:10,strength:'strong'});inspectBehavior(ctx,x.text,'probe:oidc',oidc);ctx.coverage.probesSucceeded++;ctx.coverage.totalBytes+=x.bytes;
    }}
  }catch{}

  for(const url of manifestUrls(html,finalUrl)){
    ctx.coverage.probesAttempted++;
    const before=ctx.coverage.probesSucceeded;const bytes=await probe(ctx,url,'manifest');ctx.coverage.totalBytes+=bytes;if(ctx.coverage.probesSucceeded>before)ctx.coverage.manifestsAnalyzed++;
  }
}
