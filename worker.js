import { analyzeUrl } from './src/auth-detector.js';
import { detectLoginForm } from './src/form-detector.js';

function json(data,status=200){
  return new Response(JSON.stringify(data),{
    status,
    headers:{
      'content-type':'application/json; charset=utf-8',
      'cache-control':'no-store',
      'x-content-type-options':'nosniff',
      'referrer-policy':'no-referrer'
    }
  });
}

async function readUrl(request){
  const body=await request.json().catch(()=>({}));
  if(!body.url)throw new Error('Informe uma URL.');
  return String(body.url).trim();
}

async function analyze(request){
  if(request.method!=='POST')return json({error:'Use POST.'},405);
  try{return json(await analyzeUrl(await readUrl(request)));}
  catch(error){const message=error?.name==='AbortError'?'A análise excedeu o tempo limite.':(error?.message||'Falha ao analisar a URL.');return json({error:message},400);}
}

async function analyzeForm(request){
  if(request.method!=='POST')return json({error:'Use POST.'},405);
  try{return json(await detectLoginForm(await readUrl(request)));}
  catch(error){const message=error?.name==='AbortError'?'A análise excedeu o tempo limite.':(error?.message||'Falha ao analisar o formulário.');return json({error:message},400);}
}

export default {
  async fetch(request,env){
    const url=new URL(request.url);
    if(url.pathname==='/api/analyze')return analyze(request);
    if(url.pathname==='/api/form-detect')return analyzeForm(request);
    if(env.ASSETS)return env.ASSETS.fetch(request);
    return new Response('LIMPO Auth Detector',{status:200});
  }
};