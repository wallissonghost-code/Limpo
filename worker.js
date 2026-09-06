import { analyzeUrl } from './src/auth-detector.js';
import { detectLoginForm } from './src/form-detector.js';
import { discoverAuth,publicDiscovery } from './src/auth-engine/discovery.js';
import { adapterMatrixFor } from './src/auth-engine/registry.js';
import { runAuthTest } from './src/auth-engine/orchestrator.js';

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

async function readBody(request){return await request.json().catch(()=>({}));}

async function analyze(request){
  if(request.method!=='POST')return json({error:'Use POST.'},405);
  try{const body=await readBody(request);if(!body.url)throw new Error('Informe uma URL.');return json(await analyzeUrl(String(body.url).trim()));}
  catch(error){const message=error?.name==='AbortError'?'A análise excedeu o tempo limite.':(error?.message||'Falha ao analisar a URL.');return json({error:message},400);}
}

async function discover(request){
  if(request.method!=='POST')return json({error:'Use POST.'},405);
  try{
    const body=await readBody(request);if(!body.url)throw new Error('Informe uma URL.');
    const discovery=await discoverAuth(String(body.url).trim());
    return json({...publicDiscovery(discovery),adapters:adapterMatrixFor(discovery)});
  }
  catch(error){const message=error?.name==='AbortError'?'A descoberta excedeu o tempo limite.':(error?.message||'Falha ao descobrir o mecanismo de autenticação.');return json({error:message},400);}
}

async function analyzeForm(request){
  if(request.method!=='POST')return json({error:'Use POST.'},405);
  try{const body=await readBody(request);if(!body.url)throw new Error('Informe uma URL.');return json(await detectLoginForm(String(body.url).trim()));}
  catch(error){const message=error?.name==='AbortError'?'A análise excedeu o tempo limite.':(error?.message||'Falha ao analisar o formulário.');return json({error:message},400);}
}

async function loginTest(request){
  if(request.method!=='POST')return json({error:'Use POST.'},405);
  try{
    const body=await readBody(request);
    if(body.authorized!==true)throw new Error('Confirme que você tem autorização para testar este login.');
    if(!body.url)throw new Error('Informe uma URL.');
    const method=String(body.method||'password');
    const credentials={username:String(body.email||body.username||''),password:String(body.password||'')};
    if(method==='password'&&(!credentials.username||!credentials.password))throw new Error('Informe e-mail/usuário e senha.');
    return json(await runAuthTest({url:String(body.url).trim(),method,credentials}));
  }
  catch(error){const message=error?.name==='AbortError'?'O teste excedeu o tempo limite.':(error?.message||'Falha ao testar o login.');return json({error:message},400);}
}

export default {
  async fetch(request,env){
    const url=new URL(request.url);
    if(url.pathname==='/api/analyze')return analyze(request);
    if(url.pathname==='/api/discover')return discover(request);
    if(url.pathname==='/api/form-detect')return analyzeForm(request);
    if(url.pathname==='/api/login-test')return loginTest(request);
    if(env.ASSETS)return env.ASSETS.fetch(request);
    return new Response('LIMPO Auth Engine',{status:200});
  }
};