import { analyzeUrl } from './src/auth-detector.js';
import { detectLoginForm } from './src/form-detector.js';
import { testLogin } from './src/login-tester.js';
import { discoverAuth,publicDiscovery } from './src/auth-engine/discovery.js';
import { adapterMatrixFor } from './src/auth-engine/registry.js';
import { runAuthTest } from './src/auth-engine/orchestrator.js';
import { verifyLoginResult } from './src/auth-engine/post-login-verifier.js';

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

async function directPasswordLogin(url,credentials){
  // This is the exact proven transport path that powered /api/login-test before
  // commit 76ebad3. Discovery/orchestration must never prevent a password
  // attempt that this bounded single-attempt tester can reconstruct safely.
  const result=await testLogin(url,credentials.username,credentials.password);
  const verification=verifyLoginResult(result);
  return {
    ok:true,
    method:'password',
    pipeline:'direct-password',
    adapter:{id:'direct-password',name:'Direct Password Login',provider:result?.provider||'generic',mode:'automated',ready:true},
    result,
    verification,
    status:verification.status,
    success:verification.success,
    confidence:verification.confidence,
    evidence:verification.evidence,
    reason:verification.reason,
    httpStatus:result?.httpStatus,
    loginPage:result?.loginPage,
    submitUrl:result?.submitUrl,
    redirectTo:result?.redirectTo,
    sessionCookieSet:Boolean(result?.sessionCookieSet),
    note:result?.note||''
  };
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
    const url=String(body.url).trim();

    // Password keeps the working legacy transport as the primary path. The
    // Auth Engine remains responsible for discovery and non-password flows.
    // This avoids a discovery/configuration failure blocking the actual login.
    if(method==='password')return json(await directPasswordLogin(url,credentials));
    return json(await runAuthTest({url,method,credentials}));
  }
  catch(error){
    const message=error?.name==='AbortError'?'O teste excedeu o tempo limite.':(error?.message||String(error||'Falha ao testar o login.'));
    return json({error:message,stage:'login-execution'},400);
  }
}

export default {
  async fetch(request,env){
    const url=new URL(request.url);
    try{
      if(url.pathname==='/api/analyze')return await analyze(request);
      if(url.pathname==='/api/discover')return await discover(request);
      if(url.pathname==='/api/form-detect')return await analyzeForm(request);
      if(url.pathname==='/api/login-test')return await loginTest(request);
      if(url.pathname.startsWith('/api/'))return json({error:`Endpoint da API não encontrado: ${url.pathname}`},404);
      if(env.ASSETS)return env.ASSETS.fetch(request);
      return new Response('LIMPO Auth Engine',{status:200});
    }catch(error){
      if(url.pathname.startsWith('/api/')){
        const message=error?.name==='AbortError'?'A operação excedeu o tempo limite.':(error?.message||String(error||'Falha interna na API do LIMPO.'));
        return json({error:message,stage:'worker'},500);
      }
      throw error;
    }
  }
};