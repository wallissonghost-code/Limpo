import { discoverAuth,publicDiscovery } from './discovery.js';
import { findAdapter,adapterMatrixFor } from './registry.js';
import { verifyLoginResult } from './post-login-verifier.js';
import { testLogin as legacyPasswordTest } from '../login-tester.js';

function verifiedResponse({method,adapter,availability,discovery,adapterMatrix,result,fallback=false}){
  const verification=verifyLoginResult(result);
  return {
    ok:true,method,
    adapter:{
      id:fallback?'legacy-password-fallback':adapter.id,
      name:fallback?'Fallback de Login Direto':adapter.name,
      provider:fallback?'generic':(adapter.provider||'generic'),
      ...availability,
      fallback
    },
    discovery:publicDiscovery(discovery),
    adapters:adapterMatrix,
    result,
    verification,
    status:verification.status,
    success:verification.success,
    confidence:verification.confidence,
    evidence:verification.evidence,
    reason:verification.reason
  };
}

export async function runAuthTest({url,method='password',credentials={}}){
  const discovery=await discoverAuth(url);
  const adapterMatrix=adapterMatrixFor(discovery);
  const adapter=findAdapter(discovery,method);
  const safeDiscovery=publicDiscovery(discovery);

  if(!adapter){
    return {
      ok:true,status:'NOT_SUPPORTED',success:null,method,discovery:safeDiscovery,adapters:adapterMatrix,
      reason:`O método ${method} foi solicitado, mas nenhum adaptador compatível foi encontrado. Nenhuma credencial foi enviada.`
    };
  }

  const availability=adapter.availability(discovery,method);
  if(availability.mode==='interactive'){
    return {
      ok:true,status:'INTERACTIVE_REQUIRED',success:null,method,
      adapter:{id:adapter.id,name:adapter.name,provider:adapter.provider||'generic',...availability},
      discovery:safeDiscovery,adapters:adapterMatrix,
      reason:availability.reason||'Este método exige interação do usuário no navegador. Nenhuma credencial foi enviada.'
    };
  }

  if(!availability.ready){
    // Preserve the old direct login behavior as a bounded fallback. This is
    // still a single authorized attempt: the provider-specific adapter is NOT
    // called first. The fallback independently reconstructs a usable POST,
    // Firebase or Supabase password transport from the public login page.
    if(method==='password'&&availability.mode==='config-required'){
      try{
        const result=await legacyPasswordTest(url,credentials.username,credentials.password);
        return verifiedResponse({method,adapter,availability:{supported:true,ready:true,mode:'automated',reason:'O adaptador específico não tinha configuração suficiente; o LIMPO usou o fluxo direto reconstruído da página.'},discovery,adapterMatrix,result,fallback:true});
      }catch(fallbackError){
        const status='CONFIG_REQUIRED';
        return {
          ok:true,status,success:null,method,
          adapter:{id:adapter.id,name:adapter.name,provider:adapter.provider||'generic',...availability,fallbackAttempted:true},
          discovery:safeDiscovery,adapters:adapterMatrix,
          reason:fallbackError?.message||availability.reason||'O adaptador correspondente foi identificado, mas ainda não há dados suficientes para executar este fluxo com segurança. Nenhuma credencial foi enviada.'
        };
      }
    }

    const status=availability.mode==='config-required'?'CONFIG_REQUIRED':'ADAPTER_NOT_READY';
    return {
      ok:true,status,success:null,method,
      adapter:{id:adapter.id,name:adapter.name,provider:adapter.provider||'generic',...availability},
      discovery:safeDiscovery,adapters:adapterMatrix,
      reason:availability.reason||'O adaptador correspondente foi identificado, mas ainda não há dados suficientes para executar este fluxo com segurança. Nenhuma credencial foi enviada.'
    };
  }

  const result=await adapter.test({url,method,credentials,discovery});
  return verifiedResponse({method,adapter,availability,discovery,adapterMatrix,result});
}
