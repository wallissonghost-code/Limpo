import { discoverAuth,publicDiscovery } from './discovery.js';
import { findAdapter,adapterMatrixFor } from './registry.js';

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
    const status=availability.mode==='config-required'?'CONFIG_REQUIRED':'ADAPTER_NOT_READY';
    return {
      ok:true,status,success:null,method,
      adapter:{id:adapter.id,name:adapter.name,provider:adapter.provider||'generic',...availability},
      discovery:safeDiscovery,adapters:adapterMatrix,
      reason:availability.reason||'O adaptador correspondente foi identificado, mas ainda não há dados suficientes para executar este fluxo com segurança. Nenhuma credencial foi enviada.'
    };
  }

  const result=await adapter.test({url,method,credentials,discovery});
  return {
    ok:true,method,
    adapter:{id:adapter.id,name:adapter.name,provider:adapter.provider||'generic',...availability},
    discovery:safeDiscovery,adapters:adapterMatrix,result,...result
  };
}
