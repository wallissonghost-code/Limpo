import { discoverAuth } from './discovery.js';
import { findAdapter,adapterMatrixFor } from './registry.js';

export async function runAuthTest({url,method='password',credentials={}}){
  const discovery=await discoverAuth(url);
  const adapterMatrix=adapterMatrixFor(discovery);
  const adapter=findAdapter(discovery,method);
  if(!adapter){
    return {ok:true,status:'NOT_SUPPORTED',success:null,method,discovery,adapters:adapterMatrix,reason:`Nenhum adaptador registrado para o método ${method}. Nenhuma credencial foi enviada.`};
  }
  const availability=adapter.availability(discovery,method);
  if(!availability.ready){
    return {ok:true,status:'ADAPTER_NOT_READY',success:null,method,adapter:{id:adapter.id,name:adapter.name,...availability},discovery,adapters:adapterMatrix,reason:availability.reason||'Adaptador identificado, mas ainda não está pronto para executar este fluxo. Nenhuma credencial foi enviada.'};
  }
  if(availability.mode==='interactive'){
    return {ok:true,status:'INTERACTIVE_REQUIRED',success:null,method,adapter:{id:adapter.id,name:adapter.name,...availability},discovery,adapters:adapterMatrix,reason:availability.reason||'Este método exige interação do usuário no navegador. Nenhuma credencial foi enviada.'};
  }
  const result=await adapter.test({url,method,credentials,discovery});
  return {ok:true,method,adapter:{id:adapter.id,name:adapter.name,...availability},discovery,adapters:adapterMatrix,result,...result};
}
