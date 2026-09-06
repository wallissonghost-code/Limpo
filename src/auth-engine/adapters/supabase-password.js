const TIMEOUT=7000;
async function timedFetch(url,options={}){const c=new AbortController();const t=setTimeout(()=>c.abort(),TIMEOUT);try{return await fetch(url,{...options,signal:c.signal});}finally{clearTimeout(t);}}

export default {
  id:'supabase-password',name:'Supabase Password',provider:'supabase',methods:['password'],priority:100,
  canHandle(d,m){return d.provider?.id==='supabase'&&m==='password'&&d.capabilities?.password===true;},
  availability(d,m){
    if(!this.canHandle(d,m))return{supported:false,ready:false,mode:'none'};
    const cfg=d.runtime?.supabase||{};
    if(!(cfg.url&&cfg.anonKey))return{supported:true,ready:false,mode:'config-required',reason:'Supabase Auth e Email + senha foram detectados, mas URL/chave pública ainda não foram reconstruídas com segurança. Nenhuma credencial foi enviada.'};
    return{supported:true,ready:true,mode:'automated',reason:'Supabase Password identificado e configuração pública mínima reconstruída.'};
  },
  async test({credentials,discovery}){
    const cfg=discovery.runtime?.supabase||{};if(!(cfg.url&&cfg.anonKey))return{status:'CONFIG_REQUIRED',success:null,reason:'Falta configuração pública mínima do Supabase. Nenhuma credencial foi enviada.'};
    const endpoint=`${cfg.url.replace(/\/$/,'')}/auth/v1/token?grant_type=password`;
    const r=await timedFetch(endpoint,{method:'POST',headers:{'content-type':'application/json','accept':'application/json','apikey':cfg.anonKey,'authorization':`Bearer ${cfg.anonKey}`,'user-agent':'LIMPO-Auth-Engine/2.1'},body:JSON.stringify({email:String(credentials.username||''),password:String(credentials.password||'')})});
    let payload={};try{payload=await r.json();}catch{}
    if(r.ok&&(payload?.access_token||payload?.user))return{status:'LOGIN_SUCCESS',success:true,httpStatus:r.status,transport:'supabase-password',sessionCookieSet:false,tokenReturned:Boolean(payload?.access_token),userReturned:Boolean(payload?.user),providerAcceptedCredential:true,reason:'O Supabase Auth aceitou a credencial. Tokens não são retornados pelo LIMPO.'};
    const msg=String(payload?.error_description||payload?.msg||payload?.error||'').toLowerCase();
    if(r.status===400||r.status===401||/invalid login|invalid credentials|email not confirmed|user not found|wrong password/.test(msg))return{status:'LOGIN_FAILED',success:false,httpStatus:r.status,transport:'supabase-password',sessionCookieSet:false,providerRejectedCredential:true,explicitFailure:true,reason:'O Supabase Auth rejeitou a credencial.'};
    return{status:'LOGIN_INCONCLUSIVE',success:null,httpStatus:r.status,transport:'supabase-password',sessionCookieSet:false,reason:`O Supabase respondeu HTTP ${r.status}, mas o resultado não foi conclusivo.`};
  }
};
