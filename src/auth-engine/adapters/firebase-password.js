const ENDPOINT='https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword';
const TIMEOUT=7000;

async function timedFetch(url,options={}){
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),TIMEOUT);
  try{return await fetch(url,{...options,signal:controller.signal});}finally{clearTimeout(timer);}
}

function firebaseErrorMessage(payload){return String(payload?.error?.message||payload?.error?.status||'').toUpperCase();}

export default {
  id:'firebase-password',name:'Firebase Password',provider:'firebase',methods:['password'],priority:100,
  canHandle(d,m){return d.provider?.id==='firebase'&&m==='password'&&d.capabilities?.password===true;},
  availability(d,m){
    if(!this.canHandle(d,m))return{supported:false,ready:false,mode:'none'};
    const cfg=d.runtime?.firebase||{};
    if(!cfg.apiKey)return{supported:true,ready:false,mode:'config-required',reason:'Firebase Authentication e Email + senha foram detectados, mas a chave pública de configuração não pôde ser reconstruída com segurança. Nenhuma credencial foi enviada.'};
    return{supported:true,ready:true,mode:'automated',reason:'Firebase Password identificado e configuração pública mínima reconstruída.'};
  },
  async test({credentials,discovery}){
    const cfg=discovery.runtime?.firebase||{};
    if(!cfg.apiKey)return{status:'CONFIG_REQUIRED',success:null,reason:'Falta a configuração pública mínima do Firebase. Nenhuma credencial foi enviada.'};
    const url=`${ENDPOINT}?key=${encodeURIComponent(cfg.apiKey)}`;
    const response=await timedFetch(url,{method:'POST',headers:{'content-type':'application/json','accept':'application/json','user-agent':'LIMPO-Auth-Engine/1.0'},body:JSON.stringify({email:String(credentials.username||''),password:String(credentials.password||''),returnSecureToken:true})});
    let payload={};try{payload=await response.json();}catch{}
    if(response.ok&&payload?.idToken){return{status:'LOGIN_SUCCESS',success:true,httpStatus:response.status,transport:'firebase-password',sessionCookieSet:false,reason:'O Firebase Authentication aceitou a credencial. Valores de token não são retornados pelo LIMPO.'};}
    const code=firebaseErrorMessage(payload);
    if(/INVALID_LOGIN_CREDENTIALS|INVALID_PASSWORD|EMAIL_NOT_FOUND|USER_DISABLED/.test(code))return{status:'LOGIN_FAILED',success:false,httpStatus:response.status,transport:'firebase-password',sessionCookieSet:false,reason:'O Firebase Authentication rejeitou a credencial.'};
    if(/OPERATION_NOT_ALLOWED|PASSWORD_LOGIN_DISABLED/.test(code))return{status:'ADAPTER_NOT_READY',success:null,httpStatus:response.status,transport:'firebase-password',sessionCookieSet:false,reason:'O projeto Firebase foi identificado, mas o login por senha não está habilitado para este fluxo.'};
    return{status:'LOGIN_INCONCLUSIVE',success:null,httpStatus:response.status,transport:'firebase-password',sessionCookieSet:false,reason:`O Firebase respondeu HTTP ${response.status}, mas o resultado não foi conclusivo para autenticação.`};
  }
};
