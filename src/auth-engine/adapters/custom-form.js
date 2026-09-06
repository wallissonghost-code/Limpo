import { testLogin as legacyPasswordTest } from '../../login-tester.js';

const TIMEOUT=7000;
async function timedFetch(url,options={}){const c=new AbortController();const t=setTimeout(()=>c.abort(),TIMEOUT);try{return await fetch(url,{...options,signal:c.signal});}finally{clearTimeout(t);}}
function failText(text){return /(invalid|incorrect|wrong|failed|erro|inválid|incorret|credenciais|unauthorized|bad credentials|try again|tente novamente)/i.test(text);}

export default {
  id:'custom-form',name:'Custom / HTML-JS Password',provider:'custom',methods:['password'],priority:10,
  canHandle(discovery,method){
    if(method!=='password'||discovery.capabilities?.password!==true)return false;
    const provider=discovery.provider?.id||'unknown';const protocol=String(discovery.authentication?.protocol||'unknown').toLowerCase();
    return provider==='custom'||provider==='unknown'||protocol==='custom/unknown'||protocol==='unknown';
  },
  availability(discovery,method){
    if(!this.canHandle(discovery,method))return{supported:false,ready:false,mode:'none'};
    const p=discovery.flowModel?.password;
    if(p?.ready)return{supported:true,ready:true,mode:'automated',reason:`Fluxo POST reconstruído com confiança ${p.confidence||'alta'}%.`};
    return{supported:true,ready:true,mode:'automated',reason:'Fluxo de senha customizado detectado; o adaptador tentará reconstruir formulário ou endpoint público.'};
  },
  async test({url,credentials,discovery}){
    const p=discovery.flowModel?.password;
    if(p?.ready&&p.endpoint&&p.method==='POST'&&p.contentType==='application/json'){
      const body=JSON.stringify({[p.userField||'email']:String(credentials.username||''),[p.passField||'password']:String(credentials.password||'')});
      const r=await timedFetch(p.endpoint,{method:'POST',redirect:'manual',headers:{'content-type':'application/json','accept':'application/json,text/html,*/*;q=0.5','user-agent':'LIMPO-Auth-Engine/2.0'},body});
      let text='';try{text=await r.text();}catch{}
      if(r.status===401||r.status===403||failText(text))return{status:'LOGIN_FAILED',success:false,httpStatus:r.status,transport:'generic-json-api',submitUrl:p.endpoint,sessionCookieSet:Boolean(r.headers.get('set-cookie')),reason:'O endpoint de autenticação rejeitou a credencial.'};
      if(r.ok){let payload=null;try{payload=JSON.parse(text);}catch{}if(payload&&(payload.success===true||payload.authenticated===true||payload.user||payload.access_token||payload.token))return{status:'LOGIN_SUCCESS',success:true,httpStatus:r.status,transport:'generic-json-api',submitUrl:p.endpoint,sessionCookieSet:Boolean(r.headers.get('set-cookie')),reason:'O endpoint respondeu com estrutura compatível com autenticação bem-sucedida.'};if(r.headers.get('set-cookie'))return{status:'LOGIN_SUCCESS',success:true,httpStatus:r.status,transport:'generic-json-api',submitUrl:p.endpoint,sessionCookieSet:true,reason:'O endpoint aceitou a requisição e definiu cookie de sessão.'};}
      return{status:'LOGIN_INCONCLUSIVE',success:null,httpStatus:r.status,transport:'generic-json-api',submitUrl:p.endpoint,sessionCookieSet:Boolean(r.headers.get('set-cookie')),reason:'A resposta do endpoint não fornece sinal suficiente para confirmar sucesso ou falha.'};
    }
    return legacyPasswordTest(url,credentials.username,credentials.password);
  }
};
