import { testLogin as legacyPasswordTest } from '../../login-tester.js';

const TIMEOUT=7000;
async function timedFetch(url,options={}){const c=new AbortController();const t=setTimeout(()=>c.abort(),TIMEOUT);try{return await fetch(url,{...options,signal:c.signal});}finally{clearTimeout(t);}}
function failText(text){return /(invalid|incorrect|wrong|failed|erro|inválid|incorret|credenciais|unauthorized|bad credentials|try again|tente novamente)/i.test(text);}
function authRedirect(location=''){return /\/(dashboard|account|profile|painel|home|app)(?:[/?#]|$)/i.test(String(location));}

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
      const r=await timedFetch(p.endpoint,{method:'POST',redirect:'manual',headers:{'content-type':'application/json','accept':'application/json,text/html,*/*;q=0.5','user-agent':'LIMPO-Auth-Engine/2.1'},body});
      let text='';try{text=await r.text();}catch{}
      let payload=null;try{payload=JSON.parse(text);}catch{}
      const location=r.headers.get('location')||'';
      const sessionCookieSet=Boolean(r.headers.get('set-cookie'));
      const tokenReturned=Boolean(payload?.access_token||payload?.token||payload?.idToken||payload?.id_token);
      const userReturned=Boolean(payload?.user||payload?.account||payload?.profile);
      const authenticatedFlag=payload?.authenticated===true;
      const successFlag=payload?.success===true;
      const redirectedToAuthenticatedArea=r.status>=300&&r.status<400&&authRedirect(location);
      const explicitFailure=r.status===401||r.status===403||failText(text)||payload?.success===false||payload?.authenticated===false;

      if(explicitFailure)return{status:'LOGIN_FAILED',success:false,httpStatus:r.status,transport:'generic-json-api',submitUrl:p.endpoint,sessionCookieSet,tokenReturned,userReturned,authenticatedFlag,successFlag,redirectedToAuthenticatedArea,explicitFailure:true,reason:'O endpoint de autenticação rejeitou a credencial.'};
      if(tokenReturned||userReturned||authenticatedFlag||successFlag||sessionCookieSet||redirectedToAuthenticatedArea)return{status:'LOGIN_SUCCESS',success:true,httpStatus:r.status,transport:'generic-json-api',submitUrl:p.endpoint,sessionCookieSet,tokenReturned,userReturned,authenticatedFlag,successFlag,redirectedToAuthenticatedArea,reason:'A resposta trouxe evidências adicionais compatíveis com autenticação bem-sucedida.'};
      return{status:'LOGIN_INCONCLUSIVE',success:null,httpStatus:r.status,transport:'generic-json-api',submitUrl:p.endpoint,sessionCookieSet:false,tokenReturned:false,userReturned:false,authenticatedFlag:false,successFlag:false,redirectedToAuthenticatedArea:false,reason:`HTTP ${r.status} recebido, mas sem token, usuário, cookie, flag explícita ou redirecionamento autenticado para confirmar o login.`};
    }
    return legacyPasswordTest(url,credentials.username,credentials.password);
  }
};
