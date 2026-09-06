function clamp(n,min=0,max=100){return Math.max(min,Math.min(max,n));}

function normalizeEvidence(result={}){
  const evidence=[];
  if(Number.isFinite(result.httpStatus))evidence.push({type:'http',label:`HTTP ${result.httpStatus}`,weight:result.httpStatus>=200&&result.httpStatus<300?8:0});
  if(result.sessionCookieSet)evidence.push({type:'session-cookie',label:'Cookie de sessão definido',weight:38});
  if(result.tokenReturned)evidence.push({type:'token',label:'Token de autenticação retornado',weight:45});
  if(result.userReturned)evidence.push({type:'user',label:'Objeto de usuário retornado',weight:32});
  if(result.authenticatedFlag===true)evidence.push({type:'authenticated-flag',label:'Resposta confirmou authenticated=true',weight:40});
  if(result.successFlag===true)evidence.push({type:'success-flag',label:'Resposta confirmou success=true',weight:32});
  if(result.redirectedToAuthenticatedArea)evidence.push({type:'redirect',label:'Redirecionamento compatível com área autenticada',weight:30});
  if(result.providerAcceptedCredential)evidence.push({type:'provider',label:'Provedor de identidade aceitou a credencial',weight:55});
  if(result.providerRejectedCredential)evidence.push({type:'provider-reject',label:'Provedor de identidade rejeitou a credencial',weight:-100});
  if(result.explicitFailure)evidence.push({type:'explicit-failure',label:'Resposta contém falha explícita de autenticação',weight:-100});
  return evidence;
}

export function verifyLoginResult(result={}){
  const evidence=normalizeEvidence(result);
  const positive=evidence.filter(x=>x.weight>0).reduce((s,x)=>s+x.weight,0);
  const negative=evidence.filter(x=>x.weight<0).reduce((s,x)=>s+Math.abs(x.weight),0);

  if(result.status==='LOGIN_FAILED'||negative>=100){
    return {status:'LOGIN_FAILED',success:false,confidence:99,evidence:evidence.map(({weight,...x})=>x),reason:result.reason||'Há evidência explícita de que a autenticação foi rejeitada.'};
  }

  if(result.status==='LOGIN_SUCCESS'){
    const confidence=clamp(Math.max(85,positive));
    return {status:'LOGIN_SUCCESS',success:true,confidence,evidence:evidence.map(({weight,...x})=>x),reason:result.reason||'Há evidências suficientes para confirmar autenticação bem-sucedida.'};
  }

  if(positive>=55){
    return {status:'LOGIN_SUCCESS',success:true,confidence:clamp(positive),evidence:evidence.map(({weight,...x})=>x),reason:'A combinação de sinais pós-login é forte o bastante para confirmar autenticação.'};
  }

  return {status:'LOGIN_INCONCLUSIVE',success:null,confidence:clamp(Math.max(15,positive)),evidence:evidence.map(({weight,...x})=>x),reason:result.reason||'A resposta não trouxe evidência suficiente para confirmar sucesso ou falha.'};
}
