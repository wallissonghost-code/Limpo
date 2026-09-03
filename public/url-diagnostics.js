(()=>{
  const $=s=>document.querySelector(s);
  const terminal=$('#urlTerminal');
  const bar=document.querySelector('#urlView .providerBar');
  if(!terminal||!bar)return;

  const details=document.createElement('div');
  details.id='providerDetails';
  details.innerHTML=`
    <div class="stats">
      <div class="card"><small>Teste disponível</small><b id="providerTestAvailable">---</b></div>
      <div class="card"><small>Motivo / indisponibilidade</small><b id="providerUnavailableReason">---</b></div>
      <div class="card"><small>Scripts analisados</small><b id="providerScripts">0</b></div>
    </div>
    <div class="card">
      <small>Diagnóstico dos recursos</small>
      <div id="providerDiagnostics" class="terminal" style="height:220px;margin-top:8px"><div class="muted">Nenhuma detecção executada.</div></div>
    </div>`;
  bar.insertAdjacentElement('afterend',details);

  const reasonLabels={
    provider_not_firebase:'Firebase detectado sem condição para este adaptador.',
    firebase_api_key_not_discovered:'Firebase detectado, mas a configuração pública necessária ao adaptador não foi encontrada.',
    supabase_adapter_not_implemented:'Supabase detectado; adaptador de teste ainda não implementado.',
    auth0_adapter_not_implemented:'Auth0 detectado; adaptador de teste ainda não implementado.',
    cognito_adapter_not_implemented:'Cognito detectado; adaptador de teste ainda não implementado.',
    clerk_adapter_not_implemented:'Clerk detectado; adaptador de teste ainda não implementado.',
    okta_adapter_not_implemented:'Okta detectado; adaptador de teste ainda não implementado.',
    entra_id_adapter_not_implemented:'Microsoft Entra ID detectado; adaptador de teste ainda não implementado.',
    keycloak_adapter_not_implemented:'Keycloak detectado; adaptador de teste ainda não implementado.',
    authjs_adapter_not_implemented:'Auth.js/NextAuth detectado; adaptador automático ainda não implementado.',
    custom_jwt_flow_requires_manual_review:'JWT customizado detectado; o fluxo requer revisão manual.',
    oauth2_flow_requires_manual_review:'OAuth2 detectado; o fluxo requer revisão manual.',
    oidc_flow_requires_manual_review:'OIDC detectado; o fluxo requer revisão manual.',
    provider_not_supported:'Tecnologia customizada ou indeterminada; sem adaptador automático.',
    adapter_not_implemented:'Provedor detectado; sem adaptador automático implementado.'
  };

  function line(text,cls=''){
    const d=document.createElement('div');d.className=cls;d.textContent=text;terminal.appendChild(d);terminal.scrollTop=terminal.scrollHeight;
  }
  function diagLine(text,cls=''){
    const el=$('#providerDiagnostics');const d=document.createElement('div');d.className=cls;d.textContent=text;el.appendChild(d);el.scrollTop=el.scrollHeight;
  }
  function labelProvider(p){
    const map={firebase:'FIREBASE',supabase:'SUPABASE',auth0:'AUTH0',cognito:'COGNITO',clerk:'CLERK',okta:'OKTA','entra-id':'MICROSOFT ENTRA ID',keycloak:'KEYCLOAK',authjs:'AUTH.JS / NEXTAUTH',passport:'PASSPORT','jwt-custom':'JWT CUSTOM',oauth2:'OAUTH2',oidc:'OIDC','custom-or-unknown':'CUSTOM / INDETERMINADO'};
    return map[p]||String(p||'---').toUpperCase();
  }
  function renderDiagnostics(data){
    const d=data?.diagnostics||{};
    const box=$('#providerDiagnostics');box.innerHTML='';
    diagLine(`Página inicial: HTTP ${d.initialStatus??'---'} | ${d.initialContentType||'tipo desconhecido'} | ${d.initialBytes||0} bytes`,d.initialStatus>=200&&d.initialStatus<400?'green':'warn');
    if(d.initialTruncated)diagLine('Página inicial analisada parcialmente por limite de leitura.','warn');
    const found=Array.isArray(d.scannedResources)?d.scannedResources:[];
    const failed=Array.isArray(d.failedResources)?d.failedResources:[];
    diagLine(`Recursos encontrados/analisados: ${found.length} | falhas de leitura: ${failed.length}`,'green');
    found.forEach(r=>diagLine(`OK ${r.status} | ${r.bytes||0} bytes${r.truncated?' | PARCIAL':''} | ${r.url}`,r.status>=200&&r.status<400?'green':'warn'));
    failed.forEach(r=>diagLine(`FALHOU | ${r.url} | ${r.error||'erro desconhecido'}`,'bad'));
    const probes=Array.isArray(d.manifestProbes)?d.manifestProbes:[];
    probes.forEach(p=>diagLine(`PROBE ${p.path} → ${p.status}${p.detail?' | '+p.detail:''}`,'muted'));
    if(!found.length&&!failed.length)diagLine('Nenhum script/recurso adicional foi carregado para análise.','muted');
  }
  function renderCapability(data){
    $('#providerName').textContent=labelProvider(data.provider);
    $('#providerConfidence').textContent=String(data.confidence||'---').toUpperCase();
    $('#providerAdapter').textContent=data.testAvailable?(data.adapter||'ATIVO').toUpperCase():'DETECÇÃO SOMENTE';
    $('#providerTestAvailable').textContent=data.testAvailable?'SIM':'NÃO';
    $('#providerTestAvailable').className=data.testAvailable?'green':'warn';
    $('#providerUnavailableReason').textContent=data.testAvailable?'---':(reasonLabels[data.unavailableReason]||data.unavailableReason||'Sem adaptador compatível.');
    $('#providerScripts').textContent=String(data.scannedScripts||0);
    $('#urlTestBtn').disabled=!data.testAvailable;
    $('#urlBlockBtn').disabled=!data.testAvailable;
    renderDiagnostics(data);
  }

  const detectBtn=$('#detectBtn');
  detectBtn.onclick=async()=>{
    const url=$('#targetUrl').value.trim();
    if(!url){line('Informe a URL.','warn');return}
    if($('#targetAuthorized').value!=='yes'){line('Confirme que você tem autorização para testar o sistema.','warn');return}
    detectBtn.disabled=true;$('#providerName').textContent='ANALISANDO';$('#providerConfidence').textContent='...';$('#providerAdapter').textContent='...';
    $('#providerTestAvailable').textContent='...';$('#providerUnavailableReason').textContent='...';$('#providerScripts').textContent='...';
    try{
      const r=await fetch('/url-provider-detect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url,authorized:true})});
      const data=await r.json().catch(()=>({}));
      if(!r.ok){$('#providerName').textContent='INDETERMINADO';$('#providerConfidence').textContent='---';$('#providerAdapter').textContent='---';line('Detecção falhou → '+JSON.stringify({status:r.status,error:data.error||null,detail:data.detail||null}),'warn');return}
      renderCapability(data);
      line('Detecção válida → '+JSON.stringify({provider:data.provider,confidence:data.confidence,testAvailable:data.testAvailable,adapter:data.adapter,reason:data.unavailableReason,scripts:data.scannedScripts||0,failed:data.diagnostics?.failedResources?.length||0,latencyMs:data.latencyMs||0}),'green');
    }catch(e){$('#providerName').textContent='ERRO';line('Falha de rede na detecção: '+e.message,'warn')}
    finally{detectBtn.disabled=false}
  };

  const testBtn=$('#urlTestBtn');
  testBtn.onclick=async()=>{
    const url=$('#targetUrl').value.trim(),email=$('#targetEmail').value.trim(),password=$('#targetPassword').value;
    if(!url||!email||!password){line('Preencha URL, e-mail e senha.','warn');return}
    if($('#targetAuthorized').value!=='yes'){line('Confirme a autorização.','warn');return}
    testBtn.disabled=true;$('#urlStatus').textContent='TESTANDO';$('#urlAuth').textContent='...';const t=performance.now();
    try{
      const r=await fetch('/url-auth-test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url,email,password,authorized:true})});
      const data=await r.json().catch(()=>({}));
      const ms=Number(data.latencyMs)||Math.round(performance.now()-t);$('#urlLatency').textContent=ms+' ms';
      if(data.tested===false){$('#urlStatus').textContent='NÃO TESTADO';$('#urlAuth').textContent='SEM ADAPTADOR';renderCapability(data);line('Credencial não testada: '+(reasonLabels[data.unavailableReason]||data.message||'adaptador indisponível'),'warn');return}
      const classification=data.classification==='authenticated'||data.authenticated?'AUTENTICADA':data.classification==='blocked'||r.status===429?'BLOQUEADA':data.classification==='invalid'||r.status===401?'INVÁLIDA':'INDETERMINADA';
      $('#urlStatus').textContent=classification;$('#urlAuth').textContent=data.authType||data.provider||'---';
      line('Credencial → '+JSON.stringify({status:r.status,classification,provider:data.provider||null,authType:data.authType||null,error:data.error||null,providerCode:data.providerCode||null,providerHttpStatus:data.providerHttpStatus||null}),classification==='AUTENTICADA'?'green':classification==='INVÁLIDA'?'bad':'warn');
    }catch(e){$('#urlStatus').textContent='INDETERMINADA';line('Falha; validade da credencial não determinada: '+e.message,'warn')}
    finally{$('#targetPassword').value='';if($('#providerTestAvailable').textContent==='SIM')testBtn.disabled=false}
  };

  const clearBtn=$('#urlClearBtn');
  const oldClear=clearBtn.onclick;
  clearBtn.onclick=()=>{
    if(oldClear)oldClear();
    $('#providerTestAvailable').textContent='---';$('#providerTestAvailable').className='';$('#providerUnavailableReason').textContent='---';$('#providerScripts').textContent='0';$('#providerDiagnostics').innerHTML='<div class="muted">Nenhuma detecção executada.</div>';
    $('#urlTestBtn').disabled=false;$('#urlBlockBtn').disabled=false;
  };
})();
