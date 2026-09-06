export default {
  id:'supabase-password',name:'Supabase Password',provider:'supabase',methods:['password'],priority:100,
  canHandle(d,m){return d.provider?.id==='supabase'&&m==='password'&&d.capabilities?.password===true;},
  availability(d,m){return this.canHandle(d,m)?{supported:true,ready:false,mode:'config-required',reason:'Provedor identificado: Supabase Auth. O método Email + senha foi detectado, mas URL/chave pública necessárias ao fluxo ainda não foram reconstruídas com segurança. Nenhuma credencial foi enviada.'}:{supported:false,ready:false,mode:'none'};},
  async test(){return{status:'CONFIG_REQUIRED',success:null,reason:'O adaptador Supabase Password foi selecionado, mas ainda faltam parâmetros públicos do fluxo.'};}
};
