export default {
  id:'clerk-password',name:'Clerk Password',provider:'clerk',methods:['password'],priority:100,
  canHandle(d,m){return d.provider?.id==='clerk'&&m==='password'&&d.capabilities?.password===true;},
  availability(d,m){return this.canHandle(d,m)?{supported:true,ready:false,mode:'config-required',reason:'Provedor identificado: Clerk. O método Password foi detectado, mas a instância pública e o fluxo de sign-in ainda não foram reconstruídos com segurança. Nenhuma credencial foi enviada.'}:{supported:false,ready:false,mode:'none'};},
  async test(){return{status:'CONFIG_REQUIRED',success:null,reason:'O adaptador Clerk Password foi selecionado, mas ainda faltam parâmetros públicos do fluxo.'};}
};
