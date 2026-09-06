export default {
  id:'firebase-password',name:'Firebase Password',provider:'firebase',methods:['password'],priority:100,
  canHandle(d,m){return d.provider?.id==='firebase'&&m==='password'&&d.capabilities?.password===true;},
  availability(d,m){return this.canHandle(d,m)?{supported:true,ready:false,mode:'config-required',reason:'Provedor identificado: Firebase Authentication. O método Email + senha foi detectado, mas a configuração pública necessária ao fluxo ainda não foi reconstruída com segurança. Nenhuma credencial foi enviada.'}:{supported:false,ready:false,mode:'none'};},
  async test(){return{status:'CONFIG_REQUIRED',success:null,reason:'O adaptador Firebase Password foi selecionado, mas ainda faltam parâmetros públicos do fluxo.'};}
};
