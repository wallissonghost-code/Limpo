export default {
  id:'auth0-password',name:'Auth0 Password',provider:'auth0',methods:['password'],priority:100,
  canHandle(d,m){return d.provider?.id==='auth0'&&m==='password'&&d.capabilities?.password===true;},
  availability(d,m){return this.canHandle(d,m)?{supported:true,ready:false,mode:'config-required',reason:'Provedor identificado: Auth0. O método Password foi detectado, mas tenant/client e o grant correspondente ainda não foram reconstruídos com segurança. Nenhuma credencial foi enviada.'}:{supported:false,ready:false,mode:'none'};},
  async test(){return{status:'CONFIG_REQUIRED',success:null,reason:'O adaptador Auth0 Password foi selecionado, mas ainda faltam parâmetros públicos do fluxo.'};}
};
