export default {
  id:'cognito-password',name:'Amazon Cognito Password',provider:'cognito',methods:['password'],priority:100,
  canHandle(d,m){return d.provider?.id==='cognito'&&m==='password'&&d.capabilities?.password===true;},
  availability(d,m){return this.canHandle(d,m)?{supported:true,ready:false,mode:'config-required',reason:'Provedor identificado: Amazon Cognito. O método Password foi detectado, mas User Pool, client e fluxo permitido ainda não foram reconstruídos com segurança. Nenhuma credencial foi enviada.'}:{supported:false,ready:false,mode:'none'};},
  async test(){return{status:'CONFIG_REQUIRED',success:null,reason:'O adaptador Cognito Password foi selecionado, mas ainda faltam parâmetros públicos do fluxo.'};}
};
