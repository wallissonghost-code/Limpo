export default {
  id:'cognito-password',name:'Amazon Cognito Password',provider:'cognito',methods:['password'],priority:100,
  canHandle(d,m){return d.provider?.id==='cognito'&&m==='password';},
  availability(d,m){return this.canHandle(d,m)?{supported:true,ready:false,mode:'config-required',reason:'Cognito detectado. User Pool, client e fluxo permitido ainda precisam ser reconstruídos.'}:{supported:false,ready:false,mode:'none'};},
  async test(){return{status:'NOT_READY',success:null,reason:'Adapter Cognito identificado, mas o fluxo ainda não está reconstruído.'};}
};
