export default {
  id:'firebase-password',name:'Firebase Password',provider:'firebase',methods:['password'],priority:100,
  canHandle(d,m){return d.provider?.id==='firebase'&&m==='password';},
  availability(d,m){return this.canHandle(d,m)?{supported:true,ready:false,mode:'config-required',reason:'Firebase detectado, mas a configuração pública necessária ao fluxo de senha ainda não foi reconstruída pelo Discovery Engine.'}:{supported:false,ready:false,mode:'none'};},
  async test(){return{status:'NOT_READY',success:null,reason:'Adapter Firebase identificado, mas sem configuração reconstruída para executar o fluxo.'};}
};
