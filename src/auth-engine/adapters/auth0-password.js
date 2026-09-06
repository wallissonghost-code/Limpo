export default {
  id:'auth0-password',name:'Auth0 Password',provider:'auth0',methods:['password'],priority:100,
  canHandle(d,m){return d.provider?.id==='auth0'&&m==='password';},
  availability(d,m){return this.canHandle(d,m)?{supported:true,ready:false,mode:'config-required',reason:'Auth0 detectado. O fluxo de senha exige parâmetros públicos do tenant/client e pode não estar habilitado.'}:{supported:false,ready:false,mode:'none'};},
  async test(){return{status:'NOT_READY',success:null,reason:'Adapter Auth0 identificado, mas o fluxo de senha não foi reconstruído com segurança.'};}
};
