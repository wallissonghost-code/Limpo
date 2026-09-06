export default {
  id:'clerk-password',name:'Clerk Password',provider:'clerk',methods:['password'],priority:100,
  canHandle(d,m){return d.provider?.id==='clerk'&&m==='password';},
  availability(d,m){return this.canHandle(d,m)?{supported:true,ready:false,mode:'config-required',reason:'Clerk detectado. A instância pública e o fluxo de sign-in ainda precisam ser reconstruídos.'}:{supported:false,ready:false,mode:'none'};},
  async test(){return{status:'NOT_READY',success:null,reason:'Adapter Clerk identificado, mas o fluxo ainda não está reconstruído.'};}
};
