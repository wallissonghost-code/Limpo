export default {
  id:'supabase-password',name:'Supabase Password',provider:'supabase',methods:['password'],priority:100,
  canHandle(d,m){return d.provider?.id==='supabase'&&m==='password';},
  availability(d,m){return this.canHandle(d,m)?{supported:true,ready:false,mode:'config-required',reason:'Supabase detectado, mas URL/chave pública necessárias ao fluxo ainda não foram reconstruídas pelo Discovery Engine.'}:{supported:false,ready:false,mode:'none'};},
  async test(){return{status:'NOT_READY',success:null,reason:'Adapter Supabase identificado, mas sem configuração pública reconstruída para executar o fluxo.'};}
};
