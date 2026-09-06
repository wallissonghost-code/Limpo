export default {
  id:'oauth',name:'OAuth',methods:['oauth'],priority:80,
  canHandle(d,m){return m==='oauth'&&d.capabilities?.oauth===true;},
  availability(d,m){return this.canHandle(d,m)?{supported:true,ready:true,mode:'interactive',reason:'Fluxo OAuth é interativo e deve ser aberto no navegador, não tratado como e-mail + senha.'}:{supported:false,ready:false,mode:'none'};},
  async test(){return{status:'INTERACTIVE_REQUIRED',success:null,reason:'OAuth requer redirecionamento/interação do usuário.'};}
};
