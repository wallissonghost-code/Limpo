export default {
  id:'oidc',name:'OpenID Connect',methods:['oidc'],priority:85,
  canHandle(d,m){return m==='oidc'&&d.capabilities?.oidc===true;},
  availability(d,m){return this.canHandle(d,m)?{supported:true,ready:true,mode:'interactive',reason:'OIDC normalmente exige redirect/callback e contexto de navegador.'}:{supported:false,ready:false,mode:'none'};},
  async test(){return{status:'INTERACTIVE_REQUIRED',success:null,reason:'OIDC requer fluxo interativo de autorização.'};}
};
