export default {
  id:'interactive-auth',name:'Interactive Authentication',methods:['magicLink','webauthn','mfa'],priority:70,
  canHandle(d,m){return this.methods.includes(m)&&d.capabilities?.[m]===true;},
  availability(d,m){return this.canHandle(d,m)?{supported:true,ready:true,mode:'interactive',reason:`${m} exige interação externa/navegador e não deve ser tratado como e-mail + senha.`}:{supported:false,ready:false,mode:'none'};},
  async test(){return{status:'INTERACTIVE_REQUIRED',success:null,reason:'Este fluxo exige interação do usuário.'};}
};
