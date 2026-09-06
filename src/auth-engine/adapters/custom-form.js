import { testLogin as legacyPasswordTest } from '../../login-tester.js';

export default {
  id:'custom-form',
  name:'Custom / HTML-JS Password',
  provider:'custom',
  methods:['password'],
  priority:10,
  canHandle(discovery,method){
    if(method!=='password'||discovery.capabilities?.password!==true)return false;
    const provider=discovery.provider?.id||'unknown';
    const protocol=String(discovery.authentication?.protocol||'unknown').toLowerCase();
    return provider==='custom'||provider==='unknown'||protocol==='custom/unknown'||protocol==='unknown';
  },
  availability(discovery,method){
    return this.canHandle(discovery,method)
      ?{supported:true,ready:true,mode:'automated',reason:'Fluxo de senha customizado/genérico detectado; o adaptador tentará reconstruir o formulário ou endpoint público.'}
      :{supported:false,ready:false,mode:'none'};
  },
  async test({url,credentials}){
    return legacyPasswordTest(url,credentials.username,credentials.password);
  }
};
