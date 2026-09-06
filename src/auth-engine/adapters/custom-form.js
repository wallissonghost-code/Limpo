import { testLogin as legacyPasswordTest } from '../../login-tester.js';

export default {
  id:'custom-form',
  name:'Custom / HTML-JS Password',
  methods:['password'],
  priority:10,
  canHandle(discovery,method){return method==='password'&&discovery.capabilities?.password===true;},
  availability(discovery,method){return this.canHandle(discovery,method)?{supported:true,ready:true,mode:'automated'}:{supported:false,ready:false,mode:'none'};},
  async test({url,credentials}){
    return legacyPasswordTest(url,credentials.username,credentials.password);
  }
};
