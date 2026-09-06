import { createProvider } from './plugin.js';
export default createProvider('okta','Okta',[
  {regex:/\.okta\.com\/oauth2\/[^/]+\/v1\/(?:authorize|token)/i,label:'Okta OAuth endpoint',strength:'strong',weight:10,endpoint:true},
  {regex:/okta-auth-js|@okta\/|OktaAuth/i,label:'Okta SDK',strength:'medium',weight:6}
]);
