import { createProvider } from './plugin.js';
export default createProvider('auth0','Auth0',[
  {regex:/[a-z0-9.-]+\.auth0\.com\/(?:authorize|oauth\/token)/i,label:'Auth0 endpoint',strength:'strong',weight:10,endpoint:true},
  {regex:/@auth0\/|createAuth0Client|auth0-spa-js/i,label:'Auth0 SDK',strength:'medium',weight:6},
  {regex:/\.auth0\.com/i,label:'Auth0 domain',strength:'weak',weight:3,endpoint:true}
]);
