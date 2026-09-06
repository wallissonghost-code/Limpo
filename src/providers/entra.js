import { createProvider } from './plugin.js';
export default createProvider('entra','Microsoft Entra / MSAL',[
  {regex:/login\.microsoftonline\.com\/[a-z0-9-]+\/oauth2\/v2\.0/i,label:'Microsoft Entra OAuth endpoint',strength:'strong',weight:10,endpoint:true},
  {regex:/@azure\/msal|msal-browser|PublicClientApplication/i,label:'MSAL SDK',strength:'medium',weight:6}
]);
