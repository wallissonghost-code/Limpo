import { createProvider } from './plugin.js';
export default createProvider('keycloak','Keycloak',[
  {regex:/\/realms\/[^/]+\/protocol\/openid-connect\//i,label:'Keycloak OIDC endpoint',strength:'strong',weight:10,endpoint:true},
  {regex:/keycloak-js|new\s+Keycloak|keycloak\.init/i,label:'Keycloak SDK',strength:'medium',weight:6}
]);
