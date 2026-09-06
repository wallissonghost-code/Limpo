import { createProvider } from './plugin.js';
export default createProvider('cognito','AWS Cognito',[
  {regex:/cognito-idp\.[a-z0-9-]+\.amazonaws\.com/i,label:'Cognito IdP endpoint',strength:'strong',weight:10,endpoint:true},
  {regex:/\.auth\.[a-z0-9-]+\.amazoncognito\.com/i,label:'Cognito hosted UI',strength:'strong',weight:9,endpoint:true},
  {regex:/amazon-cognito-identity-js|CognitoUserPool/i,label:'Cognito SDK',strength:'medium',weight:6}
]);
