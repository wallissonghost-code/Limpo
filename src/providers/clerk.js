import { createProvider } from './plugin.js';
export default createProvider('clerk','Clerk',[
  {regex:/accounts\.clerk\.com|\.clerk\.accounts/i,label:'Clerk account endpoint',strength:'strong',weight:10,endpoint:true},
  {regex:/@clerk\/|ClerkProvider|clerk-js/i,label:'Clerk SDK',strength:'medium',weight:6}
]);
