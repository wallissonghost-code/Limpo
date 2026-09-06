import { createProvider } from './plugin.js';
export default createProvider('authjs','Auth.js / NextAuth',[
  {regex:/\/api\/auth\/(?:session|signin|callback|providers)/i,label:'Auth.js route',strength:'strong',weight:9,endpoint:true},
  {regex:/next-auth|@auth\/|SessionProvider/i,label:'Auth.js SDK',strength:'medium',weight:6}
]);
