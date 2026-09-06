import { createProvider } from './plugin.js';
export default createProvider('passport','Passport.js',[
  {regex:/passport\.authenticate|passport-jwt|passport-local/i,label:'Passport.js',strength:'medium',weight:6}
]);
