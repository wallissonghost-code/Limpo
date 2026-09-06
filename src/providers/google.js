import { createProvider } from './plugin.js';
export default createProvider('google','Google Identity',[
  {regex:/accounts\.google\.com\/gsi\//i,label:'Google Identity endpoint',strength:'strong',weight:10,endpoint:true},
  {regex:/google\.accounts\.id|g_id_onload/i,label:'Google Identity API',strength:'medium',weight:6}
]);
