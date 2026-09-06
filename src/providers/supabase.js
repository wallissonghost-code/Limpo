import { createProvider } from './plugin.js';
export default createProvider('supabase','Supabase Auth',[
  {regex:/\.supabase\.(?:co|in)\/auth\/v1/i,label:'Supabase Auth endpoint',strength:'strong',weight:10,endpoint:true},
  {regex:/\.supabase\.(?:co|in)\/rest\/v1/i,label:'Supabase REST endpoint',strength:'strong',weight:9,endpoint:true},
  {regex:/\.supabase\.(?:co|in)\/(?:realtime|storage)\/v1/i,label:'Supabase service endpoint',strength:'strong',weight:9,endpoint:true},
  {regex:/\/auth\/v1\/(?:token|authorize|signup|user)/i,label:'Supabase Auth API path',strength:'strong',weight:10,endpoint:true},
  {regex:/@supabase\/supabase-js|supabase-js/i,label:'Supabase JS SDK',strength:'medium',weight:6},
  {regex:/signInWithPassword|signInWithOtp|supabase\.auth/i,label:'Supabase Auth API',strength:'medium',weight:6},
  {regex:/\.supabase\.(?:co|in)/i,label:'Supabase project domain',strength:'weak',weight:3,endpoint:true}
]);
