import { createProvider } from './plugin.js';
export default createProvider('firebase','Firebase Authentication',[
  {regex:/identitytoolkit\.googleapis\.com/i,label:'Identity Toolkit endpoint',strength:'strong',weight:10,endpoint:true},
  {regex:/securetoken\.googleapis\.com/i,label:'Secure Token endpoint',strength:'strong',weight:10,endpoint:true},
  {regex:/firebaseinstallations\.googleapis\.com/i,label:'Firebase Installations endpoint',strength:'strong',weight:10,endpoint:true},
  {regex:/accounts:(?:signInWithPassword|signUp|lookup|update)/i,label:'Firebase Auth REST action',strength:'strong',weight:10,endpoint:true},
  {regex:/firebase\/auth|firebase-auth|@firebase\/auth/i,label:'Firebase Auth SDK',strength:'medium',weight:6},
  {regex:/signInWithEmailAndPassword|onAuthStateChanged|initializeAuth\s*\(|getAuth\s*\(/i,label:'Firebase Auth API',strength:'medium',weight:6},
  {regex:/authDomain\s*[:=]|firebaseConfig/i,label:'Firebase public config',strength:'medium',weight:5},
  {regex:/\.firebaseapp\.com|\.web\.app|\.firebaseio\.com|\.firebasedatabase\.app/i,label:'Firebase domain',strength:'weak',weight:3,endpoint:true}
]);
