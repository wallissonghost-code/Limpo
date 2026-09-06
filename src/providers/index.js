const plugin=(id,name,signatures)=>({
  id,name,
  detect(ctx){
    const evidence=[];
    const corpus=ctx._providerCorpus ?? (ctx._providerCorpus=ctx.corpus.join('\n'));
    for(const s of signatures){
      const m=corpus.match(s.regex);
      if(m)evidence.push({provider:id,type:s.type||'provider_signal',label:s.label,value:m[0].slice(0,220),source:'corpus',strength:s.strength,weight:s.weight});
    }
    for(const ep of ctx.endpoints){
      for(const s of signatures.filter(x=>x.endpoint)){
        const m=ep.match(s.regex);
        if(m)evidence.push({provider:id,type:s.type||'provider_endpoint',label:s.label,value:ep,source:'endpoint',strength:s.strength,weight:s.weight});
      }
    }
    return evidence;
  }
});

export const providers=[
  plugin('firebase','Firebase Authentication',[
    {regex:/identitytoolkit\.googleapis\.com/i,label:'Identity Toolkit endpoint',strength:'strong',weight:10,endpoint:true},
    {regex:/securetoken\.googleapis\.com/i,label:'Secure Token endpoint',strength:'strong',weight:10,endpoint:true},
    {regex:/firebaseinstallations\.googleapis\.com/i,label:'Firebase Installations endpoint',strength:'strong',weight:10,endpoint:true},
    {regex:/accounts:(?:signInWithPassword|signUp|lookup|update)/i,label:'Firebase Auth REST action',strength:'strong',weight:10,endpoint:true},
    {regex:/firebase\/auth|firebase-auth|@firebase\/auth/i,label:'Firebase Auth SDK',strength:'medium',weight:6},
    {regex:/signInWithEmailAndPassword|onAuthStateChanged|initializeAuth\s*\(|getAuth\s*\(/i,label:'Firebase Auth API',strength:'medium',weight:6},
    {regex:/authDomain\s*[:=]|firebaseConfig/i,label:'Firebase public config',strength:'medium',weight:5},
    {regex:/\.firebaseapp\.com|\.web\.app|\.firebaseio\.com|\.firebasedatabase\.app/i,label:'Firebase domain',strength:'weak',weight:3,endpoint:true}
  ]),
  plugin('supabase','Supabase Auth',[
    {regex:/\.supabase\.(?:co|in)\/auth\/v1/i,label:'Supabase Auth endpoint',strength:'strong',weight:10,endpoint:true},
    {regex:/\.supabase\.(?:co|in)\/rest\/v1/i,label:'Supabase REST endpoint',strength:'strong',weight:9,endpoint:true},
    {regex:/\.supabase\.(?:co|in)\/(?:realtime|storage)\/v1/i,label:'Supabase service endpoint',strength:'strong',weight:9,endpoint:true},
    {regex:/\/auth\/v1\/(?:token|authorize|signup|user)/i,label:'Supabase Auth API path',strength:'strong',weight:10,endpoint:true},
    {regex:/@supabase\/supabase-js|supabase-js/i,label:'Supabase JS SDK',strength:'medium',weight:6},
    {regex:/signInWithPassword|signInWithOtp|supabase\.auth/i,label:'Supabase Auth API',strength:'medium',weight:6},
    {regex:/\.supabase\.(?:co|in)/i,label:'Supabase project domain',strength:'weak',weight:3,endpoint:true}
  ]),
  plugin('auth0','Auth0',[
    {regex:/[a-z0-9.-]+\.auth0\.com\/(?:authorize|oauth\/token)/i,label:'Auth0 endpoint',strength:'strong',weight:10,endpoint:true},
    {regex:/@auth0\/|createAuth0Client|auth0-spa-js/i,label:'Auth0 SDK',strength:'medium',weight:6},
    {regex:/\.auth0\.com/i,label:'Auth0 domain',strength:'weak',weight:3,endpoint:true}
  ]),
  plugin('clerk','Clerk',[
    {regex:/accounts\.clerk\.com|\.clerk\.accounts/i,label:'Clerk account endpoint',strength:'strong',weight:10,endpoint:true},
    {regex:/@clerk\/|ClerkProvider|clerk-js/i,label:'Clerk SDK',strength:'medium',weight:6}
  ]),
  plugin('cognito','AWS Cognito',[
    {regex:/cognito-idp\.[a-z0-9-]+\.amazonaws\.com/i,label:'Cognito IdP endpoint',strength:'strong',weight:10,endpoint:true},
    {regex:/\.auth\.[a-z0-9-]+\.amazoncognito\.com/i,label:'Cognito hosted UI',strength:'strong',weight:9,endpoint:true},
    {regex:/amazon-cognito-identity-js|CognitoUserPool/i,label:'Cognito SDK',strength:'medium',weight:6}
  ]),
  plugin('keycloak','Keycloak',[
    {regex:/\/realms\/[^/]+\/protocol\/openid-connect\//i,label:'Keycloak OIDC endpoint',strength:'strong',weight:10,endpoint:true},
    {regex:/keycloak-js|new\s+Keycloak|keycloak\.init/i,label:'Keycloak SDK',strength:'medium',weight:6}
  ]),
  plugin('okta','Okta',[
    {regex:/\.okta\.com\/oauth2\/[^/]+\/v1\/(?:authorize|token)/i,label:'Okta OAuth endpoint',strength:'strong',weight:10,endpoint:true},
    {regex:/okta-auth-js|@okta\/|OktaAuth/i,label:'Okta SDK',strength:'medium',weight:6}
  ]),
  plugin('entra','Microsoft Entra / MSAL',[
    {regex:/login\.microsoftonline\.com\/[a-z0-9-]+\/oauth2\/v2\.0/i,label:'Microsoft Entra OAuth endpoint',strength:'strong',weight:10,endpoint:true},
    {regex:/@azure\/msal|msal-browser|PublicClientApplication/i,label:'MSAL SDK',strength:'medium',weight:6}
  ]),
  plugin('google','Google Identity',[
    {regex:/accounts\.google\.com\/gsi\//i,label:'Google Identity endpoint',strength:'strong',weight:10,endpoint:true},
    {regex:/google\.accounts\.id|g_id_onload/i,label:'Google Identity API',strength:'medium',weight:6}
  ]),
  plugin('authjs','Auth.js / NextAuth',[
    {regex:/\/api\/auth\/(?:session|signin|callback|providers)/i,label:'Auth.js route',strength:'strong',weight:9,endpoint:true},
    {regex:/next-auth|@auth\/|SessionProvider/i,label:'Auth.js SDK',strength:'medium',weight:6}
  ]),
  plugin('passport','Passport.js',[
    {regex:/passport\.authenticate|passport-jwt|passport-local/i,label:'Passport.js',strength:'medium',weight:6}
  ])
];
