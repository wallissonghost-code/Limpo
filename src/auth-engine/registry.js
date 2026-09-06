import firebasePassword from './adapters/firebase-password.js';
import supabasePassword from './adapters/supabase-password.js';
import auth0Password from './adapters/auth0-password.js';
import cognitoPassword from './adapters/cognito-password.js';
import clerkPassword from './adapters/clerk-password.js';
import oauth from './adapters/oauth.js';
import oidc from './adapters/oidc.js';
import interactive from './adapters/interactive.js';
import customForm from './adapters/custom-form.js';

export const adapters=[firebasePassword,supabasePassword,auth0Password,cognitoPassword,clerkPassword,oidc,oauth,interactive,customForm]
  .sort((a,b)=>(b.priority||0)-(a.priority||0));

export function adapterMatrixFor(discovery){
  const methods=['password','oauth','oidc','magicLink','webauthn','mfa'];
  return methods.map(method=>{
    const matches=adapters.filter(a=>a.canHandle?.(discovery,method));
    return {
      method,
      detected:Boolean(discovery.capabilities?.[method]),
      adapters:matches.map(a=>({id:a.id,name:a.name,...a.availability(discovery,method)}))
    };
  });
}

export function findAdapter(discovery,method){
  const matches=adapters.filter(a=>a.canHandle?.(discovery,method));
  const ready=matches.find(a=>a.availability(discovery,method)?.ready);
  return ready||matches[0]||null;
}
