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

function matchingAdapters(discovery,method){
  return adapters.filter(a=>a.canHandle?.(discovery,method));
}

function describeAdapter(adapter,discovery,method){
  const availability=adapter.availability(discovery,method)||{};
  return {
    id:adapter.id,
    name:adapter.name,
    provider:adapter.provider||'generic',
    priority:adapter.priority||0,
    ...availability
  };
}

export function adapterMatrixFor(discovery){
  const methods=['password','oauth','oidc','magicLink','webauthn','mfa'];
  return methods.map(method=>{
    const matches=matchingAdapters(discovery,method);
    return {
      method,
      detected:Boolean(discovery.capabilities?.[method]),
      adapters:matches.map(a=>describeAdapter(a,discovery,method))
    };
  });
}

export function findAdapter(discovery,method){
  const matches=matchingAdapters(discovery,method);
  if(!matches.length)return null;

  const providerId=discovery.provider?.id||'unknown';
  const specific=matches.filter(a=>a.provider&&a.provider===providerId);
  const pool=specific.length?specific:matches;

  // Provider-specific adapters always win over generic fallbacks. If the
  // specific adapter is not ready, the orchestrator reports CONFIG_REQUIRED
  // instead of silently switching to an unrelated generic transport.
  return pool.find(a=>a.availability(discovery,method)?.ready)||pool[0]||null;
}
