import { providers } from '../providers/index.js';
import { providerScore, authBehaviorScore } from './scoring.js';

function providerResults(ctx){
  const results=[];
  for(const p of providers){
    const evidence=p.detect(ctx);
    const scored=providerScore(evidence);
    if(scored.score>0)results.push({id:p.id,name:p.name,...scored});
  }
  return results.sort((a,b)=>b.score-a.score);
}

function inferAuthType(ctx){
  if(ctx.authentication.type!=='unknown')return ctx.authentication.type;
  const corpus=ctx.corpus.join('\n');
  if(/webauthn|passkey/i.test(corpus))return 'passkey';
  if(/signInWithOtp|magic[-_ ]?link|otp/i.test(corpus))return 'otp/magic-link';
  if(/type=["']password["']|password/i.test(corpus))return 'password';
  if(ctx.flow.sso)return 'sso';
  return 'unknown';
}

function inferProtocol(ctx,best){
  if(ctx.authentication.protocol!=='unknown')return ctx.authentication.protocol;
  if(['auth0','okta','entra','keycloak'].includes(best?.id))return 'oidc/oauth2';
  if(best?.id==='firebase')return 'firebase-auth-rest';
  if(best?.id==='supabase')return 'supabase-auth';
  return 'custom/unknown';
}

export function classify(ctx){
  const providerCandidates=providerResults(ctx);
  const best=providerCandidates[0]||null;
  const behavior=authBehaviorScore(ctx.signals);
  const providerConfirmed=Boolean(best?.confirmed);
  const authDetected=providerConfirmed||behavior.detected;
  const status=authDetected?'AUTH_DETECTED':(ctx.signals.length||providerCandidates.length?'AUTH_UNKNOWN':'NO_AUTH_EVIDENCE');

  let provider={id:'unknown',name:'Unknown / Custom',confidence:0,score:0,evidence:[]};
  if(providerConfirmed){provider={id:best.id,name:best.name,confidence:best.confidence,score:best.score,evidence:best.evidence};}
  else if(authDetected){provider={id:'custom',name:'Custom / Unknown provider',confidence:behavior.confidence,score:behavior.score,evidence:behavior.signals.slice(0,14)};}
  else if(best){provider={id:'unknown',name:'Unknown / Custom',confidence:best.confidence,score:best.score,evidence:best.evidence};}

  const authentication={
    type:inferAuthType(ctx),
    protocol:inferProtocol(ctx,providerConfirmed?best:null),
    session:ctx.authentication.session,
    token:ctx.authentication.token
  };

  return {
    status,
    detected:status==='AUTH_DETECTED',
    provider,
    authentication,
    flow:{...ctx.flow},
    mfa:{detected:ctx.flow.mfa,methods:[...ctx.mfa.methods]},
    frameworks:[...ctx.frameworks],
    cookieNames:[...ctx.cookieNames],
    signals:behavior.signals.slice(0,30),
    alternatives:providerCandidates.slice(providerConfirmed?1:0,4).map(x=>({id:x.id,name:x.name,score:x.score,confidence:x.confidence,confirmed:x.confirmed})),
    confidence:providerConfirmed?best.confidence:behavior.confidence,
    score:providerConfirmed?best.score:behavior.score
  };
}
