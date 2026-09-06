function first(text,patterns){
  for(const re of patterns){const m=text.match(re);if(m?.[1])return m[1];}
  return null;
}

function firebaseConfig(corpus){
  const text=String(corpus||'');
  const apiKey=first(text,[
    /\bapiKey\s*[:=]\s*["'`]([A-Za-z0-9_\-]{20,})["'`]/i,
    /[?&]key=([A-Za-z0-9_\-]{20,})/i,
    /"apiKey"\s*:\s*"([A-Za-z0-9_\-]{20,})"/i
  ]);
  const authDomain=first(text,[/\bauthDomain\s*[:=]\s*["'`]([^"'`\s]+)["'`]/i,/"authDomain"\s*:\s*"([^"]+)"/i]);
  const projectId=first(text,[/\bprojectId\s*[:=]\s*["'`]([^"'`\s]+)["'`]/i,/"projectId"\s*:\s*"([^"]+)"/i]);
  const passwordFlow=/signInWithEmailAndPassword|accounts:signInWithPassword|EMAIL_PASSWORD_SIGN_IN/i.test(text);
  return {apiKey,authDomain,projectId,passwordFlow};
}

function supabaseConfig(corpus){
  const text=String(corpus||'');
  const url=first(text,[
    /\b(?:supabaseUrl|SUPABASE_URL|NEXT_PUBLIC_SUPABASE_URL)\s*[:=]\s*["'`](https:\/\/[^"'`\s]+)["'`]/i,
    /(https:\/\/[a-z0-9-]+\.supabase\.co)/i
  ]);
  const anonKey=first(text,[
    /\b(?:supabaseAnonKey|SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_ANON_KEY)\s*[:=]\s*["'`]([^"'`\s]{40,})["'`]/i
  ]);
  return {url,anonKey,passwordFlow:/signInWithPassword|grant_type=password/i.test(text)};
}

export function extractRuntimeConfig(providerId,ctx){
  const corpus=(ctx?.corpus||[]).join('\n');
  if(providerId==='firebase')return {firebase:firebaseConfig(corpus)};
  if(providerId==='supabase')return {supabase:supabaseConfig(corpus)};
  return {};
}

export function publicRuntimeSummary(runtime={}){
  const out={};
  if(runtime.firebase)out.firebase={apiKey:Boolean(runtime.firebase.apiKey),authDomain:Boolean(runtime.firebase.authDomain),projectId:Boolean(runtime.firebase.projectId),passwordFlow:Boolean(runtime.firebase.passwordFlow)};
  if(runtime.supabase)out.supabase={url:Boolean(runtime.supabase.url),anonKey:Boolean(runtime.supabase.anonKey),passwordFlow:Boolean(runtime.supabase.passwordFlow)};
  return out;
}
