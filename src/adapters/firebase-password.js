function classifyFirebaseError(code) {
  const value = String(code || 'AUTH_FAILED').toUpperCase();
  if (/TOO_MANY|QUOTA|RATE|TRY_LATER/.test(value)) return 'blocked';
  if (/INVALID_LOGIN_CREDENTIALS|INVALID_PASSWORD|EMAIL_NOT_FOUND/.test(value)) return 'invalid';
  return 'indeterminate';
}

export function firebasePasswordAvailability(discovery) {
  const config = discovery?.adapterHints?.firebase;
  if (discovery?.provider !== 'firebase') {
    return { available:false, adapter:'firebase-password', reason:'provider_not_firebase' };
  }
  if (!config?.apiKey) {
    return { available:false, adapter:'firebase-password', reason:'firebase_api_key_not_discovered' };
  }
  return { available:true, adapter:'firebase-password', reason:null };
}

export async function testFirebasePassword({ discovery, email, password, started = Date.now() }) {
  const availability = firebasePasswordAvailability(discovery);
  if (!availability.available) {
    return {
      httpStatus:200,
      body:{
        ok:true,
        tested:false,
        authenticated:null,
        classification:'not_tested',
        provider:'firebase',
        authType:'detection-only',
        testAvailable:false,
        unavailableReason:availability.reason,
        latencyMs:Date.now()-started
      }
    };
  }

  const config = discovery.adapterHints.firebase;
  const endpoint = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(config.apiKey)}`;
  let response, data;
  try {
    response = await fetch(endpoint, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ email, password, returnSecureToken:true })
    });
    data = await response.json().catch(()=>({}));
  } catch {
    return {
      httpStatus:502,
      body:{ ok:false, tested:true, authenticated:false, classification:'indeterminate', provider:'firebase', authType:'firebase-password', testAvailable:true, error:'provider_unreachable', latencyMs:Date.now()-started }
    };
  }

  const latencyMs = Date.now()-started;
  if (response.ok && data?.localId) {
    return {
      httpStatus:200,
      body:{ ok:true, tested:true, authenticated:true, classification:'authenticated', provider:'firebase', authType:'firebase-password', testAvailable:true, providerHttpStatus:response.status, latencyMs }
    };
  }

  const providerCode = String(data?.error?.message || 'AUTH_FAILED');
  const classification = classifyFirebaseError(providerCode);
  const httpStatus = classification === 'blocked' ? 429 : classification === 'invalid' ? 401 : 200;
  return {
    httpStatus,
    body:{
      ok:classification !== 'blocked' && classification !== 'invalid',
      tested:true,
      authenticated:false,
      classification,
      provider:'firebase',
      authType:'firebase-password',
      testAvailable:true,
      error:classification === 'blocked' ? 'rate_limited' : classification === 'invalid' ? 'invalid_credentials' : 'indeterminate_auth_result',
      providerCode,
      providerHttpStatus:response.status,
      retryAfter:response.headers.get('retry-after') || null,
      latencyMs
    }
  };
}
