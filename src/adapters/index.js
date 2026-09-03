import { firebasePasswordAvailability, testFirebasePassword } from './firebase-password.js';

const DETECTION_ONLY_REASONS = {
  supabase:'supabase_adapter_not_implemented',
  auth0:'auth0_adapter_not_implemented',
  cognito:'cognito_adapter_not_implemented',
  clerk:'clerk_adapter_not_implemented',
  okta:'okta_adapter_not_implemented',
  'entra-id':'entra_id_adapter_not_implemented',
  keycloak:'keycloak_adapter_not_implemented',
  authjs:'authjs_adapter_not_implemented',
  passport:'passport_adapter_not_implemented',
  'jwt-custom':'custom_jwt_flow_requires_manual_review',
  oauth2:'oauth2_flow_requires_manual_review',
  oidc:'oidc_flow_requires_manual_review',
  'custom-or-unknown':'provider_not_supported'
};

export function resolveAdapter(discovery) {
  if (discovery?.provider === 'firebase') {
    const availability = firebasePasswordAvailability(discovery);
    return {
      provider:'firebase',
      adapter:'firebase-password',
      testAvailable:availability.available,
      unavailableReason:availability.reason,
      test:availability.available ? testFirebasePassword : null
    };
  }

  const provider = discovery?.provider || 'custom-or-unknown';
  return {
    provider,
    adapter:null,
    testAvailable:false,
    unavailableReason:DETECTION_ONLY_REASONS[provider] || 'adapter_not_implemented',
    test:null
  };
}
