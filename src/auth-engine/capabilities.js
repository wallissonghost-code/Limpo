export function inferCapabilities(result){
  const flow=result.flow||{};
  const type=String(result.authentication?.type||'unknown').toLowerCase();
  const protocol=String(result.authentication?.protocol||'unknown').toLowerCase();
  const signals=[...(result.signals||[]),...(result.evidence||[])].map(x=>`${x.type||''} ${x.label||''} ${x.value||''}`).join('\n');
  const text=`${type}\n${protocol}\n${signals}`;

  const password=type==='password'||/password|passwd|senha|sign.?in.?with.?password|grant_type.?password/i.test(text);
  const oauth=/oauth|google|github|facebook|apple|microsoft|social.?login|authorization.?code/i.test(text)||flow.sso===true;
  const oidc=/oidc|openid|\.well-known\/openid-configuration|id_token/i.test(text);
  const magicLink=/magic.?link|sign.?in.?with.?otp|email.?link|otp/i.test(text)||type.includes('magic');
  const webauthn=/webauthn|passkey|publickeycredential/i.test(text)||type==='passkey';
  const mfa=Boolean(result.mfa?.detected)||/mfa|totp|2fa|multi.?factor/i.test(text);

  return {password,oauth,oidc,magicLink,webauthn,mfa};
}
