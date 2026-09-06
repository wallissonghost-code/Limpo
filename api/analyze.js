import dns from 'node:dns/promises';
import net from 'node:net';

const MAX_BYTES = 1_500_000;
const TIMEOUT_MS = 10_000;

const PROVIDERS = [
  {
    id: 'firebase',
    name: 'Firebase Authentication',
    patterns: [
      ['identitytoolkit.googleapis.com', 40],
      ['securetoken.googleapis.com', 35],
      ['firebase-auth', 30],
      ['firebaseapp.com', 18],
      ['firebaseConfig', 15],
      ['initializeAuth(', 20],
      ['getAuth(', 15],
      ['signInWithEmailAndPassword', 25],
      ['signInWithPopup', 18]
    ]
  },
  {
    id: 'supabase',
    name: 'Supabase Auth',
    patterns: [
      ['supabase.co/auth/v1', 45],
      ['/auth/v1/token', 35],
      ['@supabase/supabase-js', 30],
      ['createClient(', 12],
      ['supabase.auth', 30]
    ]
  },
  {
    id: 'auth0',
    name: 'Auth0',
    patterns: [
      ['auth0.com', 35],
      ['cdn.auth0.com', 30],
      ['@auth0/', 25],
      ['createAuth0Client', 30],
      ['authorize?', 8]
    ]
  },
  {
    id: 'clerk',
    name: 'Clerk',
    patterns: [
      ['clerk.com', 30],
      ['clerk.accounts', 35],
      ['@clerk/', 30],
      ['ClerkProvider', 25],
      ['clerk-js', 25]
    ]
  },
  {
    id: 'cognito',
    name: 'AWS Cognito',
    patterns: [
      ['amazoncognito.com', 40],
      ['cognito-idp.', 35],
      ['amazon-cognito-identity-js', 35],
      ['CognitoUserPool', 30],
      ['Auth.signIn', 18]
    ]
  },
  {
    id: 'keycloak',
    name: 'Keycloak',
    patterns: [
      ['/realms/', 20],
      ['/protocol/openid-connect/', 45],
      ['keycloak-js', 35],
      ['new Keycloak', 30],
      ['keycloak.init', 25]
    ]
  },
  {
    id: 'okta',
    name: 'Okta',
    patterns: [
      ['okta.com', 35],
      ['okta-auth-js', 35],
      ['@okta/', 30],
      ['OktaAuth', 30]
    ]
  },
  {
    id: 'entra',
    name: 'Microsoft Entra / MSAL',
    patterns: [
      ['login.microsoftonline.com', 45],
      ['@azure/msal', 35],
      ['msal-browser', 30],
      ['PublicClientApplication', 30]
    ]
  },
  {
    id: 'google',
    name: 'Google Identity',
    patterns: [
      ['accounts.google.com/gsi', 45],
      ['google.accounts.id', 40],
      ['g_id_onload', 30]
    ]
  },
  {
    id: 'authjs',
    name: 'Auth.js / NextAuth',
    patterns: [
      ['/api/auth/session', 35],
      ['/api/auth/signin', 35],
      ['next-auth', 35],
      ['SessionProvider', 20],
      ['getSession(', 15]
    ]
  }
];

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || (p[0] === 169 && p[1] === 254) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) ||
      p[0] === 0 || p[0] >= 224;
  }
  if (net.isIPv6(ip)) {
    const x = ip.toLowerCase();
    return x === '::1' || x === '::' || x.startsWith('fc') || x.startsWith('fd') || x.startsWith('fe8') || x.startsWith('fe9') || x.startsWith('fea') || x.startsWith('feb');
  }
  return true;
}

async function assertPublicUrl(raw) {
  let url;
  try { url = new URL(raw); } catch { throw new Error('URL inválida.'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Use apenas URLs HTTP ou HTTPS.');
  const host = url.hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.local')) throw new Error('Endereço local não permitido.');
  if (net.isIP(host) && isPrivateIp(host)) throw new Error('IP privado/reservado não permitido.');

  const records = await dns.lookup(host, { all: true, verbatim: true });
  if (!records.length || records.some(r => isPrivateIp(r.address))) throw new Error('Destino privado/reservado não permitido.');
  return url;
}

function confidence(score) {
  if (score >= 80) return 99;
  if (score >= 60) return 94;
  if (score >= 45) return 88;
  if (score >= 30) return 78;
  if (score >= 18) return 66;
  return Math.max(20, Math.min(60, score * 3));
}

function detect(body, finalUrl, headers) {
  const corpus = `${finalUrl}\n${body}\n${JSON.stringify(headers)}`;
  const lower = corpus.toLowerCase();

  const matches = PROVIDERS.map(provider => {
    let score = 0;
    const evidence = [];
    for (const [pattern, weight] of provider.patterns) {
      if (lower.includes(pattern.toLowerCase())) {
        score += weight;
        evidence.push(pattern);
      }
    }
    return { ...provider, score, evidence };
  }).filter(x => x.score > 0).sort((a, b) => b.score - a.score);

  if (!matches.length) {
    return {
      detected: false,
      provider: 'Não identificado',
      confidence: 0,
      evidence: [],
      alternatives: [],
      note: 'Nenhuma assinatura pública forte foi encontrada. O login pode usar autenticação própria ou ocultar o provedor no backend.'
    };
  }

  const best = matches[0];
  return {
    detected: true,
    provider: best.name,
    providerId: best.id,
    confidence: confidence(best.score),
    score: best.score,
    evidence: best.evidence.slice(0, 8),
    alternatives: matches.slice(1, 4).map(x => ({ provider: x.name, score: x.score, evidence: x.evidence.slice(0, 4) })),
    note: 'Resultado baseado somente em indícios públicos expostos pelo frontend.'
  };
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Use POST.' });

  try {
    const rawUrl = typeof req.body === 'string' ? JSON.parse(req.body).url : req.body?.url;
    if (!rawUrl) return res.status(400).json({ error: 'Informe uma URL.' });

    const target = await assertPublicUrl(rawUrl.trim());
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

    const response = await fetch(target, {
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'user-agent': 'AuthTechnologyDetector/1.0 (+public-signature-analysis)',
        'accept': 'text/html,application/xhtml+xml,*/*;q=0.8'
      }
    });
    clearTimeout(timer);

    const finalUrl = await assertPublicUrl(response.url);
    const type = response.headers.get('content-type') || '';
    if (!type.includes('text/html') && !type.includes('text/plain') && !type.includes('javascript')) {
      return res.status(415).json({ error: `Conteúdo não analisável: ${type || 'tipo desconhecido'}` });
    }

    const reader = response.body?.getReader();
    let total = 0;
    const chunks = [];
    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_BYTES) break;
        chunks.push(value);
      }
    }
    const body = new TextDecoder().decode(Buffer.concat(chunks.map(x => Buffer.from(x))));
    const selectedHeaders = {
      server: response.headers.get('server'),
      'www-authenticate': response.headers.get('www-authenticate'),
      'x-powered-by': response.headers.get('x-powered-by')
    };

    const result = detect(body, finalUrl.toString(), selectedHeaders);
    return res.status(200).json({
      ok: true,
      requestedUrl: target.toString(),
      finalUrl: finalUrl.toString(),
      httpStatus: response.status,
      analyzedBytes: Math.min(total, MAX_BYTES),
      ...result
    });
  } catch (error) {
    const message = error?.name === 'AbortError' ? 'A análise excedeu o tempo limite.' : (error?.message || 'Falha ao analisar a URL.');
    return res.status(400).json({ error: message });
  }
}
