import { analyzeUrl } from '../auth-detector.js';
import { inferCapabilities } from './capabilities.js';

export async function discoverAuth(rawUrl){
  const analysis=await analyzeUrl(rawUrl);
  return {
    status:analysis.status,
    detected:analysis.detected,
    provider:{
      id:analysis.providerId||'unknown',
      name:analysis.provider||'Unknown / Custom',
      confidence:analysis.confidence||0
    },
    authentication:analysis.authentication,
    capabilities:inferCapabilities(analysis),
    flow:analysis.flow,
    mfa:analysis.mfa,
    frameworks:analysis.frameworks,
    finalUrl:analysis.finalUrl,
    evidence:analysis.evidence,
    signals:analysis.signals,
    alternatives:analysis.alternatives,
    coverage:analysis.coverage
  };
}
