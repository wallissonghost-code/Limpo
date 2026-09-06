import { analyzeUrlInternal } from '../auth-detector.js';
import { inferCapabilities } from './capabilities.js';
import { reconstructRuntimeConfig,publicRuntimeSummary } from './runtime-config.js';
import { reconstructFlowModel,publicFlowSummary } from './flow-reconstructor.js';

export async function discoverAuth(rawUrl){
  const {analysis,ctx}=await analyzeUrlInternal(rawUrl);
  const providerId=analysis.providerId||'unknown';
  const runtime=await reconstructRuntimeConfig(providerId,ctx);
  const flowModel=reconstructFlowModel(providerId,ctx,runtime);
  return {
    status:analysis.status,
    detected:analysis.detected,
    provider:{id:providerId,name:analysis.provider||'Unknown / Custom',confidence:analysis.confidence||0},
    authentication:analysis.authentication,
    capabilities:inferCapabilities(analysis),
    flow:analysis.flow,
    mfa:analysis.mfa,
    frameworks:analysis.frameworks,
    finalUrl:analysis.finalUrl,
    evidence:analysis.evidence,
    signals:analysis.signals,
    alternatives:analysis.alternatives,
    coverage:analysis.coverage,
    runtime,
    flowModel,
    configuration:publicRuntimeSummary(runtime),
    reconstruction:publicFlowSummary(flowModel)
  };
}

export function publicDiscovery(discovery){
  const {runtime,flowModel,...safe}=discovery||{};
  return safe;
}
