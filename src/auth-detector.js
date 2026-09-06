import { scanTarget } from './detector/scanner.js';
import { classify } from './detector/classifier.js';
import { runPublicProbes } from './detector/probes.js';
import { detectGenericAuth } from './detector/generic.js';

function publicContext(ctx){
  return {
    requestedUrl:ctx.requestedUrl,
    finalUrl:ctx.finalUrl,
    httpStatus:ctx.httpStatus,
    coverage:ctx.coverage
  };
}

function toPublicResult(ctx,result){
  const note = result.status==='AUTH_DETECTED'
    ? 'Autenticação detectada a partir de sinais públicos. A classificação do provedor é separada do tipo/protocolo de autenticação.'
    : result.status==='AUTH_UNKNOWN'
      ? 'Há indícios relacionados a autenticação, mas não há evidência suficiente para identificar com segurança o provedor ou o fluxo completo.'
      : 'Nenhuma evidência pública suficiente foi encontrada. Isso não prova que o site não possua autenticação; ela pode estar totalmente no backend ou fora da cobertura da análise.';

  return {
    ok:true,
    ...publicContext(ctx),
    analyzedBytes:ctx.coverage.totalBytes,
    status:result.status,
    detected:result.detected,
    provider:result.provider.name,
    providerId:result.provider.id,
    confidence:result.confidence,
    score:result.score,
    evidence:result.provider.evidence.slice(0,20),
    authentication:result.authentication,
    flow:result.flow,
    mfa:result.mfa,
    frameworks:result.frameworks,
    cookieNames:result.cookieNames,
    signals:result.signals,
    alternatives:result.alternatives,
    note
  };
}

export async function analyzeUrlInternal(rawUrl){
  const ctx=await scanTarget(rawUrl);
  await runPublicProbes(ctx,ctx.finalUrl,ctx.corpus.join('\n'));
  detectGenericAuth(ctx);
  const result=classify(ctx);
  return {analysis:toPublicResult(ctx,result),ctx,result};
}

export async function analyzeUrl(rawUrl){
  const {analysis}=await analyzeUrlInternal(rawUrl);
  return analysis;
}
