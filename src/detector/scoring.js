export function providerScore(evidence=[]) {
  const dedup = new Map();
  for (const e of evidence) {
    const key=`${e.type}|${e.value||''}|${e.label||''}`;
    if (!dedup.has(key) || (dedup.get(key).weight||0) < (e.weight||0)) dedup.set(key,e);
  }
  const items=[...dedup.values()];
  const score=items.reduce((n,e)=>n+(e.weight||0),0);
  const strong=items.filter(e=>e.strength==='strong').length;
  const medium=items.filter(e=>e.strength==='medium').length;
  const weak=items.filter(e=>e.strength==='weak').length;
  const confirmed = strong>=1 || medium>=2 || (medium>=1 && weak>=2 && score>=10);
  const confidence = confirmed
    ? Math.min(99, Math.round(68 + Math.min(31, score*1.65 + strong*7)))
    : Math.min(69, Math.round(score*5));
  return {score,strong,medium,weak,confirmed,confidence,evidence:items.sort((a,b)=>(b.weight||0)-(a.weight||0))};
}

export function authBehaviorScore(signals=[]) {
  const relevant=signals.filter(s=>!["framework_hint"].includes(s.type));
  const unique=new Map();
  for(const s of relevant){
    const key=`${s.type}|${s.value||''}`;
    if(!unique.has(key) || (unique.get(key).weight||0)<(s.weight||0)) unique.set(key,s);
  }
  const items=[...unique.values()];
  const score=items.reduce((n,s)=>n+(s.weight||0),0);
  const strong=items.filter(x=>x.strength==='strong').length;
  const medium=items.filter(x=>x.strength==='medium').length;
  const behavioral = items.filter(x=>/endpoint|token|cookie|login_form|credentialed|authorization|jwt|oidc|oauth|auth_storage|mfa/i.test(x.type)).length;
  const detected = strong>=1 || medium>=2 || behavioral>=3 || score>=10;
  return {
    score,
    detected,
    confidence: detected ? Math.min(96,Math.round(55+score*2.4+strong*5)) : Math.min(55,score*4),
    signals: items.sort((a,b)=>(b.weight||0)-(a.weight||0))
  };
}
