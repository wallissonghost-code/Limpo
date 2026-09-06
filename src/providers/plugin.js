export function createProvider(id,name,signatures){
  return {
    id,name,
    detect(ctx){
      const evidence=[];
      const corpus=ctx._providerCorpus ?? (ctx._providerCorpus=ctx.corpus.join('\n'));
      for(const s of signatures){
        const m=corpus.match(s.regex);
        if(m)evidence.push({provider:id,type:s.type||'provider_signal',label:s.label,value:m[0].slice(0,220),source:'corpus',strength:s.strength,weight:s.weight});
      }
      for(const ep of ctx.endpoints){
        for(const s of signatures){
          if(!s.endpoint)continue;
          const m=ep.match(s.regex);
          if(m)evidence.push({provider:id,type:s.type||'provider_endpoint',label:s.label,value:ep,source:'endpoint',strength:s.strength,weight:s.weight});
        }
      }
      return evidence;
    }
  };
}
