import { parseTarget } from './detector/scanner.js';

const MAX_HTML=900_000;
const TIMEOUT=7000;
const REDIRECTS=4;

function decode(v=''){return String(v).replace(/&quot;/gi,'"').replace(/&#39;/gi,"'").replace(/&amp;/gi,'&').replace(/&lt;/gi,'<').replace(/&gt;/gi,'>');}
function attrs(tag){const out={};const re=/([a-zA-Z_:][-\w:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g;let m;while((m=re.exec(tag)))out[m[1].toLowerCase()]=decode(m[2]??m[3]??m[4]??'');return out;}
function scoreUser(a){let s=0;const v=[a.type,a.name,a.id,a.autocomplete,a.placeholder,a['aria-label']].filter(Boolean).join(' ').toLowerCase();if(a.type==='email')s+=10;if(/\bemail\b|e-mail/.test(v))s+=8;if(/username|user-name|login|usuario|usuário/.test(v))s+=6;if(a.autocomplete==='username'||a.autocomplete==='email')s+=7;if(a.type==='text')s+=1;return s;}
function scorePass(a){let s=0;const v=[a.type,a.name,a.id,a.autocomplete,a.placeholder,a['aria-label']].filter(Boolean).join(' ').toLowerCase();if(a.type==='password')s+=12;if(/password|passwd|senha|pwd/.test(v))s+=8;if(/current-password/.test(a.autocomplete||''))s+=7;return s;}

async function timedFetch(url,options={}){const c=new AbortController();const t=setTimeout(()=>c.abort(),TIMEOUT);try{return await fetch(url,{...options,signal:c.signal});}finally{clearTimeout(t);}}
async function readLimited(r,max=MAX_HTML){const reader=r.body?.getReader();if(!reader)return'';const chunks=[];let total=0;while(true){const {done,value}=await reader.read();if(done)break;const remain=max-total;if(remain<=0)break;const part=value.byteLength>remain?value.slice(0,remain):value;chunks.push(part);total+=part.byteLength;if(value.byteLength>remain)break;}try{await reader.cancel();}catch{}const all=new Uint8Array(total);let o=0;for(const c of chunks){all.set(c,o);o+=c.byteLength;}return new TextDecoder().decode(all);}
async function fetchLoginPage(start){let current=start;for(let i=0;i<=REDIRECTS;i++){const r=await timedFetch(current.toString(),{redirect:'manual',headers:{'user-agent':'LIMPO-Login-Test/1.0','accept':'text/html,application/xhtml+xml,*/*;q=0.5'}});if([301,302,303,307,308].includes(r.status)){const loc=r.headers.get('location');if(!loc)return{response:r,finalUrl:current};current=parseTarget(new URL(loc,current).toString());continue;}return{response:r,finalUrl:current};}throw new Error('Redirecionamentos demais.');}

function chooseForm(html,base){const forms=[...html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi)].map((m,index)=>{const fa=attrs(`<form ${m[1]}>`);const inputs=[...m[2].matchAll(/<input\b[^>]*>/gi)].map(x=>attrs(x[0]));let user=null,pass=null;for(const a of inputs){const us=scoreUser(a),ps=scorePass(a);if(us>0&&(!user||us>user.score))user={a,score:us};if(ps>0&&(!pass||ps>pass.score))pass={a,score:ps};}const score=(user?.score||0)+(pass?.score||0)+(pass?10:0);return{index,fa,inputs,user,pass,score};}).sort((a,b)=>b.score-a.score);
 const best=forms[0];if(!best||!best.user||!best.pass)throw new Error('Não foi possível identificar automaticamente os campos de usuário e senha no mesmo formulário.');
 const action=new URL(best.fa.action||base,base);const baseUrl=new URL(base);if(action.origin!==baseUrl.origin)throw new Error('O formulário envia credenciais para outro domínio. O teste automático foi bloqueado por segurança.');
 const method=(best.fa.method||'get').toLowerCase();if(method!=='post')throw new Error('O formulário não usa POST. O LIMPO não envia senha por GET.');
 const enctype=(best.fa.enctype||'application/x-www-form-urlencoded').toLowerCase();if(!enctype.includes('application/x-www-form-urlencoded'))throw new Error(`Formato de formulário não suportado neste teste: ${enctype}`);
 const hidden=[];for(const a of best.inputs){if((a.type||'').toLowerCase()==='hidden'&&a.name)hidden.push({name:a.name,value:a.value||''});}
 return{action:action.toString(),method,userName:best.user.a.name||null,passName:best.pass.a.name||null,hidden};
}

function looksLikeFailure(text){return /(invalid|incorrect|wrong|failed|erro|inválid|incorret|senha incorreta|credenciais|try again|tente novamente|unauthorized)/i.test(text);}
function stillHasLogin(text){return /<input\b[^>]*type\s*=\s*["']?password/i.test(text)||/(sign\s*in|log\s*in|entrar|acessar)[\s\S]{0,500}(password|senha)/i.test(text);}

export async function testLogin(rawUrl,email,password){if(!email||!password)throw new Error('Informe e-mail/usuário e senha.');if(String(password).length>512||String(email).length>320)throw new Error('Credenciais inválidas.');
 const target=parseTarget(rawUrl);const {response,finalUrl}=await fetchLoginPage(target);const html=await readLimited(response);const form=chooseForm(html,finalUrl.toString());if(!form.userName||!form.passName)throw new Error('Os campos detectados não possuem atributo name; não é possível montar o POST com segurança.');
 const body=new URLSearchParams();for(const h of form.hidden)body.set(h.name,h.value);body.set(form.userName,String(email));body.set(form.passName,String(password));
 const submit=await timedFetch(form.action,{method:'POST',redirect:'manual',headers:{'user-agent':'LIMPO-Login-Test/1.0','accept':'text/html,application/xhtml+xml,application/json,*/*;q=0.5','content-type':'application/x-www-form-urlencoded','origin':new URL(finalUrl).origin,'referer':finalUrl.toString()},body:body.toString()});
 const location=submit.headers.get('location');const cookieSet=!!submit.headers.get('set-cookie');let responseText='';try{responseText=await readLimited(submit,400_000);}catch{}
 let status='LOGIN_INCONCLUSIVE',success=null,reason='A resposta não fornece sinal suficiente para confirmar o resultado.';
 if([301,302,303,307,308].includes(submit.status)&&location){const dest=new URL(location,form.action);if(dest.origin===new URL(form.action).origin&&!/(login|signin|sign-in|auth)/i.test(dest.pathname)){status='LOGIN_SUCCESS';success=true;reason='O servidor redirecionou para fora da rota de login após o POST.';}else if(/login|signin|sign-in|auth/i.test(dest.pathname)){status='LOGIN_FAILED';success=false;reason='O servidor redirecionou de volta para uma rota de login/autenticação.';}}
 if(success===null&&(submit.status===401||submit.status===403)){status='LOGIN_FAILED';success=false;reason=`O servidor respondeu HTTP ${submit.status}.`;}
 if(success===null&&looksLikeFailure(responseText)){status='LOGIN_FAILED';success=false;reason='A resposta contém mensagem compatível com falha de autenticação.';}
 if(success===null&&submit.ok&&cookieSet&&!stillHasLogin(responseText)){status='LOGIN_SUCCESS';success=true;reason='A resposta foi aceita, definiu cookie de sessão e não apresentou novamente o formulário de login.';}
 return{ok:true,status,success,httpStatus:submit.status,loginPage:finalUrl.toString(),submitUrl:form.action,redirectTo:location?new URL(location,form.action).toString():null,sessionCookieSet:cookieSet,reason,note:'Resultado heurístico de uma única tentativa. O LIMPO não retorna nem armazena senha, valor de cookie ou token.'};}
