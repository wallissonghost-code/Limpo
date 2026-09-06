import { parseTarget } from './detector/scanner.js';

const MAX_HTML=900_000;
const MAX_SCRIPT=420_000;
const MAX_MAP=500_000;
const MAX_SCRIPTS=12;
const MAX_MAPS=4;
const TIMEOUT=7000;
const REDIRECTS=4;

function decode(v=''){return String(v).replace(/&quot;/gi,'"').replace(/&#39;/gi,"'").replace(/&amp;/gi,'&').replace(/&lt;/gi,'<').replace(/&gt;/gi,'>');}
function attrs(tag){const out={};const re=/([a-zA-Z_:][-\w:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g;let m;while((m=re.exec(tag)))out[m[1].toLowerCase()]=decode(m[2]??m[3]??m[4]??'');return out;}
function scoreUser(a){let s=0;const v=[a.type,a.name,a.id,a.autocomplete,a.placeholder,a['aria-label']].filter(Boolean).join(' ').toLowerCase();if(a.type==='email')s+=10;if(/\bemail\b|e-mail/.test(v))s+=8;if(/username|user-name|login|usuario|usuário/.test(v))s+=6;if(a.autocomplete==='username'||a.autocomplete==='email')s+=7;if(a.type==='text')s+=1;return s;}
function scorePass(a){let s=0;const v=[a.type,a.name,a.id,a.autocomplete,a.placeholder,a['aria-label']].filter(Boolean).join(' ').toLowerCase();if(a.type==='password')s+=12;if(/password|passwd|senha|pwd/.test(v))s+=8;if(/current-password/.test(a.autocomplete||''))s+=7;return s;}

async function timedFetch(url,options={}){const c=new AbortController();const t=setTimeout(()=>c.abort(),TIMEOUT);try{return await fetch(url,{...options,signal:c.signal});}finally{clearTimeout(t);}}
async function readLimited(r,max=MAX_HTML){const reader=r.body?.getReader();if(!reader)return'';const chunks=[];let total=0;while(true){const {done,value}=await reader.read();if(done)break;const remain=max-total;if(remain<=0)break;const part=value.byteLength>remain?value.slice(0,remain):value;chunks.push(part);total+=part.byteLength;if(value.byteLength>remain)break;}try{await reader.cancel();}catch{}const all=new Uint8Array(total);let o=0;for(const c of chunks){all.set(c,o);o+=c.byteLength;}return new TextDecoder().decode(all);}
async function fetchLoginPage(start){let current=start;for(let i=0;i<=REDIRECTS;i++){const r=await timedFetch(current.toString(),{redirect:'manual',headers:{'user-agent':'LIMPO-Login-Test/1.3','accept':'text/html,application/xhtml+xml,*/*;q=0.5'}});if([301,302,303,307,308].includes(r.status)){const loc=r.headers.get('location');if(!loc)return{response:r,finalUrl:current};current=parseTarget(new URL(loc,current).toString());continue;}return{response:r,finalUrl:current};}throw new Error('Redirecionamentos demais.');}

function addCandidate(list,raw,base,kind,context=''){try{const u=parseTarget(new URL(raw,base).toString());if(u.protocol!=='https:')return;let score=0;const p=u.pathname+u.search;if(/\/api\//i.test(p))score+=3;if(/auth|identity|session/i.test(p))score+=4;if(/login|signin|sign-in|authenticate|token|sessions?/i.test(p))score+=8;if(/password|credential/i.test(context))score+=2;if(/email|username|user/i.test(context))score+=1;if(kind==='fetch-post'||kind==='axios-post'||kind==='xhr-post')score+=5;list.push({url:u.toString(),kind,score,context:context.slice(0,260)});}catch{}}

function discoverFromCode(code,base,candidates){let m;
 const fetchRe=/fetch\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*\{[\s\S]{0,1000}?method\s*:\s*["'`]POST["'`]/gi;while((m=fetchRe.exec(code)))addCandidate(candidates,m[1],base,'fetch-post',code.slice(Math.max(0,m.index-220),m.index+1100));
 const axiosRe=/axios\.post\s*\(\s*["'`]([^"'`]+)["'`]/gi;while((m=axiosRe.exec(code)))addCandidate(candidates,m[1],base,'axios-post',code.slice(Math.max(0,m.index-220),m.index+900));
 const reqRe=/(?:axios\.)?request\s*\(\s*\{[\s\S]{0,700}?url\s*:\s*["'`]([^"'`]+)["'`][\s\S]{0,700}?method\s*:\s*["'`]post["'`]/gi;while((m=reqRe.exec(code)))addCandidate(candidates,m[1],base,'request-post',code.slice(Math.max(0,m.index-220),m.index+1500));
 const xhrRe=/\.open\s*\(\s*["'`]POST["'`]\s*,\s*["'`]([^"'`]+)["'`]/gi;while((m=xhrRe.exec(code)))addCandidate(candidates,m[1],base,'xhr-post',code.slice(Math.max(0,m.index-220),m.index+900));
 const nextRe=/["'`]([^"'`]*(?:\/api\/(?:auth|login|signin|session)[^"'`]*|\/(?:auth|login|signin|sign-in|authenticate|sessions?)(?:\/[^"'`]*)?))["'`]/gi;while((m=nextRe.exec(code)))addCandidate(candidates,m[1],base,'auth-path',code.slice(Math.max(0,m.index-180),m.index+600));
}

function scriptUrls(html,base){const out=[];let m;const re=/<script\b[^>]*\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))[^>]*>/gi;while((m=re.exec(html))&&out.length<MAX_SCRIPTS){try{const u=parseTarget(new URL(decode(m[1]||m[2]||m[3]),base).toString());if(u.protocol==='https:'&&!out.includes(u.toString()))out.push(u.toString());}catch{}}return out;}
function inlineScripts(html){return [...html.matchAll(/<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script\s*>/gi)].map(m=>m[1]).join('\n').slice(0,MAX_SCRIPT);}
function sourceMapUrl(code,scriptUrl){const m=code.match(/[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)/i);if(!m)return null;try{return parseTarget(new URL(m[1].trim(),scriptUrl).toString()).toString();}catch{return null;}}

async function discoverJsLoginEndpoint(html,base){const candidates=[];discoverFromCode(html,base,candidates);const inline=inlineScripts(html);if(inline)discoverFromCode(inline,base,candidates);
 const scripts=scriptUrls(html,base);let scriptsScanned=0,mapsScanned=0;
 for(const url of scripts){try{const r=await timedFetch(url,{headers:{'user-agent':'LIMPO-Login-Test/1.3','accept':'application/javascript,text/javascript,*/*;q=0.5'}});if(!r.ok)continue;const code=await readLimited(r,MAX_SCRIPT);scriptsScanned++;discoverFromCode(code,url,candidates);if(mapsScanned<MAX_MAPS){const map=sourceMapUrl(code,url)||(/\.js(?:\?|$)/i.test(url)?url.replace(/(\.js)(\?.*)?$/i,'$1.map$2'):null);if(map){try{const mr=await timedFetch(map,{headers:{'user-agent':'LIMPO-Login-Test/1.3','accept':'application/json,text/plain,*/*;q=0.5'}});if(mr.ok){const txt=await readLimited(mr,MAX_MAP);mapsScanned++;discoverFromCode(txt,map,candidates);}}catch{}}}}
 catch{}}
 const dedup=new Map();for(const c of candidates){const old=dedup.get(c.url);if(!old||c.score>old.score)dedup.set(c.url,c);}const ranked=[...dedup.values()].sort((a,b)=>b.score-a.score);return{candidate:ranked[0]||null,alternatives:ranked.slice(1,6),scriptsScanned,mapsScanned};}

function detectFields(html){const inputs=[...html.matchAll(/<input\b[^>]*>/gi)].map(x=>attrs(x[0]));let user=null,pass=null;for(const a of inputs){const us=scoreUser(a),ps=scorePass(a);if(us>0&&(!user||us>user.score))user={a,score:us};if(ps>0&&(!pass||ps>pass.score))pass={a,score:ps};}return{user,pass};}

async function chooseLoginTransport(html,base){const forms=[...html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi)].map((m,index)=>{const fa=attrs(`<form ${m[1]}>`);const fields=detectFields(m[2]);const score=(fields.user?.score||0)+(fields.pass?.score||0)+(fields.pass?10:0);return{index,fa,inputs:[...m[2].matchAll(/<input\b[^>]*>/gi)].map(x=>attrs(x[0])),...fields,score};}).sort((a,b)=>b.score-a.score);
 const pageFields=detectFields(html);const best=forms[0];const user=best?.user||pageFields.user;const pass=best?.pass||pageFields.pass;if(!user||!pass)throw new Error('Não foi possível identificar os campos de usuário e senha na página.');
 const userName=user.a.name||user.a.id||(/user/i.test([user.a.placeholder,user.a.autocomplete].join(' '))?'username':'email');const passName=pass.a.name||pass.a.id||'password';const baseUrl=new URL(base);
 if(best){const method=(best.fa.method||'').toLowerCase();if(method==='post'){
   const action=parseTarget(new URL(best.fa.action||base,base).toString());if(action.protocol!=='https:')throw new Error('O destino do login não usa HTTPS. O LIMPO não envia senha por conexão insegura.');
   const enctype=(best.fa.enctype||'application/x-www-form-urlencoded').toLowerCase();if(enctype.includes('application/x-www-form-urlencoded')){const hidden=[];for(const a of best.inputs){if((a.type||'').toLowerCase()==='hidden'&&a.name)hidden.push({name:a.name,value:a.value||''});}return{transport:'html-form',action:action.toString(),userName,passName,hidden,crossOrigin:action.origin!==baseUrl.origin,submitOrigin:action.origin,contentType:'application/x-www-form-urlencoded',discovery:{scriptsScanned:0,mapsScanned:0}};}
 }}
 const js=await discoverJsLoginEndpoint(html,base);if(js.candidate){const action=new URL(js.candidate.url);return{transport:'javascript-api',action:js.candidate.url,userName,passName,hidden:[],crossOrigin:action.origin!==baseUrl.origin,submitOrigin:action.origin,contentType:'application/json',discovery:{scriptsScanned:js.scriptsScanned,mapsScanned:js.mapsScanned,kind:js.candidate.kind,score:js.candidate.score,alternatives:js.alternatives.map(x=>x.url)}};}
 if(best&&(best.fa.method||'get').toLowerCase()==='get')throw new Error(`O HTML sugere envio por GET e nenhum endpoint POST foi identificado após analisar ${js.scriptsScanned} arquivo(s) JavaScript${js.mapsScanned?` e ${js.mapsScanned} source map(s)`:''}. O LIMPO não envia senha pela URL.`);
 throw new Error(`O login depende de JavaScript, mas nenhum endpoint POST confiável foi identificado após analisar ${js.scriptsScanned} arquivo(s) JavaScript${js.mapsScanned?` e ${js.mapsScanned} source map(s)`:''}.`);
}

function looksLikeFailure(text){return /(invalid|incorrect|wrong|failed|erro|inválid|incorret|senha incorreta|credenciais|try again|tente novamente|unauthorized|bad credentials)/i.test(text);}
function looksLikeSuccessJson(text){try{const j=JSON.parse(text);return !!(j&&typeof j==='object'&&(j.success===true||j.authenticated===true||j.access_token||j.accessToken||j.token||j.user));}catch{return false;}}
function stillHasLogin(text){return /<input\b[^>]*type\s*=\s*["']?password/i.test(text)||/(sign\s*in|log\s*in|entrar|acessar)[\s\S]{0,500}(password|senha)/i.test(text);}

export async function testLogin(rawUrl,email,password){if(!email||!password)throw new Error('Informe e-mail/usuário e senha.');if(String(password).length>512||String(email).length>320)throw new Error('Credenciais inválidas.');
 const target=parseTarget(rawUrl);const {response,finalUrl}=await fetchLoginPage(target);const html=await readLimited(response);const login=await chooseLoginTransport(html,finalUrl.toString());
 let body,contentType;if(login.transport==='javascript-api'){body=JSON.stringify({[login.userName]:String(email),[login.passName]:String(password)});contentType='application/json';}else{const params=new URLSearchParams();for(const h of login.hidden)params.set(h.name,h.value);params.set(login.userName,String(email));params.set(login.passName,String(password));body=params.toString();contentType='application/x-www-form-urlencoded';}
 const submit=await timedFetch(login.action,{method:'POST',redirect:'manual',headers:{'user-agent':'LIMPO-Login-Test/1.3','accept':'text/html,application/xhtml+xml,application/json,*/*;q=0.5','content-type':contentType,'origin':new URL(finalUrl).origin,'referer':finalUrl.toString()},body});
 const location=submit.headers.get('location');const cookieSet=!!submit.headers.get('set-cookie');let responseText='';try{responseText=await readLimited(submit,400_000);}catch{}
 let status='LOGIN_INCONCLUSIVE',success=null,reason='A resposta não fornece sinal suficiente para confirmar o resultado.';
 if([301,302,303,307,308].includes(submit.status)&&location){const dest=new URL(location,login.action);if(!/(login|signin|sign-in|auth)/i.test(dest.pathname)){status='LOGIN_SUCCESS';success=true;reason='O servidor redirecionou para fora da rota de login após o POST.';}else{status='LOGIN_FAILED';success=false;reason='O servidor redirecionou de volta para uma rota de login/autenticação.';}}
 if(success===null&&(submit.status===401||submit.status===403)){status='LOGIN_FAILED';success=false;reason=`O servidor respondeu HTTP ${submit.status}.`;}
 if(success===null&&looksLikeFailure(responseText)){status='LOGIN_FAILED';success=false;reason='A resposta contém mensagem compatível com falha de autenticação.';}
 if(success===null&&submit.ok&&looksLikeSuccessJson(responseText)){status='LOGIN_SUCCESS';success=true;reason='A API respondeu com estrutura compatível com autenticação bem-sucedida.';}
 if(success===null&&submit.ok&&cookieSet&&!stillHasLogin(responseText)){status='LOGIN_SUCCESS';success=true;reason='A resposta foi aceita, definiu cookie de sessão e não apresentou novamente o formulário de login.';}
 return{ok:true,status,success,httpStatus:submit.status,transport:login.transport,loginPage:finalUrl.toString(),submitUrl:login.action,submitOrigin:login.submitOrigin,crossOrigin:login.crossOrigin,redirectTo:location?new URL(location,login.action).toString():null,sessionCookieSet:cookieSet,discovery:login.discovery,reason,note:`Uma única tentativa via ${login.transport==='javascript-api'?'API JavaScript detectada':'formulário HTML'}. ${login.crossOrigin?'O destino de autenticação usa outro domínio HTTPS. ':''}O LIMPO não retorna nem armazena senha, valor de cookie ou token.`};}
