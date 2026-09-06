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
async function fetchLoginPage(start){let current=start;for(let i=0;i<=REDIRECTS;i++){const r=await timedFetch(current.toString(),{redirect:'manual',headers:{'user-agent':'LIMPO-Login-Test/1.2','accept':'text/html,application/xhtml+xml,*/*;q=0.5'}});if([301,302,303,307,308].includes(r.status)){const loc=r.headers.get('location');if(!loc)return{response:r,finalUrl:current};current=parseTarget(new URL(loc,current).toString());continue;}return{response:r,finalUrl:current};}throw new Error('Redirecionamentos demais.');}

function discoverJsLoginEndpoint(html,base){const candidates=[];const add=(raw,kind)=>{try{const u=parseTarget(new URL(raw,base).toString());if(u.protocol!=='https:')return;let score=0;if(/\/api\//i.test(u.pathname))score+=2;if(/auth/i.test(u.pathname))score+=3;if(/login|signin|sign-in|authenticate|token/i.test(u.pathname))score+=7;candidates.push({url:u.toString(),kind,score});}catch{}};
 let m;const fetchRe=/fetch\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*\{[\s\S]{0,800}?method\s*:\s*["'`]POST["'`]/gi;while((m=fetchRe.exec(html)))add(m[1],'fetch');
 const axiosRe=/axios\.post\s*\(\s*["'`]([^"'`]+)["'`]/gi;while((m=axiosRe.exec(html)))add(m[1],'axios');
 const generic=/["'`]([^"'`]*(?:\/api\/[^"'`]*|\/auth\/[^"'`]*|\/login\b[^"'`]*|\/signin\b[^"'`]*))["'`]/gi;while((m=generic.exec(html)))add(m[1],'generic');
 return candidates.sort((a,b)=>b.score-a.score)[0]||null;
}

function chooseLoginTransport(html,base){const forms=[...html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi)].map((m,index)=>{const fa=attrs(`<form ${m[1]}>`);const inputs=[...m[2].matchAll(/<input\b[^>]*>/gi)].map(x=>attrs(x[0]));let user=null,pass=null;for(const a of inputs){const us=scoreUser(a),ps=scorePass(a);if(us>0&&(!user||us>user.score))user={a,score:us};if(ps>0&&(!pass||ps>pass.score))pass={a,score:ps};}const score=(user?.score||0)+(pass?.score||0)+(pass?10:0);return{index,fa,inputs,user,pass,score};}).sort((a,b)=>b.score-a.score);
 const best=forms[0];if(!best||!best.user||!best.pass)throw new Error('Não foi possível identificar automaticamente os campos de usuário e senha no mesmo formulário.');
 const userName=best.user.a.name||best.user.a.id||'email';const passName=best.pass.a.name||best.pass.a.id||'password';const baseUrl=new URL(base);
 const method=(best.fa.method||'').toLowerCase();if(method==='post'){
   const action=parseTarget(new URL(best.fa.action||base,base).toString());if(action.protocol!=='https:')throw new Error('O destino do login não usa HTTPS. O LIMPO não envia senha por conexão insegura.');
   const enctype=(best.fa.enctype||'application/x-www-form-urlencoded').toLowerCase();if(!enctype.includes('application/x-www-form-urlencoded'))throw new Error(`Formato de formulário não suportado neste teste: ${enctype}`);
   const hidden=[];for(const a of best.inputs){if((a.type||'').toLowerCase()==='hidden'&&a.name)hidden.push({name:a.name,value:a.value||''});}
   return{transport:'html-form',action:action.toString(),userName,passName,hidden,crossOrigin:action.origin!==baseUrl.origin,submitOrigin:action.origin,contentType:'application/x-www-form-urlencoded'};
 }
 const js=discoverJsLoginEndpoint(html,base);if(js){const action=new URL(js.url);return{transport:'javascript-api',action:js.url,userName,passName,hidden:[],crossOrigin:action.origin!==baseUrl.origin,submitOrigin:action.origin,contentType:'application/json'};}
 if((best.fa.method||'get').toLowerCase()==='get')throw new Error('O HTML sugere envio por GET e nenhum endpoint POST em JavaScript foi identificado. O LIMPO não envia senha pela URL.');
 throw new Error('O formulário parece depender de JavaScript, mas o endpoint de login não pôde ser identificado com segurança.');
}

function looksLikeFailure(text){return /(invalid|incorrect|wrong|failed|erro|inválid|incorret|senha incorreta|credenciais|try again|tente novamente|unauthorized|bad credentials)/i.test(text);}
function looksLikeSuccessJson(text){try{const j=JSON.parse(text);return !!(j&&typeof j==='object'&&(j.success===true||j.authenticated===true||j.access_token||j.accessToken||j.token||j.user));}catch{return false;}}
function stillHasLogin(text){return /<input\b[^>]*type\s*=\s*["']?password/i.test(text)||/(sign\s*in|log\s*in|entrar|acessar)[\s\S]{0,500}(password|senha)/i.test(text);}

export async function testLogin(rawUrl,email,password){if(!email||!password)throw new Error('Informe e-mail/usuário e senha.');if(String(password).length>512||String(email).length>320)throw new Error('Credenciais inválidas.');
 const target=parseTarget(rawUrl);const {response,finalUrl}=await fetchLoginPage(target);const html=await readLimited(response);const login=chooseLoginTransport(html,finalUrl.toString());
 let body,contentType;if(login.transport==='javascript-api'){body=JSON.stringify({[login.userName]:String(email),[login.passName]:String(password)});contentType='application/json';}else{const params=new URLSearchParams();for(const h of login.hidden)params.set(h.name,h.value);params.set(login.userName,String(email));params.set(login.passName,String(password));body=params.toString();contentType='application/x-www-form-urlencoded';}
 const submit=await timedFetch(login.action,{method:'POST',redirect:'manual',headers:{'user-agent':'LIMPO-Login-Test/1.2','accept':'text/html,application/xhtml+xml,application/json,*/*;q=0.5','content-type':contentType,'origin':new URL(finalUrl).origin,'referer':finalUrl.toString()},body});
 const location=submit.headers.get('location');const cookieSet=!!submit.headers.get('set-cookie');let responseText='';try{responseText=await readLimited(submit,400_000);}catch{}
 let status='LOGIN_INCONCLUSIVE',success=null,reason='A resposta não fornece sinal suficiente para confirmar o resultado.';
 if([301,302,303,307,308].includes(submit.status)&&location){const dest=new URL(location,login.action);if(!/(login|signin|sign-in|auth)/i.test(dest.pathname)){status='LOGIN_SUCCESS';success=true;reason='O servidor redirecionou para fora da rota de login após o POST.';}else{status='LOGIN_FAILED';success=false;reason='O servidor redirecionou de volta para uma rota de login/autenticação.';}}
 if(success===null&&(submit.status===401||submit.status===403)){status='LOGIN_FAILED';success=false;reason=`O servidor respondeu HTTP ${submit.status}.`;}
 if(success===null&&looksLikeFailure(responseText)){status='LOGIN_FAILED';success=false;reason='A resposta contém mensagem compatível com falha de autenticação.';}
 if(success===null&&submit.ok&&looksLikeSuccessJson(responseText)){status='LOGIN_SUCCESS';success=true;reason='A API respondeu com estrutura compatível com autenticação bem-sucedida.';}
 if(success===null&&submit.ok&&cookieSet&&!stillHasLogin(responseText)){status='LOGIN_SUCCESS';success=true;reason='A resposta foi aceita, definiu cookie de sessão e não apresentou novamente o formulário de login.';}
 return{ok:true,status,success,httpStatus:submit.status,transport:login.transport,loginPage:finalUrl.toString(),submitUrl:login.action,submitOrigin:login.submitOrigin,crossOrigin:login.crossOrigin,redirectTo:location?new URL(location,login.action).toString():null,sessionCookieSet:cookieSet,reason,note:`Uma única tentativa via ${login.transport==='javascript-api'?'API JavaScript detectada':'formulário HTML'}. ${login.crossOrigin?'O destino de autenticação usa outro domínio HTTPS. ':''}O LIMPO não retorna nem armazena senha, valor de cookie ou token.`};}
