const te=new TextEncoder();
export const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
export const unb64=s=>Uint8Array.from(atob(s.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));
export async function hash(s){return b64(await crypto.subtle.digest('SHA-256',te.encode(s)));}
export async function appJWT(env){
 const key=await crypto.subtle.importKey('pkcs8',unb64(env.GITHUB_APP_PRIVATE_KEY.replace(/-----[^-]+-----|\s/g,'')),{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['sign']);
 const now=Math.floor(Date.now()/1000), input=b64(te.encode(JSON.stringify({alg:'RS256',typ:'JWT'})))+'.'+b64(te.encode(JSON.stringify({iat:now-60,exp:now+540,iss:env.GITHUB_APP_ID})));
 return input+'.'+b64(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',key,te.encode(input)));
}
export async function authenticate(request,env,fetcher=fetch){
 const token=request.headers.get('authorization')?.match(/^Bearer ([A-Za-z0-9_.-]+)$/)?.[1];
 if(!token||token.length>16000) throw Error('Missing or malformed bearer token');
 const parts=token.split('.'); if(parts.length!==3) throw Error('Malformed token');
 const header=JSON.parse(new TextDecoder().decode(unb64(parts[0])));
 if(header.alg!=='RS256'||typeof header.kid!=='string') throw Error('Unsupported signature');
 const u=new URL(env.AUTH_JWKS_URL); if(u.protocol!=='https:'||u.username||u.password) throw Error('Invalid JWKS configuration');
 const r=await fetcher(u,{redirect:'error',signal:AbortSignal.timeout(10000)}); if(!r.ok) throw Error('Identity provider unavailable');
 const keys=(await r.json()).keys; const candidates=keys.filter(k=>k.kid===header.kid&&k.kty==='RSA'&&(!k.alg||k.alg==='RS256')&&(!k.use||k.use==='sig')); if(candidates.length!==1) throw Error('Unknown signing key');
 const key=await crypto.subtle.importKey('jwk',candidates[0],{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
 if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,unb64(parts[2]),te.encode(parts[0]+'.'+parts[1]))) throw Error('Invalid signature');
 const c=JSON.parse(new TextDecoder().decode(unb64(parts[1]))), now=Math.floor(Date.now()/1000);
 if(c.iss!==env.AUTH_ISSUER||!(Array.isArray(c.aud)?c.aud:[c.aud]).includes(env.PUBLIC_ORIGIN+'/mcp')||c.sub!==env.AUTH_SUBJECT||!Number.isFinite(c.exp)||c.exp<=now||c.nbf!==undefined&&(!Number.isFinite(c.nbf)||c.nbf>now)) throw Error('Invalid identity, audience or lifetime');
 const scopes=typeof c.scope==='string'?c.scope.split(' '):[]; if(!scopes.includes('github:read')) throw Error('Read scope required');
 return {subject:c.sub,scopes};
}
