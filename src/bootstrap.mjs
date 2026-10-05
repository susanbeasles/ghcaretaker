import {unb64} from './crypto.mjs';
export async function bootstrapIdentity(request,env,fetcher=fetch){
 if(!env.SETUP_ACCESS_ISSUER||!env.SETUP_ACCESS_AUD||!env.SETUP_OWNER_EMAIL)throw Error('Configure owner-only Cloudflare Access before setup');
 const issuer=new URL(env.SETUP_ACCESS_ISSUER);
 if(issuer.protocol!=='https:'||!issuer.hostname.endsWith('.cloudflareaccess.com')||issuer.origin!==env.SETUP_ACCESS_ISSUER)throw Error('Invalid Access issuer');
 const token=request.headers.get('Cf-Access-Jwt-Assertion');if(!token||token.length>16000)throw Error('Access authentication required');
 const parts=token.split('.');if(parts.length!==3)throw Error('Invalid Access token');
 const decode=s=>JSON.parse(new TextDecoder().decode(unb64(s))),h=decode(parts[0]),c=decode(parts[1]);
 if(h.alg!=='RS256'||typeof h.kid!=='string')throw Error('Invalid Access signature');
 const r=await fetcher(issuer.origin+'/cdn-cgi/access/certs',{redirect:'error',signal:AbortSignal.timeout(10000)});if(!r.ok)throw Error('Access unavailable');
 const keys=(await r.json()).keys?.filter(k=>k.kid===h.kid&&k.kty==='RSA');if(keys?.length!==1)throw Error('Unknown Access key');
 const key=await crypto.subtle.importKey('jwk',keys[0],{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
 if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,unb64(parts[2]),new TextEncoder().encode(parts[0]+'.'+parts[1])))throw Error('Invalid Access signature');
 const now=Date.now()/1000;
 if(c.iss!==issuer.origin||!Array.isArray(c.aud)||!c.aud.includes(env.SETUP_ACCESS_AUD)||!Number.isFinite(c.exp)||c.exp<=now||!Number.isFinite(c.nbf)||c.nbf>now||!c.sub||c.email?.toLowerCase()!==env.SETUP_OWNER_EMAIL.toLowerCase())throw Error('Owner-only Access identity required');
 return c.sub;
}
export const escape=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function page(body,headers={}){return new Response('<!doctype html><meta charset="utf-8"><title>GitHub Caretaker</title><h1>GitHub Caretaker</h1>'+body,{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; form-action 'self' https://github.com; frame-ancestors 'none'; base-uri 'none'",...headers}});}
export function sameOrigin(request,env){if(request.headers.get('Origin')!==env.PUBLIC_ORIGIN)throw Error('Cross-origin submission denied');}
