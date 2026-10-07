const te=new TextEncoder();
export const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
export const unb64=s=>Uint8Array.from(atob(s.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));
export async function hash(s){return b64(await crypto.subtle.digest('SHA-256',te.encode(s)));}
export async function appJWT(env){
 if(env.APP_VAULT)return env.APP_VAULT.get(env.APP_VAULT.idFromName('personal-app')).appJWT();
 const key=await crypto.subtle.importKey('pkcs8',unb64(env.GITHUB_APP_PRIVATE_KEY.replace(/-----[^-]+-----|\s/g,'')),{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['sign']);
 const now=Math.floor(Date.now()/1000), input=b64(te.encode(JSON.stringify({alg:'RS256',typ:'JWT'})))+'.'+b64(te.encode(JSON.stringify({iat:now-60,exp:now+540,iss:env.GITHUB_APP_ID})));
 return input+'.'+b64(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',key,te.encode(input)));
}
