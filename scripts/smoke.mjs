const origin=process.env.WORKER_ORIGIN||'https://mcp.vespoli.me',endpoint=origin+'/ghcaretaker';
const options={redirect:'error',signal:AbortSignal.timeout(20000)};
const discovery=await fetch(origin+'/.well-known/oauth-protected-resource/ghcaretaker',options);
if(!discovery.ok)throw Error('OAuth resource discovery failed');
const data=await discovery.json();if(data.resource!==endpoint||data.authorization_servers?.[0]!==endpoint+'/auth')throw Error('Unexpected metadata');
const denied=await fetch(endpoint,{...options,method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'})});
if(denied.status!==401||!denied.headers.get('www-authenticate')?.includes('resource_metadata='))throw Error('Authentication boundary or audit storage unhealthy');
console.log('Discovery and unauthenticated-denial smoke checks passed');
