const origin=process.env.WORKER_ORIGIN;if(!origin)throw Error('WORKER_ORIGIN required');
const u=new URL(origin);if(u.protocol!=='https:'||u.origin!==origin)throw Error('Bare HTTPS origin required');
const options={redirect:'error',signal:AbortSignal.timeout(20000)};
const discovery=await fetch(origin+'/.well-known/oauth-protected-resource/mcp',options);
if(!discovery.ok)throw Error('OAuth resource discovery failed');
const data=await discovery.json();if(data.resource!==origin+'/mcp'||!data.authorization_servers?.length)throw Error('Unexpected resource metadata');
const denied=await fetch(origin+'/mcp',{...options,method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'})});
if(denied.status!==401||!denied.headers.get('www-authenticate')?.includes('resource_metadata='))throw Error('Authentication boundary or audit storage unhealthy');
console.log('Discovery and unauthenticated-denial smoke checks passed');
