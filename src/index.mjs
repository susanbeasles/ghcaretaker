import {controlRedirect,gatewayRequest} from './ingress.mjs';
import {handleWebhook} from './webhook.mjs';
import {handleDashboard} from './dashboard.mjs';
export {AppVault} from './vault.mjs';
export {CaretakerCapability} from './rpc.mjs';
export {EventLedger,CommitLedger} from './ledgers.mjs';
function mcp(request,env){const u=new URL(request.url);if(u.origin!==env.PUBLIC_ORIGIN)return new Response('Not found',{status:404});if(u.pathname===env.MCP_PATH+'/health')return Response.json({service:'ghcaretaker',auth_gate:env.AUTH_ORIGIN},{headers:{'cache-control':'no-store'}});if(u.pathname===env.MCP_PATH+'/setup'||u.pathname.startsWith(env.MCP_PATH+'/setup/'))return Response.redirect(controlRedirect(request,env),303);if(u.pathname===env.MCP_PATH||u.pathname.startsWith(env.MCP_PATH+'/auth/')||u.pathname.startsWith('/.well-known/'))return env.AUTH_GATEWAY.fetch(gatewayRequest(request,env));return new Response('Not found',{status:404});}
// Host dispatch: the webhook hostname serves exactly POST /github and nothing else; the dashboard hostname serves only
// the Access-verified dashboard (src/dashboard.mjs); every other host keeps the MCP rules.
export default {async fetch(request,env){const u=new URL(request.url);if(env.HOOKS_ORIGIN&&u.origin===env.HOOKS_ORIGIN)return handleWebhook(request,env);
if(env.DASHBOARD_ORIGIN&&u.origin===env.DASHBOARD_ORIGIN)return handleDashboard(request,env);
return mcp(request,env);}};
