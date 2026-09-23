import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { URL } from 'node:url';
import 'dotenv/config';
import { NotificatorClient } from '@notificator-project/api';
import { verifyWebflowSignature } from './webflow-security.mjs';

// OAuth state is temporary development state. Production deployments must
// move it, along with installations, into shared encrypted storage.
const port = Number(process.env.PORT || 8787);
const pendingStates = new Map();
let webflowInstallation = null;

/** Read a required configuration value without exposing its contents. */
function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

/** Write a JSON response using the local Node HTTP adapter. */
function sendJson(response, status, body) {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(body));
}

/** Complete an OAuth redirect from the local development server. */
function redirect(response, location) {
  response.writeHead(302, { location });
  response.end();
}

/** Read a request body as bytes so webhook signatures use the exact payload. */
async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks);
}

/** Make an authenticated request to the Webflow Data API. */
async function webflowRequest(path, options = {}) {
  if (!webflowInstallation?.accessToken) {
    throw new Error('Connect a Webflow account first');
  }
  const response = await fetch(`https://api.webflow.com/v2${path}`, {
    ...options,
    headers: {
      accept: 'application/json',
      authorization: `Bearer ${webflowInstallation.accessToken}`,
      ...options.headers,
    },
  });
  const body = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    throw new Error(body?.message || body?.error || `Webflow API returned ${response.status}`);
  }
  return body;
}

/** Build the Webflow authorization URL with the requested least-privilege scopes. */
function webflowAuthorizeUrl(state) {
  const clientId = required('WEBFLOW_CLIENT_ID');
  const redirectUri = required('WEBFLOW_REDIRECT_URI');
  const scopes = process.env.WEBFLOW_SCOPES || 'sites:read forms:read cms:read';
  const url = new URL('https://webflow.com/oauth/authorize');
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', scopes);
  url.searchParams.set('state', state);
  return url;
}

/** Exchange Webflow's short-lived authorization code for an access token. */
async function exchangeWebflowCode(code) {
  const response = await fetch('https://api.webflow.com/oauth/access_token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_id: required('WEBFLOW_CLIENT_ID'),
      client_secret: required('WEBFLOW_CLIENT_SECRET'),
      code,
      redirect_uri: required('WEBFLOW_REDIRECT_URI'),
    }),
  });
  const body = await response.json();
  if (!response.ok) {
    throw new Error(body.error_description || body.error || 'Webflow OAuth failed');
  }
  return body;
}

/** Verify and forward one Webflow event to the Notificator API. */
async function handleWebhook(request, response) {
  const rawBody = await readBody(request);
  if (
    !verifyWebflowSignature(
      rawBody,
      request.headers['x-webflow-timestamp'],
      request.headers['x-webflow-signature'],
      process.env.WEBFLOW_WEBHOOK_SECRET?.trim() || process.env.WEBFLOW_CLIENT_SECRET?.trim(),
    )
  ) {
    return sendJson(response, 401, { error: 'Invalid Webflow webhook signature' });
  }

  const event = JSON.parse(rawBody.toString('utf8'));
  const payload = event.payload || event;
  const title = payload.name || event.triggerType || 'Webflow event';
  const body = payload.siteName ? `${payload.siteName}: ${title}` : `Webflow reported ${title}.`;
  const client = new NotificatorClient({
    apiKey: required('NOTIFICATOR_API_KEY'),
    mqttConnectionMode: 'account',
  });
  await client.notify({
    title,
    body,
    category: 'webflow',
    severity: 'info',
    source: 'webflow',
    data: event,
  });
  return sendJson(response, 200, { accepted: true });
}

// Local HTTP adapter. Netlify uses the equivalent Fetch-style handler in
// netlify/functions/webflow.mjs.
const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

    if (request.method === 'GET' && url.pathname === '/health') {
      return sendJson(response, 200, { ok: true, service: 'notificator-webflow' });
    }

    if (request.method === 'GET' && url.pathname === '/') {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return response.end(
        `<!doctype html><html><head><meta charset="utf-8"><title>Notificator for Webflow</title></head><body><h1>Notificator for Webflow</h1><p>${webflowInstallation ? 'Webflow connected.' : 'Connect Webflow to configure notifications.'}</p><p><a href="/auth/webflow">Connect with Webflow</a></p><p><a href="/api/webflow/sites">View connected sites</a></p></body></html>`,
      );
    }

    if (request.method === 'GET' && url.pathname === '/auth/webflow') {
      // The state value prevents an attacker from injecting an OAuth code.
      const state = randomBytes(24).toString('hex');
      pendingStates.set(state, Date.now() + 10 * 60 * 1000);
      return redirect(response, webflowAuthorizeUrl(state).toString());
    }

    if (request.method === 'GET' && url.pathname === '/auth/webflow/callback') {
      // Consume state once so a valid callback cannot be replayed.
      const stateExpiry = pendingStates.get(url.searchParams.get('state'));
      pendingStates.delete(url.searchParams.get('state'));
      if (!stateExpiry || stateExpiry < Date.now()) {
        return sendJson(response, 400, { error: 'Invalid or expired OAuth state' });
      }
      const code = url.searchParams.get('code');
      if (!code) {
        return sendJson(response, 400, { error: 'Missing OAuth code' });
      }
      const tokens = await exchangeWebflowCode(code);
      webflowInstallation = {
        accessToken: tokens.access_token,
        tokenType: tokens.token_type,
        connectedAt: new Date().toISOString(),
      };
      return sendJson(response, 200, {
        connected: true,
        message:
          'Webflow connected. Store the token in encrypted account storage before production use.',
        tokenType: tokens.token_type,
      });
    }

    if (request.method === 'GET' && url.pathname === '/api/webflow/sites') {
      return sendJson(response, 200, await webflowRequest('/sites'));
    }

    if (request.method === 'POST' && url.pathname === '/api/webflow/webhooks') {
      // Webflow requires sites:write for this registration endpoint.
      const payload = JSON.parse((await readBody(request)).toString('utf8'));
      if (!payload.siteId || !payload.triggerType) {
        return sendJson(response, 400, { error: 'siteId and triggerType are required' });
      }
      const webhook = await webflowRequest(
        `/sites/${encodeURIComponent(payload.siteId)}/webhooks`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            triggerType: payload.triggerType,
            url: payload.url || required('WEBFLOW_WEBHOOK_URL'),
            ...(payload.filter ? { filter: payload.filter } : {}),
          }),
        },
      );
      return sendJson(response, 201, webhook);
    }

    if (request.method === 'POST' && url.pathname === '/webhooks/webflow') {
      return await handleWebhook(request, response);
    }

    return sendJson(response, 404, { error: 'Not found' });
  } catch (error) {
    console.error(error);
    return sendJson(response, 500, { error: error.message || 'Internal server error' });
  }
});

server.listen(port, () => {
  console.log(`Notificator Webflow app listening on http://localhost:${port}`);
});
