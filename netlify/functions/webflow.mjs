import { randomBytes, randomUUID } from 'node:crypto';
import { NotificatorClient } from '@notificator-project/api';
import { verifyWebflowSignature } from '../../src/webflow-security.mjs';
import { encryptSecret } from '../../src/secret-crypto.mjs';
import {
  getInstallation,
  getInstallationBySite,
  getScenario,
  saveInstallation as saveDatabaseInstallation,
  saveNotificatorKey,
  saveScenario,
  saveSite,
} from './database.mjs';
import { consumeOAuthState, saveOAuthState } from './storage.mjs';

/** Read a required secret or configuration value. */
function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

/** Return a JSON response from the Fetch-style Netlify function. */
function json(body, status = 200) {
  return Response.json(body, { status });
}

/** Redirect the browser to Webflow's OAuth authorization screen. */
function redirect(location) {
  return new Response(null, { status: 302, headers: { location } });
}

/** Read the setup installation ID from the HttpOnly browser cookie. */
function installationId(request) {
  const cookies = request.headers.get('cookie') || '';
  const match = cookies.match(/(?:^|;\s*)notificator_webflow_setup=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

/** Replace simple `{{field}}` placeholders with values from an event payload. */
function renderTemplate(template, payload) {
  return template.replace(/{{\s*([^}\s]+)\s*}}/g, (_, path) => {
    const value = path.split('.').reduce((current, key) => current?.[key], payload);
    return value === undefined || value === null ? '' : String(value);
  });
}

/** Make an authenticated request to Webflow's v2 Data API. */
async function webflowRequest(installation, path, options = {}) {
  if (!installation?.accessToken) throw new Error('Connect a Webflow account first');
  const response = await fetch(`https://api.webflow.com/v2${path}`, {
    ...options,
    headers: {
      accept: 'application/json',
      authorization: `Bearer ${installation.accessToken}`,
      ...options.headers,
    },
  });
  const body = response.status === 204 ? null : await response.json();
  if (!response.ok)
    throw new Error(body?.message || body?.error || `Webflow API returned ${response.status}`);
  return body;
}

/** Build the OAuth URL used by the public Netlify route. */
function authorizeUrl(state) {
  const url = new URL('https://webflow.com/oauth/authorize');
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', required('WEBFLOW_CLIENT_ID'));
  url.searchParams.set('redirect_uri', required('WEBFLOW_REDIRECT_URI'));
  url.searchParams.set(
    'scope',
    process.env.WEBFLOW_SCOPES || 'sites:read sites:write forms:read cms:read',
  );
  url.searchParams.set('state', state);
  return url;
}

/** Exchange the one-time OAuth code for an access token. */
async function exchangeCode(code) {
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
  if (!response.ok) throw new Error(body.error_description || body.error || 'Webflow OAuth failed');
  return body;
}

/** Validate and deliver a signed Webflow event. */
async function handleWebhook(request) {
  const rawBody = await request.text();
  if (
    !verifyWebflowSignature(
      rawBody,
      request.headers.get('x-webflow-timestamp'),
      request.headers.get('x-webflow-signature'),
      process.env.WEBFLOW_WEBHOOK_SECRET?.trim() || process.env.WEBFLOW_CLIENT_SECRET?.trim(),
    )
  ) {
    return json({ error: 'Invalid Webflow webhook signature' }, 401);
  }
  const event = JSON.parse(rawBody);
  const payload = event.payload || event;
  const installation = await getInstallationBySite(payload.siteId);
  if (!installation?.apiKey) return json({ error: 'No Notificator connection for this site' }, 409);
  const scenario = await getScenario(installation.id, event.triggerType);
  if (scenario?.form_name && scenario.form_name !== payload.name) return json({ accepted: true });
  const title = scenario
    ? renderTemplate(scenario.title_template, payload)
    : payload.name || event.triggerType || 'Webflow event';
  const client = new NotificatorClient({
    apiKey: installation.apiKey,
    mqttConnectionMode: 'account',
  });
  await client.notify({
    title,
    body: scenario
      ? renderTemplate(scenario.body_template, payload)
      : payload.siteName
        ? `${payload.siteName}: ${title}`
        : `Webflow reported ${title}.`,
    category: 'webflow',
    severity: scenario?.severity || 'info',
    source: 'webflow',
    data: event,
  });
  return json({ accepted: true });
}

/**
 * Netlify entry point for all Webflow routes.
 *
 * `netlify.toml` adds the route query parameter while preserving the public
 * URL, allowing one function to share authentication and API helpers.
 */
export default async (request) => {
  try {
    const url = new URL(request.url);
    const route = url.searchParams.get('route');

    if (route === 'auth') {
      // State expires quickly and is consumed by the callback below.
      const state = randomBytes(24).toString('hex');
      const id = randomUUID();
      await saveOAuthState(state, { installationId: id, expiresAt: Date.now() + 600000 });
      const response = redirect(authorizeUrl(state).toString());
      response.headers.append(
        'set-cookie',
        `notificator_webflow_setup=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`,
      );
      return response;
    }

    if (route === 'callback') {
      // Never accept an OAuth code without a matching, single-use state.
      const state = url.searchParams.get('state');
      const stateRecord = await consumeOAuthState(state);
      if (!stateRecord || stateRecord.expiresAt < Date.now() || !stateRecord.installationId)
        return json({ error: 'Invalid or expired OAuth state' }, 400);
      const code = url.searchParams.get('code');
      if (!code) return json({ error: 'Missing OAuth code' }, 400);
      const tokens = await exchangeCode(code);
      await saveDatabaseInstallation(stateRecord.installationId, {
        webflow_access_token: encryptSecret(tokens.access_token),
      });
      return new Response(
        '<h1>Webflow connected</h1><p>Return to the setup screen to connect your Notificator account.</p>',
        {
          headers: {
            'content-type': 'text/html; charset=utf-8',
            'set-cookie': `notificator_webflow_setup=${encodeURIComponent(stateRecord.installationId)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`,
          },
        },
      );
    }

    if (route === 'connect') {
      if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
      const id = installationId(request);
      if (!id) return json({ error: 'Connect Webflow before adding a Notificator key' }, 400);
      const { apiKey } = await request.json();
      if (typeof apiKey !== 'string' || !apiKey.trim())
        return json({ error: 'apiKey is required' }, 400);
      const client = new NotificatorClient({ apiKey: apiKey.trim() });
      const metadata = await client.getMetadata();
      await saveNotificatorKey(id, apiKey.trim());
      return json({ connected: true, metadata });
    }

    if (route === 'sites') {
      const installation = await getInstallation(installationId(request));
      if (!installation) return json({ error: 'Connect Webflow first' }, 400);
      return json(await webflowRequest(installation, '/sites'));
    }

    if (route === 'register-webhook') {
      // Register events server-side so Webflow credentials never reach the UI.
      if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
      const payload = await request.json();
      const id = installationId(request);
      const installation = await getInstallation(id);
      if (!installation) return json({ error: 'Connect Webflow first' }, 400);
      if (!installation.apiKey)
        return json({ error: 'Connect your Notificator account first' }, 400);
      if (!payload.siteId || !payload.triggerType)
        return json({ error: 'siteId and triggerType are required' }, 400);
      const webhook = await webflowRequest(
        installation,
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
      await saveSite(id, { id: payload.siteId, name: payload.siteName });
      await saveScenario(id, {
        name: payload.name || 'Webflow form submissions',
        trigger_type: payload.triggerType,
        webhook_id: webhook.id,
        form_name: payload.filter?.name || null,
        title_template: payload.titleTemplate || 'New Webflow form submission',
        body_template: payload.bodyTemplate || 'A new form was submitted on your Webflow site.',
        severity: payload.severity || 'info',
      });
      return json(webhook, 201);
    }

    if (route === 'webhook') return handleWebhook(request);
    return json({ ok: true, service: 'notificator-webflow' });
  } catch (error) {
    console.error(error);
    return json({ error: error.message || 'Internal server error' }, 500);
  }
};
