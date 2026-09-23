# Notificator Webflow App

Initial Webflow integration foundation for Notificator.

## Current foundation

- Webflow OAuth authorization-code flow with CSRF state validation.
- Signed Webflow webhook endpoint at `POST /webhooks/webflow`.
- Connected-site listing at `GET /api/webflow/sites`.
- Webhook registration at `POST /api/webflow/webhooks`.
- Delivery through `@notificator-project/api` using the account-managed MQTT mode.
- Health endpoint at `GET /health`.
- Netlify Function routing for OAuth, site discovery, webhook registration, and webhook delivery.
- Encrypted API-key storage and a first `form_submission` scenario builder.

This is a development scaffold. OAuth tokens and installation metadata are held in memory only; production work must store them encrypted and associate them with the Notificator account and Webflow site.

## Netlify deployment

The included `netlify.toml` maps the public routes to `netlify/functions/webflow.mjs`. Configure the environment variables in Netlify with Functions access, then deploy the repository. The OAuth redirect should point to `/auth/webflow/callback` on the deployed domain.

OAuth state and the current test installation are stored in Netlify Blobs so callbacks survive function cold starts. Set a unique `WEBFLOW_INSTALLATION_KEY` per environment. Before inviting multiple users, move installations, OAuth tokens, webhook IDs, and account associations into encrypted Supabase storage.

## Local setup

```sh
cp .env.example .env
npm install
npm run dev
```

Then open `http://localhost:8787/` to begin OAuth and inspect the connected sites.

The Webflow app must be configured with the exact callback URL from `WEBFLOW_REDIRECT_URI` and a webhook destination of `https://YOUR_HOST/webhooks/webflow`. OAuth webhooks use the app client secret for signature verification; site-token webhooks should set their per-webhook secret in `WEBFLOW_WEBHOOK_SECRET`.

## Netlify test flow

1. Run the Supabase migration in `supabase/migrations/202609230001_webflow_integrations.sql`.
2. Set `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, and a random 32-byte hex `WEBFLOW_ENCRYPTION_KEY` in Netlify.
3. Open the deployed site and connect Webflow.
4. Enter a valid Notificator API key.
5. Select a Webflow site and create the form-submission scenario.
6. Submit the selected form and verify the notification delivery.

The API key and Webflow access token are never returned to the browser after saving. The current schema supports one installation per setup cookie; account ownership and multiple installations should be added through the dashboard/Supabase account model before public release.

## Next milestones

1. Add a small Designer Extension for selecting sites, event types, and notification rules.
2. Persist Webflow installations and webhook IDs in the Notificator backend.
3. Add webhook listing, update, and deletion through the Webflow Data API.
4. Link setup to the existing dashboard API-key/account flow instead of asking for broker credentials.
5. Add delivery history, retry handling, and a Webflow Marketplace-ready consent screen.
