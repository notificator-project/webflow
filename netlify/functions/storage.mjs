import { getStore } from '@netlify/blobs';

const store = getStore('notificator-webflow');
const installationKey = () => `installation:${process.env.WEBFLOW_INSTALLATION_KEY || 'default'}`;

/** Persist a short-lived OAuth state with its expiry timestamp. */
export async function saveOAuthState(state, record) {
  await store.setJSON(`oauth-state:${state}`, record);
}

/** Read and consume an OAuth state so it cannot be replayed. */
export async function consumeOAuthState(state) {
  if (!state) return null;
  const key = `oauth-state:${state}`;
  const value = await store.get(key, { type: 'json' });
  await store.delete(key);
  return value;
}

/** Persist the current Webflow installation for the configured test account. */
export async function saveInstallation(installation) {
  await store.setJSON(installationKey(), installation);
}

/** Load the Webflow installation after a cold start. */
export async function loadInstallation() {
  return store.get(installationKey(), { type: 'json' });
}
