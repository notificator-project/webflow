import { createClient } from '@supabase/supabase-js';
import { decryptSecret, encryptSecret } from '../../src/secret-crypto.mjs';

let client;

function supabase() {
  if (!client) {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SECRET_KEY;
    if (!url || !key) throw new Error('Supabase server configuration is missing');
    client = createClient(url, key, { auth: { persistSession: false } });
  }
  return client;
}

/** Create or update the installation represented by the setup cookie. */
export async function saveInstallation(id, values) {
  const { data, error } = await supabase()
    .from('webflow_installations')
    .upsert(
      {
        id,
        ...values,
        updated_at: new Date().toISOString(),
      },
      { onConflict: 'id' },
    )
    .select('id, webflow_site_id, webflow_site_name, status')
    .single();
  if (error) throw new Error(`Unable to save Webflow installation: ${error.message}`);
  return data;
}

/** Load an installation and decrypt its Webflow access token server-side. */
export async function getInstallation(id) {
  const { data, error } = await supabase()
    .from('webflow_installations')
    .select('*')
    .eq('id', id)
    .maybeSingle();
  if (error) throw new Error(`Unable to load Webflow installation: ${error.message}`);
  if (!data) return null;
  return {
    ...data,
    accessToken: decryptSecret(data.webflow_access_token),
    apiKey: data.notificator_api_key ? decryptSecret(data.notificator_api_key) : null,
  };
}

/** Find the installation that owns a Webflow site webhook event. */
export async function getInstallationBySite(siteId) {
  const { data, error } = await supabase()
    .from('webflow_installations')
    .select('*')
    .eq('webflow_site_id', siteId)
    .eq('status', 'active')
    .maybeSingle();
  if (error) throw new Error(`Unable to load Webflow site installation: ${error.message}`);
  if (!data) return null;
  return {
    ...data,
    accessToken: decryptSecret(data.webflow_access_token),
    apiKey: data.notificator_api_key ? decryptSecret(data.notificator_api_key) : null,
  };
}

/** Validate and encrypt the user's Notificator API key. */
export async function saveNotificatorKey(id, apiKey) {
  const { data, error } = await supabase()
    .from('webflow_installations')
    .update({
      notificator_api_key: encryptSecret(apiKey),
      updated_at: new Date().toISOString(),
    })
    .eq('id', id)
    .select('id, webflow_site_id, webflow_site_name, status')
    .single();
  if (error) throw new Error(`Unable to save Notificator connection: ${error.message}`);
  return data;
}

/** Save the selected Webflow site without returning any credentials. */
export async function saveSite(id, site) {
  const { data, error } = await supabase()
    .from('webflow_installations')
    .update({
      webflow_site_id: site.id,
      webflow_site_name: site.name || null,
      updated_at: new Date().toISOString(),
    })
    .eq('id', id)
    .select('id, webflow_site_id, webflow_site_name, status')
    .single();
  if (error) throw new Error(`Unable to save Webflow site: ${error.message}`);
  return data;
}

/** Store the Webflow webhook ID after a scenario is registered. */
export async function saveScenario(id, values) {
  const { data, error } = await supabase()
    .from('webflow_scenarios')
    .insert({ installation_id: id, ...values })
    .select('id, name, trigger_type, webhook_id, enabled')
    .single();
  if (error) throw new Error(`Unable to save Webflow scenario: ${error.message}`);
  return data;
}

/** Load the enabled scenario for an incoming Webflow trigger. */
export async function getScenario(id, triggerType) {
  const { data, error } = await supabase()
    .from('webflow_scenarios')
    .select('title_template, body_template, severity, form_name')
    .eq('installation_id', id)
    .eq('trigger_type', triggerType)
    .eq('enabled', true)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();
  if (error) throw new Error(`Unable to load Webflow scenario: ${error.message}`);
  return data;
}
