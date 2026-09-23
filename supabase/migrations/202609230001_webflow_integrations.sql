-- Webflow installations and notification scenarios for the Notificator app.
-- Tokens are encrypted by the Netlify function before they reach this table.
create table if not exists public.webflow_installations (
  id uuid primary key,
  webflow_site_id text,
  webflow_site_name text,
  webflow_access_token text not null,
  notificator_api_key text,
  status text not null default 'active' check (status in ('active', 'disabled')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index if not exists webflow_installations_site_id_idx
  on public.webflow_installations (webflow_site_id)
  where webflow_site_id is not null;

create table if not exists public.webflow_scenarios (
  id uuid primary key default gen_random_uuid(),
  installation_id uuid not null references public.webflow_installations(id) on delete cascade,
  name text not null,
  trigger_type text not null check (trigger_type in ('form_submission')),
  webhook_id text,
  form_name text,
  title_template text not null default 'New Webflow form submission',
  body_template text not null default 'A new form was submitted on your Webflow site.',
  severity text not null default 'info' check (severity in ('info', 'warning', 'critical')),
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.webflow_installations enable row level security;
alter table public.webflow_installations force row level security;
alter table public.webflow_scenarios enable row level security;
alter table public.webflow_scenarios force row level security;

-- The integration currently uses the server-side service role only. No client
-- role receives access to encrypted credentials or scenario records.
revoke all on public.webflow_installations from public, anon, authenticated;
revoke all on public.webflow_scenarios from public, anon, authenticated;

