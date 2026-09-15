-- ============================================================
-- EcoBite — run once in Supabase: SQL Editor -> New query
-- (Safe to re-run: every statement below is idempotent.)
--
-- Auth itself (email/password, sessions) is handled by Supabase's
-- built-in auth.users table. This file:
--   1. creates a profiles table extending each account with the
--      role-specific details collected on the sign-up form,
--   2. locks it down with row-level security (you only ever see
--      and edit your own row),
--   3. installs a trigger that creates the profile row the moment
--      a user signs up, from the details signup.html passes as
--      sign-up metadata (sb.auth.signUp({ options: { data } })).
--
-- Creating the row inside the database matters: when email
-- confirmation is on, the browser has no session yet right after
-- signUp, so a client-side insert runs as anonymous and RLS
-- rightly blocks it ("new row violates row-level security policy").
-- The trigger runs as the table owner instead, with the details
-- already attached to the user.
-- ============================================================

-- ---- 1. Table -------------------------------------------------

do $$
begin
  create type public.ecobite_role as enum ('donor', 'org', 'driver');
exception
  when duplicate_object then null;  -- type already exists from a previous run
end $$;

create table if not exists public.profiles (
  id               uuid references auth.users(id) on delete cascade primary key,
  role             public.ecobite_role not null,
  full_name        text not null,
  city             text not null,
  org_name         text,           -- donor: business name / org: organisation name
  org_kind         text,           -- donor: restaurant, grocer, bakery...
  reach            text,           -- org: people served per week
  storage          text[],         -- org: chilled / frozen / dry / same-day
  surplus_windows  text[],         -- donor: when surplus usually shows up
  transport        text,           -- driver: on foot / bike / car / van
  availability     text[],         -- driver: when they're usually free
  created_at       timestamptz not null default now()
);

-- ---- 2. Row-level security ------------------------------------

alter table public.profiles enable row level security;

-- Everyone can only ever see, create, or edit their own row —
-- never anyone else's.
drop policy if exists "Individuals can view their own profile" on public.profiles;
create policy "Individuals can view their own profile"
  on public.profiles for select
  using (auth.uid() = id);

drop policy if exists "Individuals can insert their own profile" on public.profiles;
create policy "Individuals can insert their own profile"
  on public.profiles for insert
  with check (auth.uid() = id);

drop policy if exists "Individuals can update their own profile" on public.profiles;
create policy "Individuals can update their own profile"
  on public.profiles for update
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- ---- 3. Auto-create the profile on sign-up ---------------------

-- Turns the JSON arrays from the sign-up form (checkbox lists)
-- into Postgres text[] columns. Missing or non-array values
-- quietly become '{}'.
create or replace function public.jsonb_to_text_array(v jsonb)
returns text[]
language sql
immutable
as $$
  select coalesce(array_agg(x.value order by x.ord), '{}'::text[])
  from jsonb_array_elements_text(
         case when jsonb_typeof(v) = 'array' then v else '[]'::jsonb end
       ) with ordinality as x(value, ord)
$$;

-- security definer: runs as the table owner, so the insert can't be
-- tripped up by RLS or by the session not existing yet mid-signup.
-- search_path is pinned to empty so the function can't be hijacked
-- by a maliciously named object in another schema.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  meta jsonb := new.raw_user_meta_data;
begin
  insert into public.profiles (
    id, role, full_name, city,
    org_name, org_kind, reach, storage, surplus_windows,
    transport, availability
  ) values (
    new.id,
    -- CASE short-circuits, so the enum cast is never attempted for a
    -- value outside the three roles — an odd value degrades to donor
    -- instead of erroring and rolling back the whole sign-up.
    case when meta->>'role' in ('donor','org','driver')
         then (meta->>'role')::public.ecobite_role
         else 'donor'::public.ecobite_role end,
    coalesce(meta->>'full_name', ''),
    coalesce(meta->>'city', ''),
    nullif(meta->>'org_name', ''),
    nullif(meta->>'org_kind', ''),
    nullif(meta->>'reach', ''),
    public.jsonb_to_text_array(meta->'storage'),
    public.jsonb_to_text_array(meta->'surplus_windows'),
    nullif(meta->>'transport', ''),
    public.jsonb_to_text_array(meta->'availability')
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---- 4. One-time repair ----------------------------------------
-- Creates profile rows for accounts that signed up while the old
-- (broken) setup was live, using whatever details they carry as
-- sign-up metadata. Accounts created before the metadata change
-- fall back to a blank donor profile — delete and re-create those
-- in Authentication -> Users if you want their real details.

insert into public.profiles (
  id, role, full_name, city,
  org_name, org_kind, reach, storage, surplus_windows,
  transport, availability
)
select
  u.id,
  case when u.raw_user_meta_data->>'role' in ('donor','org','driver')
       then (u.raw_user_meta_data->>'role')::public.ecobite_role
       else 'donor'::public.ecobite_role end,
  coalesce(u.raw_user_meta_data->>'full_name', ''),
  coalesce(u.raw_user_meta_data->>'city', ''),
  nullif(u.raw_user_meta_data->>'org_name', ''),
  nullif(u.raw_user_meta_data->>'org_kind', ''),
  nullif(u.raw_user_meta_data->>'reach', ''),
  public.jsonb_to_text_array(u.raw_user_meta_data->'storage'),
  public.jsonb_to_text_array(u.raw_user_meta_data->'surplus_windows'),
  nullif(u.raw_user_meta_data->>'transport', ''),
  public.jsonb_to_text_array(u.raw_user_meta_data->'availability')
from auth.users u
where not exists (select 1 from public.profiles p where p.id = u.id);
