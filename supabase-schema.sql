-- ============================================================
-- EcoBite — run once in Supabase: SQL Editor -> New query
-- Creates one row per account, holding the details collected
-- on the sign-up form. Auth itself (email/password, sessions)
-- is already handled by Supabase's built-in auth.users table —
-- this just extends it with the role-specific fields.
-- ============================================================

create type public.ecobite_role as enum ('donor', 'org', 'driver');

create table public.profiles (
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

alter table public.profiles enable row level security;

-- Everyone can only ever see, create, or edit their own row —
-- never anyone else's.
create policy "Individuals can view their own profile"
  on public.profiles for select
  using (auth.uid() = id);

create policy "Individuals can insert their own profile"
  on public.profiles for insert
  with check (auth.uid() = id);

create policy "Individuals can update their own profile"
  on public.profiles for update
  using (auth.uid() = id);
