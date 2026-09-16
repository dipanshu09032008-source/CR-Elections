-- CR Elections 2026 - security + voter identity + candidate profiles
-- Run this ONCE in Supabase SQL Editor against the existing project.

-- 1) Voter identity: one Google/Supabase account <-> one Institute ID.
create table if not exists public.voter_registrations (
    user_id uuid primary key
        references auth.users(id)
        on delete cascade,

    institute_id text not null unique
        check (institute_id ~ '^[A-Z]{5}-[0-9]{5}$'),

    created_at timestamptz default now()
);

alter table public.voter_registrations enable row level security;

drop policy if exists "Users can view own voter registration"
on public.voter_registrations;

create policy "Users can view own voter registration"
on public.voter_registrations
for select
to authenticated
using (auth.uid() = user_id);

drop policy if exists "Users can register own voter identity"
on public.voter_registrations;

create policy "Users can register own voter identity"
on public.voter_registrations
for insert
to authenticated
with check (auth.uid() = user_id);

-- Deliberately no UPDATE policy: once an Institute ID is bound,
-- the voter cannot change it from the client.

-- 2) Require a registered voter before a vote can be inserted.
drop policy if exists "Users can submit own vote"
on public.votes;

create policy "Users can submit own vote"
on public.votes
for insert
to authenticated
with check (
    auth.uid() = voter_id
    and exists (
        select 1
        from public.voter_registrations vr
        where vr.user_id = auth.uid()
    )
);

-- Do not expose every voter's UUID to every logged-in user.
drop policy if exists "Votes visible to logged users"
on public.votes;

drop policy if exists "Users can view own vote"
on public.votes;

create policy "Users can view own vote"
on public.votes
for select
to authenticated
using (auth.uid() = voter_id);

-- 3) Secure aggregate results function.
create or replace function public.get_vote_counts()
returns table (
    candidate_id bigint,
    vote_count bigint
)
language sql
security definer
set search_path = public
as $$
    select v.candidate_id, count(*)::bigint
    from public.votes v
    group by v.candidate_id;
$$;

revoke all on function public.get_vote_counts() from public;
grant execute on function public.get_vote_counts() to authenticated;

-- 4) Candidate profiles.
alter table public.candidates
    add column if not exists user_id uuid references auth.users(id) on delete set null;

alter table public.candidates
    add column if not exists about text;

alter table public.candidates
    add column if not exists skills text;

alter table public.candidates
    add column if not exists goals text;

create unique index if not exists candidates_user_id_unique
on public.candidates(user_id)
where user_id is not null;

drop policy if exists "Candidates can update own profile"
on public.candidates;

create policy "Candidates can update own profile"
on public.candidates
for update
to authenticated
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

-- 5) Candidate photo storage.
insert into storage.buckets (id, name, public)
values ('candidate-photos', 'candidate-photos', true)
on conflict (id) do update set public = true;

drop policy if exists "Candidate photos can be uploaded by linked candidates"
on storage.objects;

create policy "Candidate photos can be uploaded by linked candidates"
on storage.objects
for insert
to authenticated
with check (
    bucket_id = 'candidate-photos'
    and split_part(name, '/', 1) = auth.uid()::text
    and exists (
        select 1
        from public.candidates c
        where c.user_id = auth.uid()
          and c.id = split_part(name, '/', 2)::bigint
    )
);

drop policy if exists "Candidate photos can be updated by linked candidates"
on storage.objects;

create policy "Candidate photos can be updated by linked candidates"
on storage.objects
for update
to authenticated
using (
    bucket_id = 'candidate-photos'
    and split_part(name, '/', 1) = auth.uid()::text
)
with check (
    bucket_id = 'candidate-photos'
    and split_part(name, '/', 1) = auth.uid()::text
);

drop policy if exists "Candidate photos are publicly viewable"
on storage.objects;

create policy "Candidate photos are publicly viewable"
on storage.objects
for select
to public
using (bucket_id = 'candidate-photos');

-- OPTIONAL BEFORE THE REAL ELECTION:
-- delete from public.votes;
-- This resets all test votes while keeping candidates/accounts.
