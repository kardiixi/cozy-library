-- Выполнить в Supabase SQL Editor (новый проект).
create extension if not exists pgcrypto;
create table public.profiles (
 id uuid primary key references auth.users(id) on delete cascade,
 username text not null unique check (username ~ '^[a-z0-9_]{3,24}$'),
 display_name text not null check (char_length(display_name) between 1 and 60),
 created_at timestamptz not null default now()
);
create table public.books (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references auth.users(id) on delete cascade,
 title text not null check (char_length(title) between 1 and 150),
 author text not null check (char_length(author) between 1 and 120),
 genre text not null default '', cover text not null default '',
 status text not null default 'want' check (status in ('want','reading','done')),
 rating integer check (rating between 1 and 10),
 pages integer not null default 0 check (pages between 0 and 100000),
 current_page integer not null default 0 check (current_page between 0 and pages),
 notes text not null default '' check (char_length(notes)<=3000),
 is_private boolean not null default false,
 created_at timestamptz not null default now()
);
create index books_user_idx on public.books(user_id);
create table public.friend_requests (
 id uuid primary key default gen_random_uuid(),
 sender_id uuid not null references auth.users(id) on delete cascade,
 receiver_id uuid not null references auth.users(id) on delete cascade,
 status text not null default 'pending' check (status in ('pending','accepted','rejected')),
 created_at timestamptz not null default now(),
 check (sender_id <> receiver_id), unique(sender_id,receiver_id)
);
create index friend_receiver_idx on public.friend_requests(receiver_id);
create index friend_sender_idx on public.friend_requests(sender_id);
create or replace function public.are_friends(a uuid,b uuid) returns boolean
language sql stable security definer set search_path = '' as $$
 select exists(select 1 from public.friend_requests r where r.status='accepted' and
 ((r.sender_id=a and r.receiver_id=b) or (r.sender_id=b and r.receiver_id=a)))
$$;
revoke all on function public.are_friends(uuid,uuid) from public;
grant execute on function public.are_friends(uuid,uuid) to authenticated;
alter table public.profiles enable row level security;
alter table public.books enable row level security;
alter table public.friend_requests enable row level security;
create policy "profiles readable" on public.profiles for select to authenticated using (true);
create policy "profile own insert" on public.profiles for insert to authenticated with check (id=auth.uid());
create policy "profile own update" on public.profiles for update to authenticated using (id=auth.uid()) with check (id=auth.uid());
create policy "books readable" on public.books for select to authenticated using
 (user_id=auth.uid() or (not is_private and public.are_friends(auth.uid(),user_id)));
create policy "books own insert" on public.books for insert to authenticated with check (user_id=auth.uid());
create policy "books own update" on public.books for update to authenticated using (user_id=auth.uid()) with check (user_id=auth.uid());
create policy "books own delete" on public.books for delete to authenticated using (user_id=auth.uid());
create policy "requests participants read" on public.friend_requests for select to authenticated
 using (sender_id=auth.uid() or receiver_id=auth.uid());
create policy "requests send" on public.friend_requests for insert to authenticated
 with check (sender_id=auth.uid() and status='pending');
create policy "requests receiver update" on public.friend_requests for update to authenticated
 using (receiver_id=auth.uid() and status='pending')
 with check (receiver_id=auth.uid() and status in ('accepted','rejected'));
create policy "requests participants delete" on public.friend_requests for delete to authenticated
 using (sender_id=auth.uid() or receiver_id=auth.uid());
-- Запрещаем смену участников заявки и повторное принятие чужих заявок через UPDATE.
create or replace function public.protect_friend_request() returns trigger
language plpgsql set search_path = '' as $$ begin
 if new.sender_id<>old.sender_id or new.receiver_id<>old.receiver_id or new.created_at<>old.created_at then
 raise exception 'Cannot change participants'; end if;
 if old.status<>'pending' or new.status not in ('accepted','rejected') then
 raise exception 'Invalid request transition'; end if;
 return new; end $$;
create trigger protect_friend_request before update on public.friend_requests
for each row execute function public.protect_friend_request();
