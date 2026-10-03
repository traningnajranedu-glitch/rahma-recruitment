begin;
create table public.app_members (
 user_id uuid primary key references auth.users(id) on delete cascade,
 role text not null check(role in ('admin','accountant','viewer')),
 created_at timestamptz not null default now()
);
create table public.records (
 id uuid primary key,
 kind text not null check(kind in ('client','supplier','contract','sale','purchase','receipt','payment','expense','entry','settings','item','movement')),
 number text unique not null,
 date date not null,
 data jsonb not null check(jsonb_typeof(data)='object'),
 created bigint not null,
 created_by uuid not null default auth.uid() references auth.users(id)
);
create index records_kind_created on public.records(kind,created desc);
create index records_invoice on public.records((data->>'invoice')) where kind in ('receipt','payment');
create index records_item on public.records((data->>'item')) where kind='movement';
alter table public.app_members enable row level security;
alter table public.records enable row level security;
revoke all on public.app_members, public.records from anon;
revoke all on public.app_members, public.records from authenticated;
grant select on public.app_members to authenticated;
grant select,insert on public.records to authenticated;
create policy members_self on public.app_members for select to authenticated using(user_id=(select auth.uid()));
create policy records_read on public.records for select to authenticated using(exists(select 1 from public.app_members m where m.user_id=(select auth.uid())));
create policy records_insert on public.records for insert to authenticated with check(created_by=(select auth.uid()) and exists(select 1 from public.app_members m where m.user_id=(select auth.uid()) and m.role in ('admin','accountant')));
create schema if not exists rahma_private;
revoke all on schema rahma_private from public,anon,authenticated;
grant usage on schema rahma_private to authenticated;
create function rahma_private.validate_record() returns trigger language plpgsql security invoker set search_path='' as $$
declare invoice public.records; n numeric; paid numeric; qty numeric; available numeric; line jsonb; debit numeric:=0; credit numeric:=0; expected text;
begin
 if new.created_by is distinct from auth.uid() then raise exception 'invalid_author'; end if;
 if not exists(select 1 from public.app_members where user_id=auth.uid() and role in ('admin','accountant')) then raise exception 'unauthorized'; end if;
 if new.kind in ('client','supplier','contract','settings','item') and coalesce(btrim(new.data->>'name'),'')='' then raise exception 'name_required'; end if;
 if new.kind in ('sale','purchase','contract') then
  n:=(new.data->>'net')::numeric;
  if n is null or n<=0 or n<>trunc(n) then raise exception 'invalid_amount'; end if;
  if new.data->>'service' not in ('استقدام','نقل خدمات','متابعة طلب','تأجير عمالة') or new.data->>'service' is null then raise exception 'invalid_service'; end if;
  if (new.data->>'rate')::numeric not in (0,15) or new.data->>'rate' is null then raise exception 'invalid_tax_rate'; end if;
  if (new.data->>'tax')::numeric is distinct from round(n*(new.data->>'rate')::numeric/100) or (new.data->>'total')::numeric is distinct from n+(new.data->>'tax')::numeric then raise exception 'invalid_total'; end if;
  if new.kind in ('sale','purchase') then
   expected:=case when new.kind='sale' then 'client' else 'supplier' end;
   if not exists(select 1 from public.records where id=(new.data->>'party')::uuid and kind=expected) then raise exception 'invalid_party'; end if;
  end if;
 end if;
 if new.kind in ('receipt','payment','expense') then
  n:=(new.data->>'amount')::numeric;
  if n is null or n<=0 or n<>trunc(n) or new.data->>'account' is null or new.data->>'account' not in ('1010','1020') then raise exception 'invalid_amount_or_account'; end if;
  if new.kind in ('receipt','payment') then
   perform pg_advisory_xact_lock(747201,hashtext(new.data->>'invoice'));
   select * into invoice from public.records where id=(new.data->>'invoice')::uuid;
   expected:=case when new.kind='receipt' then 'sale' else 'purchase' end;
   if invoice.id is null or invoice.kind<>expected then raise exception 'invalid_invoice'; end if;
   if new.data->>'party' is distinct from invoice.data->>'party' then raise exception 'invalid_party'; end if;
   select coalesce(sum((data->>'amount')::numeric),0) into paid from public.records where kind=new.kind and data->>'invoice'=new.data->>'invoice';
   if paid+n>(invoice.data->>'total')::numeric then raise exception 'overpayment'; end if;
  end if;
 end if;
 if new.kind='entry' then
  if jsonb_typeof(new.data->'lines') is distinct from 'array' or jsonb_array_length(new.data->'lines')<2 or jsonb_array_length(new.data->'lines')>30 then raise exception 'invalid_lines'; end if;
  for line in select value from jsonb_array_elements(new.data->'lines') loop
   if line->>'account' is null or line->>'account' not in ('1010','1020','1030','1040','2010','2020','3010','4010','4020','4030','5010','5020') then raise exception 'invalid_account'; end if;
   if line->>'debit' is null or line->>'credit' is null or (line->>'debit')::numeric<0 or (line->>'credit')::numeric<0 or (line->>'debit')::numeric<>trunc((line->>'debit')::numeric) or (line->>'credit')::numeric<>trunc((line->>'credit')::numeric) or (((line->>'debit')::numeric>0)=((line->>'credit')::numeric>0)) then raise exception 'invalid_entry_line'; end if;
   debit:=debit+(line->>'debit')::numeric;credit:=credit+(line->>'credit')::numeric;
  end loop;
  if debit<>credit or debit<=0 then raise exception 'unbalanced_entry'; end if;
 end if;
 if new.kind='movement' then
  qty:=(new.data->>'quantity')::numeric;
  if qty is null or qty<=0 or new.data->>'direction' is null or new.data->>'direction' not in ('in','out') then raise exception 'invalid_movement'; end if;
  if not exists(select 1 from public.records where id=(new.data->>'item')::uuid and kind='item') then raise exception 'invalid_item'; end if;
  perform pg_advisory_xact_lock(747202,hashtext(new.data->>'item'));
  select coalesce(sum(case when data->>'direction'='in' then (data->>'quantity')::numeric else -(data->>'quantity')::numeric end),0) into available from public.records where kind='movement' and data->>'item'=new.data->>'item';
  if new.data->>'direction'='out' and qty>available then raise exception 'insufficient_stock'; end if;
 end if;
 return new;
end;
$$;
revoke all on function rahma_private.validate_record() from public,anon,authenticated;
create trigger validate_record before insert on public.records for each row execute function rahma_private.validate_record();
commit;
