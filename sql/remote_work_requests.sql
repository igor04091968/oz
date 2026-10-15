declare @d1 date, @d2 date;

-- Period when documents in the tracked flows were submitted.
set @d1 = '20260801';
set @d2 = '20260825';

select
    convert(varchar(32), d.id_filial) + ':' + convert(varchar(32), d.id) as document_id,
    rtrim(p.name) as flow_name,                  -- document flow
    convert(varchar(10), d.date1, 23) as date_z,  -- request date
    convert(varchar(64), d.num1) as num1,          -- request number
    rtrim(isnull(d.pole4, N'')) as ot_kogo, -- existing author mapping; may be empty
    convert(varchar(10), d.date3, 23) as date_n,  -- first remote-work day
    rtrim(d.pole3) as time_n,              -- time period on first day
    convert(varchar(10), d.date2, 23) as date_k,  -- last day, empty for one-day requests
    rtrim(d.pole2) as time_k,              -- time period on last day
    rtrim(d.pole1) as prich,               -- request reason
    statuses.status_received + statuses.status_not_received as por_neisp,
    statuses.status_received,
    statuses.status_not_received,
    statuses.status_executed,
    statuses.status_agreed,
    statuses.status_rejected,
    statuses.status_noted,
    statuses.status_read,
    statuses.status_unknown
from docum d
inner join potok p on p.id = d.id_potok
outer apply (
    select
        count(case when ltrim(rtrim(isnull(por.ispol, N''))) = N'Получено' then 1 end) as status_received,
        count(case when ltrim(rtrim(isnull(por.ispol, N''))) = N'Не получено' then 1 end) as status_not_received,
        count(case when ltrim(rtrim(isnull(por.ispol, N''))) = N'Исполнено' then 1 end) as status_executed,
        count(case when ltrim(rtrim(isnull(por.ispol, N''))) = N'Согласовано' then 1 end) as status_agreed,
        count(case when ltrim(rtrim(isnull(por.ispol, N''))) = N'Не согласовано' then 1 end) as status_rejected,
        count(case when ltrim(rtrim(isnull(por.ispol, N''))) = N'Принято к сведению' then 1 end) as status_noted,
        count(case when ltrim(rtrim(isnull(por.ispol, N''))) = N'Ознакомлен' then 1 end) as status_read,
        count(case when ltrim(rtrim(isnull(por.ispol, N''))) not in (N'Получено', N'Не получено', N'Исполнено', N'Согласовано', N'Не согласовано', N'Принято к сведению', N'Ознакомлен') then 1 end) as status_unknown
    from poruch por
    where por.id_filial = d.id_filial
      and por.id_docum = d.id
      and por.del = 0
) statuses
where d.date1 >= @d1
  and d.date1 < dateadd(day, 1, @d2)
  and rtrim(p.name) in (
      N'Заявки на удаленную работу',
      N'Служебные записки',
      N'Запросы на права',
      N'Согласие на работу в выходные дни'
  )
order by d.date1, d.id_filial, d.id;
