declare @d1 datetime, @d2 datetime;

-- Period when remote-work requests were submitted.
set @d1 = '20260801';
set @d2 = '20260825';

select
    convert(date, d.date1) as date_z,      -- request date
    d.num1,                                -- request number
    rtrim(d.pole4) as ot_kogo,             -- request author
    convert(date, d.date3) as date_n,      -- first remote-work day
    rtrim(d.pole3) as time_n,              -- time period on first day
    convert(date, d.date2) as date_k,      -- last day, empty for one-day requests
    rtrim(d.pole2) as time_k,              -- time period on last day
    rtrim(d.pole1) as prich,               -- request reason
    isnull((
        select top 1 1
        from poruch por with (nolock index = ind6)
        where por.id_filial = d.id_filial
          and por.id_docum = d.id
          and por.del = 0
          and por.ispol in ('Получено', 'Не получено')
    ), 0) as por_neisp                     -- has unfinished assignments
from docum d
inner join potok p on p.id = d.id_potok
where d.date1 >= @d1
  and d.date1 < dateadd(day, 1, @d2)
  and rtrim(p.name) = 'Заявки на удаленную работу'
order by d.date1;
