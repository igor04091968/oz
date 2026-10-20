-- Read-only schema discovery. Run in rd_all; no employee/document data is read.
select s.name as schema_name, t.name as table_name, c.column_id,
       c.name as column_name, ty.name as data_type, c.is_nullable
from sys.tables t
join sys.schemas s on s.schema_id = t.schema_id
join sys.columns c on c.object_id = t.object_id
join sys.types ty on ty.user_type_id = c.user_type_id
where t.name in (N'poruch', N'users')
order by s.name, t.name, c.column_id;

select fk.name as foreign_key,
       object_schema_name(fkc.parent_object_id) as source_schema,
       object_name(fkc.parent_object_id) as source_table,
       col_name(fkc.parent_object_id, fkc.parent_column_id) as source_column,
       object_schema_name(fkc.referenced_object_id) as target_schema,
       object_name(fkc.referenced_object_id) as target_table,
       col_name(fkc.referenced_object_id, fkc.referenced_column_id) as target_column
from sys.foreign_key_columns fkc
join sys.foreign_keys fk on fk.object_id = fkc.constraint_object_id
where object_name(fkc.parent_object_id) = N'poruch'
order by fk.name, fkc.constraint_column_id;
