import sqlite3
import argparse
from pathlib import Path

def check_fixture(query):
    db=sqlite3.connect(':memory:')
    db.create_function('charindex',2,lambda needle,haystack: (haystack or '').find(needle)+1)
    db.create_function('lower',1,lambda value: value.lower() if value is not None else None)
    db.executescript('''
    create table users(id integer,id_filial integer,name text);
    create table docum(id integer,id_filial integer,id_contr integer);
    create table poruch(id_docum integer,id_filial integer,id_komu integer,fil_komu integer,del integer);
    insert into users values(1,1,'Петров Пётр'),(1,2,'Другой сотрудник'),(2,1,'Сидорова Анна'),(3,1,'Другой получатель');
    insert into docum values(10,1,3),(11,1,1),(12,1,3),(13,1,3),(14,1,3),(10,2,3),(15,1,3),(16,2,3),(17,1,3),(18,1,3);
    insert into poruch values(10,1,1,1,0),(11,1,3,1,0),(12,1,1,2,0),(13,1,1,1,1),(14,1,1,1,0),(14,1,2,1,0),(10,2,3,1,0),(16,2,1,1,0),(17,1,999,1,0),(18,1,2,1,0);
    ''')
    sql=query.replace("N'", "'").replace('isnull(', 'ifnull(')
    actual=db.execute(sql).fetchall()
    assert actual==[(10,1),(14,1),(18,1),(16,2)],actual
    no_recipient_branch=sql.replace('and recipient.id_filial = recipient_assignment.fil_komu','')
    assert (12,1) in db.execute(no_recipient_branch).fetchall()
    no_document_branch=sql.replace('recipient_assignment.id_filial = d.id_filial','1=1')
    assert (10,2) in db.execute(no_document_branch).fetchall()
    no_deleted_guard=sql.replace('and recipient_assignment.del = 0','')
    assert (13,1) in db.execute(no_deleted_guard).fetchall()
    branch_two=sql.replace('where 1=1','where d.id_filial = 2',1)
    assert db.execute(branch_two).fetchall()==[(16,2)]
    db.close()
    return {'selected_documents':4,'matching_assignment_duplicates':False,'author_only_excluded':True,'recipient_and_document_branch_guards':True,'deleted_guard':True,'branch_selection':True}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Check actual OZ-generated recipient SQL with synthetic SQLite fixtures; not a SQL Server integration test.')
    parser.add_argument('cargo_output',type=Path)
    args=parser.parse_args()
    raw=args.cargo_output.read_text()
    query=raw.split('OZ_TEST_QUERY_BEGIN\n',1)[1].split('\nOZ_TEST_QUERY_END',1)[0]
    print(check_fixture(query))
