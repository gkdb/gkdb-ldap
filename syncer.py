import db_sql
import db_ldap

def init_dummies():
    try:
        users =        db_ldap.PosixGroup('users', 100)
        sql_admin =    db_ldap.PosixGroup('sql_admin', 2000)
        sql_writer =   db_ldap.PosixGroup('sql_write', 2001)
        sql_readonly = db_ldap.PosixGroup('sql_readonly', 2002)
        user0 =        db_ldap.PosixAccount('Admin', 'User', sql_admin.gidNumber)
        user1 =        db_ldap.PosixAccount('Trusted', 'User',  sql_writer.gidNumber)
        user2 =        db_ldap.PosixAccount('Untrusted', 'User',  sql_readonly.gidNumber)
    except db_ldap.ldap.ALREADY_EXISTS:
        pass

def sync_ldap_sql():
    cur = db_sql.get_sql_usergroups()
    sql_users = {x for x in cur}
    ldap_users = db_ldap.get_user_sqlgroup_map()
    missing = ldap_users.difference(sql_users)
    [db_sql.create_user(miss[0], groups=[miss[1]]) for miss in missing]

#init_dummies()
sync_ldap_sql()
