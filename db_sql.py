import psycopg2 as psy

db = psy.connect(dbname='gkdb', host='gkdb.org')
def get_groups(uid):
    cur = db.cursor()
    cur.execute("""
      SELECT * FROM
      pg_group
      WHERE
      %s = ANY (grolist)
      ;""", (uid, ))
    return cur

def get_sql_usergroups():
    cur = db.cursor()
    cur.execute("""
      SELECT usename, STRING_AGG(groname, ', ')
      FROM pg_catalog.pg_user AS u
      LEFT JOIN pg_catalog.pg_group AS g ON u.usesysid = ANY (g.grolist)
      GROUP BY usename
      """)
    return cur

def create_user(username, password=None, groups=[]):
    cur = db.cursor()
    cur.execute('SET ROLE developer') # Needed to create new roles
    groups = ', '.join(groups)
    print(groups)
    if password is None:
        password = "something.."
    print(username, password, groups)
    cur.execute("CREATE USER " + username +
                   " IN ROLE " + groups
                   )
    db.commit()
