import ldap
import ldap.modlist
import inspect
from IPython import embed
from ldaphelper import ldaphelper
import sys
import os
root = os.path.dirname(os.path.realpath(__file__))
for subpath in ['gkdb', 'ssha']:
    path = os.path.join(root, subpath)
    if not path in sys.path:
        sys.path.append(path)
print(sys.path)
from ssha.openldap_passwd import *
from base64 import b64encode
from os import urandom
import psycopg2 as psy

conn = psy.connect(dbname='gkdb', host='gkdb.org')
cur = conn.cursor()
cur.execute('SET ROLE developer') # Needed to create new roles
def get_groups(uid):
    cur = conn.cursor()
    cur.execute("""
      SELECT * FROM
      pg_group
      WHERE
      %s = ANY (grolist)
      ;""", (uid, ))
    return cur

def get_usergroups():
    cur = conn.cursor()
    cur.execute("""
      SELECT usename, usesysid, STRING_AGG(groname, ', ')
      FROM pg_catalog.pg_user AS u
      LEFT JOIN pg_catalog.pg_group AS g ON u.usesysid = ANY (g.grolist)
      GROUP BY usename, usesysid
      """)
    return cur

def create_user(username, password=None, groups=[]):
    cur = conn.cursor()
    groups = ', '.join(groups)
    print(groups)
    if password is None:
        password = "something.."
    print(username, password, groups)
    cur.execute("CREATE USER " + username +
                   " PASSWORD %s" +
                   " IN ROLE " + groups,
                   (password, ))

ldap_server="gkdb.org"
username = "admin"
password= "admin"
# the following is the user_dn format provided by the ldap server
base_dn = "dc=gkdb,dc=org"
admin_dn = "cn="+username+","+base_dn
# adjust this to your base dn for searching
l = ldap.open(ldap_server)
search_filter = "cn="+username
try:
    #if authentication successful, get the full user data
    l.bind_s(admin_dn,password)
    result = l.search_s(base_dn,ldap.SCOPE_SUBTREE,search_filter)
    # return all user data results
    #l.unbind_s()
    print result
except ldap.LDAPError:
    l.unbind_s()
    print "authentication error"

class posixGroup:
    objectclass = ['top', 'posixGroup']
    def __init__(self, name, gid, description=None, memberUid=None, userPassword=None, autopush=True):
        self.cn = name
        self.gidNumber = gid

        self.description = description
        self.memberUid = memberUid
        self.userPassword = userPassword
        if autopush:
            self.to_server()

    def to_addModlist(self):
        attrs = inspect.getmembers(self, lambda a:not(inspect.isroutine(a)))
        modlist = []
        for attr, val in attrs:
            if not attr.startswith('_') and val is not None:
                if val.__class__ in [str, list]:
                    pass
                else:
                    val = str(val)
                modlist.append((attr, val))
        return modlist

    def to_server(self, server_dn=base_dn):
        l.add_s('cn=' + self.cn + ',' + server_dn, self.to_addModlist())

class posixUser:
    objectclass = ['top', 'inetOrgPerson', 'posixAccount']
    def __init__(self, first_name, last_name, primary_gid, description=None, gecos=None, loginShell=None, userPassword=None, autopush=True):
        self.sn = last_name
        self.gn = first_name
        self.gidNumber = primary_gid
        self.uid = ''.join([first_name[0].lower()] + last_name.lower().split())
        self.cn = self.uid
        self.homeDirectory = ''.join(['/home/users/', self.uid])
        if get_highest_uid() == -1:
            self.uidNumber = 1000
        else:
            self.uidNumber = get_highest_uid() + 1
        self.description = description
        self.gecos = gecos
        self.loginShell = loginShell
        if userPassword is None:
            random_bytes = urandom(64)
            password = b64encode(random_bytes).decode('utf-8')
            print(password)
            userPassword = make_secret(b64encode(random_bytes).decode('utf-8'))
        self.userPassword = userPassword
        if autopush:
            self.to_server()

    def to_addModlist(self):
        attrs = inspect.getmembers(self, lambda a:not(inspect.isroutine(a)))
        modlist = []
        for attr, val in attrs:
            if not attr.startswith('_') and val is not None:
                if val.__class__ in [str, list]:
                    pass
                else:
                    val = str(val)
                modlist.append((attr, val))
        return modlist

    def to_server(self, server_dn=base_dn):
        l.add_s('cn=' + self.cn + ',' + server_dn, self.to_addModlist())

def get_all_users():
    search_filter = '(&(objectClass=posixAccount)(uid=*))'
    result = l.search_s(base_dn,ldap.SCOPE_SUBTREE,search_filter)
    return ldaphelper.get_search_results(result)

def get_highest_uid():
    highest_uid = -1
    for user in get_all_users():
        uid = int(user.get_attributes()['uidNumber'][0])
        if uid > highest_uid:
            highest_uid = uid
    return highest_uid

posix_to_sql = {'sql_readonly': 'read_only',
                'sql_write': 'write_to_sandbox',
                'sql_admin': 'developer'
                }
try:
    users = posixGroup('users', 100)
    sql_admin = posixGroup('sql_admin', 2000)
    sql_writer = posixGroup('sql_writer', 2001)
    sql_readonly = posixGroup('sql_readonly', 2002)
    user0 = posixUser('Karel', 'van de Plassche', sql_admin.gidNumber, userPassword='test')
    user1 = posixUser('Trusted', 'User',  sql_writer.gidNumber)
    user2 = posixUser('Untrusted', 'User',  sql_readonly.gidNumber)
except ldap.ALREADY_EXISTS:
    pass
embed()
