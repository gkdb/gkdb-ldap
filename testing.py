import ldap
import ldap.modlist
import inspect
from IPython import embed
from ldaphelper import ldaphelper
PYSOLR_PATH = './gkdb'
import sys
if not PYSOLR_PATH in sys.path:
    sys.path.append(PYSOLR_PATH)
from gkdb.core.model import *

db.execute_sql('SET ROLE developer') # Needed to create new roles
def get_groups(uid):
    return db.execute_sql("""
      SELECT * FROM
      pg_group
      WHERE
      %s = ANY (grolist)
      ;""", (uid, ))

def get_usergroups():
    return db.execute_sql("""
      SELECT usename, STRING_AGG(groname, ', ')
      FROM pg_catalog.pg_user AS u
      LEFT JOIN pg_catalog.pg_group AS g ON u.usesysid = ANY (g.grolist)
      GROUP BY usename
      """)

def create_user(username, password=None, groups=[]):
    groups = ', '.join(groups)
    print(groups)
    if password is None:
        password = "something.."
    print(username, password, groups)
    db.execute_sql("CREATE USER " + username +
                   " PASSWORD %s" +
                   " IN ROLE " + groups,
                   (password, ))

ldap_server="172.32.0.3"
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
        self.cn = ' '.join([first_name, last_name])
        self.sn = last_name
        self.gn = first_name
        self.gidNumber = primary_gid
        self.uid = ''.join([first_name[0].lower(), last_name.lower()])
        self.homeDirectory = ''.join(['/home/users', self.uid])
        if get_highest_uid() == -1:
            self.uidNumber = 1000
        else:
            self.uidNumber = get_highest_uid() + 1
        self.description = description
        self.gecos = gecos
        self.loginShell = loginShell
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

posix_to_sql = {'sql_readonly': 'something'} 
try:
    users = posixGroup('users', 100)
    sql_admin = posixGroup('sql_admin', 2000)
    sql_writer = posixGroup('sql_writer', 2001)
    sql_readonly = posixGroup('sql_readonly', 2002)
    user0 = posixUser('Karel', 'van de Plassche', sql_admin.gidNumber)
    user1 = posixUser('Trusted', 'User',  sql_writer.gidNumber)
    user2 = posixUser('Untrusted', 'User',  sql_readonly.gidNumber)
except ldap.ALREADY_EXISTS:
    pass
embed()
