import ldap
import ldap.modlist
import inspect
from IPython import embed
from ldaphelper import ldaphelper
ldap_server="localhost"
username = "admin"
password= "admin"
# the following is the user_dn format provided by the ldap server
base_dn = "dc=gkdb,dc=org"
user_dn = "cn="+username+","+base_dn
# adjust this to your base dn for searching
l = ldap.open(ldap_server)
search_filter = "cn="+username
try:
    #if authentication successful, get the full user data
    l.bind_s(user_dn,password)
    result = l.search_s(base_dn,ldap.SCOPE_SUBTREE,search_filter)
    # return all user data results
    #l.unbind_s()
    print result
except ldap.LDAPError:
    l.unbind_s()
    print "authentication error"

class posixGroup:
    objectclass = ['top', 'posixGroup']
    def __init__(self, name, gid, description=None, memberUid=None, userPassword=None):
        self.cn = name
        self.gidNumber = gid

        self.description = description
        self.memberUid = memberUid
        self.userPassword = userPassword

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
    def __init__(self, first_name, last_name, primary_gid, description=None, gecos=None, loginShell=None, userPassword=None):
        self.cn = ' '.join([first_name, last_name])
        self.sn = last_name
        self.gn = first_name
        self.gidNumber = primary_gid
        self.uid = ''.join([first_name[0].lower(), last_name.lower()])
        self.homeDirectory = ''.join(['/home/users', self.uid])
        self.uidNumber = 1000
        self.description = description
        self.gecos = gecos
        self.loginShell = loginShell
        self.userPassword = userPassword

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
group = posixGroup('users', 100)
user = posixUser('Mister', 'Testuser', group.gidNumber)
embed()
