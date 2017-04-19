import ldap
import inspect
from ldaphelper import ldaphelper
import sys
import os
root = os.path.dirname(os.path.realpath(__file__))
for subpath in ['ssha']:
    path = os.path.join(root, subpath)
    if not path in sys.path:
        sys.path.append(path)

from ssha.openldap_passwd import *
from base64 import b64encode

def connect(server, username, password):
    # the following is the user_dn format provided by the ldap server
    admin_dn = "cn="+username+","+base_dn
    # adjust this to your base dn for searching
    db = ldap.open(ldap_server)
    try:
        db.bind_s(admin_dn,password)
    except ldap.LDAPError:
        db.unbind_s()
        raise Exception("authentication error")
    return db

base_dn = "dc=gkdb,dc=org"
ldap_server="gkdb.org"
username = os.environ['LDAP_ADMIN_USER']
password = os.environ['LDAP_ADMIN_PASSWORD']
db = connect(ldap_server, username, password)

POSIX_TO_SQL = {'sql_readonly': 'read_only',
                'sql_write': 'write_to_sandbox',
                'sql_admin': 'developer'
                }
class LdapGroup:
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
        db.add_s('cn=' + self.cn + ',' + server_dn, self.to_addModlist())

class PosixGroup(LdapGroup):
    objectclass = ['top', 'posixGroup']
    def __init__(self, name, gid, description=None, memberUid=None, userPassword=None, autopush=True):
        self.cn = name
        self.gidNumber = gid

        self.description = description
        self.memberUid = memberUid
        self.userPassword = userPassword
        if autopush:
            self.to_server()


class PosixAccount(LdapGroup):
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
            random_bytes = os.urandom(64)
            password = b64encode(random_bytes).decode('utf-8')
            userPassword = make_secret(b64encode(random_bytes).decode('utf-8'))
        self.userPassword = userPassword
        if autopush:
            self.to_server()
        print('created user: ', self.uid, ' with password: ' + password)

def get_all_users():
    search_filter = '(&(objectClass=posixAccount)(uid=*))'
    result = db.search_s(base_dn,ldap.SCOPE_SUBTREE,search_filter)
    return ldaphelper.get_search_results(result)

def get_all_groups():
    search_filter = '(&(objectClass=posixGroup)(gidNumber=*))'
    result = db.search_s(base_dn,ldap.SCOPE_SUBTREE,search_filter)
    return ldaphelper.get_search_results(result)

def get_highest_uid():
    highest_uid = -1
    for user in get_all_users():
        uid = int(user.get_attributes()['uidNumber'][0])
        if uid > highest_uid:
            highest_uid = uid
    return highest_uid

def get_gid_name_map():
    ress = get_all_groups()
    attrs = [res.get_attributes() for res in ress]
    return {attr['gidNumber'][0]: attr['cn'][0] for attr in attrs}

def get_user_sqlgroup_map():
    attrs = [user.get_attributes() for user in get_all_users()]
    gid_name_map = get_gid_name_map()
    return {(attr['uid'][0], POSIX_TO_SQL[gid_name_map[attr['gidNumber'][0]]]) for attr in attrs}
