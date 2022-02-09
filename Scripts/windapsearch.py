#!/usr/bin/env python3

import ldap
import argparse
import getpass
import sys
import re
import string
from datetime import datetime
import base64
import csv

FUNCTIONALITYLEVELS = {
    b"0": "2000",
    b"1": "2003 Interim",
    b"2": "2003",
    b"3": "2008",
    b"4": "2008 R2",
    b"5": "2012",
    b"6": "2012 R2",
    b"7": "2016"
}

DOMAIN_ADMIN_GROUPS = [
    "Domain Admins",
    "Domain-Admins",
    "Domain Administrators",
    "Domain-Administrators",
    "Domänen Admins",
    "Domänen-Admins",
    "Domain Admins",
    "Domain-Admins",
    "Domänen Administratoren",
    "Domänen-Administratoren",
]

# Privileged builtin AD groups relevant to look for
BUILTIN_PRIVILEGED_GROUPS = DOMAIN_ADMIN_GROUPS + [
    "Administrators",  # Builtin administrators group for the domain
    "Enterprise Admins",
    "Schema Admins",  # Highly privileged builtin group
    "Account Operators",
    "Backup Operators",
    "Server Management",
    "Konten-Operatoren",
    "Sicherungs-Operatoren",
    "Server-Operatoren",
    "Schema-Admins",
]


class LDAPSearchResult(object):
    """A helper class to work with raw search results
    Copied from here: https://www.packtpub.com/books/content/configuring-and-securing-python-ldap-applications-part-2
    """

    dn = ''

    def __init__(self, entry_tuple):
        (dn, attrs) = entry_tuple
        if dn:
            self.dn = dn
        else:
            return

        self.attrs = ldap.cidict.cidict(attrs)

    def get_attributes(self):
        return self.attrs

    def has_attribute(self, attr_name):
        return attr_name in self.attrs

    def get_attr_values(self, key):
        return self.attrs[key]

    def get_attr_names(self):
        return self.attrs.keys()

    def get_dn(self):
        return self.dn

    def get_print_value(self, value):
        isprintable = False
        try:
            dec_value = value.decode()
            isprintable = dec_value.isprintable()
            if isprintable:
                value = dec_value
        except UnicodeDecodeError:
            pass
        if not isprintable:
            value = base64.b64encode(value).decode()

        return value

    def pretty_print(self):
        attrs = self.attrs.keys()
        for attr in attrs:
            values = self.get_attr_values(attr)
            for value in values:
                print("{}: {}".format(attr, self.get_print_value(value)))

    def getCSVLine(self):
        attrs = self.attrs.keys()
        lineValues = []
        for attr in attrs:
            values = self.get_attr_values(attr)
            for value in values:
                lineValues.append(self.get_print_value(value))

        return lineValues


class LDAPSession(object):
    def __init__(self, dc_ip='', username='', password='', domain=''):

        if dc_ip:
            self.dc_ip = dc_ip
        else:
            self.get_set_DC_IP(domain)

        self.username = username
        self.password = password
        self.domain = domain

        self.con = self.initializeConnection()
        self.domainBase = ''
        self.is_binded = False

    def initializeConnection(self):
        if not self.dc_ip:
            self.get_set_DC_IP(self.domain)

        con = ldap.initialize('ldap://{}'.format(self.dc_ip))
        con.set_option(ldap.OPT_REFERRALS, 0)
        return con

    def unbind(self):
        self.con.unbind()
        self.is_binded = False

    def get_set_DC_IP(self, domain):
        """
        if domain is provided, do a _ldap._tcp.domain to try and find DC, or maybe a "host -av domain" eventually ?
        if no domain is provided, do a multicast and hope it's in the search domain
        if can't find anything, return error and require dc_ip set manually
        """
        import socket
        try:
            dc_ip = socket.gethostbyname(domain)
        except:
            print("[!] Unable to locate domain controller IP through host lookup. Please provide manually")
            sys.exit(1)

        self.dc_ip = dc_ip

    def getDefaultNamingContext(self):
        try:
            newCon = ldap.initialize('ldap://{}'.format(self.dc_ip))
            newCon.simple_bind_s('', '')
            res = newCon.search_s("", ldap.SCOPE_BASE, '(objectClass=*)')
            rootDSE = res[0][1]
        except ldap.LDAPError as e:
            print("[!] Error retrieving the root DSE")
            print("[!] {}".format(e))
            sys.exit(1)

        if 'defaultNamingContext' not in rootDSE:
            print("[!] No defaultNamingContext found!")
            sys.exit(1)

        defaultNamingContext = rootDSE['defaultNamingContext'][0].decode()

        self.domainBase = defaultNamingContext
        newCon.unbind()
        return defaultNamingContext

    def do_bind(self):
        try:
            self.con.simple_bind_s(self.username, self.password)
            self.is_binded = True
            return True
        except ldap.INVALID_CREDENTIALS:
            print("[!] Error: invalid credentials")
            sys.exit(1)
        except ldap.LDAPError as e:
            print("[!] {}".format(e))
            sys.exit(1)

    def whoami(self):
        try:
            current_dn = self.con.whoami_s()
        except ldap.LDAPError as e:
            print("[!] {}".format(e))
            sys.exit(1)

        return current_dn

    def do_ldap_query(self, base_dn, subtree, objectFilter, attrs, page_size=1000):
        """
        actually perform the ldap query, with paging
        copied from another LDAP search script I found: https://github.com/CroweCybersecurity/ad-ldap-enum
        found this script well after i'd written most of this one. oh well
        """
        more_pages = True
        cookie = None

        ldap_control = ldap.controls.SimplePagedResultsControl(True, size=page_size, cookie='')

        allResults = []

        while more_pages:
            msgid = self.con.search_ext(base_dn, subtree, objectFilter, attrs, serverctrls=[ldap_control])
            result_type, rawResults, message_id, server_controls = self.con.result3(msgid)

            allResults += rawResults

            # Get the page control and get the cookie from the control.
            page_controls = [c for c in server_controls if
                             c.controlType == ldap.controls.SimplePagedResultsControl.controlType]

            if page_controls:
                cookie = page_controls[0].cookie

            if not cookie:
                more_pages = False
            else:
                ldap_control.cookie = cookie

        return allResults

    def get_search_results(self, results):
        # takes raw results and returns a list of helper objects
        res = []
        arr = []
        if type(results) == tuple and len(results) == 2:
            (code, arr) = results
        elif type(results) == list:
            arr = results

        if len(results) == 0:
            return res

        for item in arr:
            resitem = LDAPSearchResult(item)
            if resitem.dn:  # hack to workaround "blank" results
                res.append(resitem)

        return res

    def getFunctionalityLevel(self):
        objectFilter = '(objectclass=*)'
        attrs = ['domainFunctionality', 'forestFunctionality', 'domainControllerFunctionality']
        try:
            # rawFunctionality = self.do_ldap_query('', ldap.SCOPE_BASE, objectFilter, attrs)
            rawData = self.con.search_s('', ldap.SCOPE_BASE, "(objectclass=*)", attrs)
            functionalityLevels = rawData[0][1]
        except Error as e:
            print("[!] Error retrieving functionality level")
            print("[!] {}".format(e))
            sys.exit(1)

        return functionalityLevels

    def getAllUsers(self, attrs=''):
        if not attrs:
            attrs = ['cn', 'userPrincipalName']

        objectFilter = '(objectCategory=user)'
        base_dn = self.domainBase
        try:
            rawUsers = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving users")
            print("[!] {}".format(e))
            sys.exit(1)

        return self.get_search_results(rawUsers), attrs

    def getAllGroups(self, attrs=''):
        if not attrs:
            attrs = ['distinguishedName', 'cn']

        objectFilter = '(objectCategory=group)'
        base_dn = self.domainBase
        try:
            rawGroups = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving groups")
            print("[!] {}".format(e))
            sys.exit(1)

        return self.get_search_results(rawGroups), attrs

    def doFuzzySearch(self, searchTerm, objectCategory=''):
        if objectCategory:
            objectFilter = '(&(objectCategory={})(anr={}))'.format(objectCategory, searchTerm)
        else:
            objectFilter = '(anr={})'.format(searchTerm)
        attrs = ['dn']
        base_dn = self.domainBase
        try:
            rawResults = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving results")
            print("[!] {}".format(e))
            sys.exit(1)
        return self.get_search_results(rawResults)

    def doCustomSearch(self, base, objectFilter, attrs):
        try:
            rawResults = self.do_ldap_query(base, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error doing search")
            print("[!] {}".format(e))
            sys.exit(1)

        return self.get_search_results(rawResults)

    def queryGroupMembership(self, groupDN, getUPNs=False):
        objectFilter = '(objectCategory=group)'
        attrs = ['member']
        results = self.doCustomSearch(groupDN, objectFilter, attrs)
        if not results:
            return False
        members = []
        for result in results:
            if not result.has_attribute('member'):
                break
            members = members + result.get_attr_values('member')
        if getUPNs:
            membernames = {}
            for member in members:
                upnresult = self.doCustomSearch(member, '(objectCategory=user)', ['userPrincipalName'])
                upn = upnresult[0].get_attr_values('userPrincipalName') if upnresult[0].has_attribute(
                    'userPrincipalName') else ''
                membernames[member] = upn
            return membernames
        else:
            return members

    def getNestedGroupMemberships(self, groupDN, attrs=''):
        """see here for more details:
        https://labs.mwrinfosecurity.com/blog/active-directory-users-in-nested-groups-reconnaissance/
        """
        objectFilter = "(&(objectClass=user)(memberof:1.2.840.113556.1.4.1941:={}))".format(groupDN)
        if not attrs:
            attrs = ['cn', 'userPrincipalName']
        base_dn = self.domainBase
        results = self.doCustomSearch(base_dn, objectFilter, attrs)
        return results, attrs

    def getAllComputers(self, attrs=''):
        if not attrs:
            attrs = ['cn', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'operatingSystemServicePack']

        objectFilter = '(objectClass=Computer)'
        base_dn = self.domainBase

        try:
            rawComputers = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving computers")
            print("[!] {}".format(e))
            sys.exit(1)

        return self.get_search_results(rawComputers), attrs

    def getComputerDict(self, computerResults, ipLookup=False):
        """returns dict object of computers and attributes
        if iplookup speficied will add IP addresses through simple host lookup
        returns dictionary of computers in the domain with DN as key"""
        import socket
        computersDict = {}
        for computer in computerResults:
            computerInfo = {}
            dn = computer.dn
            for attr in computer.get_attr_names():
                computerInfo[attr] = ','.join(computer.get_attr_values(attr))

            if 'dNSHostName' in computerInfo:
                hostname = computerInfo['dNSHostName']
            else:
                hostname = computerInfo['cn'] + self.domain

            try:
                computerInfo['IP'] = socket.gethostbyname(hostname)
            except:
                computerInfo['IP'] = ""

            computersDict[dn] = computerInfo

        return computersDict

    def getAdminObjects(self, attrs=''):
        if not attrs:
            attrs = ['dn']
        objectFilter = 'adminCount=1'
        base_dn = self.domainBase
        try:
            rawAdminResults = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving admin objects")
            print("[!] {}".format(e))
            sys.exit(1)
        return self.get_search_results(rawAdminResults), attrs

    def getSPNs(self, attrs=''):
        if not attrs:
            attrs = ['dn']
        objectFilter = "(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))"
        base_dn = self.domainBase
        try:
            rawSpnResults = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving SPNs")
            print("[!] {}".format(e))
            sys.exit(1)
        return self.get_search_results(rawSpnResults), attrs

    def getUnconstrainedUsers(self, attrs=''):
        if not attrs:
            attrs = ['dn', 'userPrincipalName']
        objectFilter = "(&(&(objectCategory=person)(objectClass=user))(userAccountControl:1.2.840.113556.1.4.803:=524288))"
        base_dn = self.domainBase
        try:
            rawUnconstrainedUsers = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving unconstrained users")
            print("[!] {}".format(e))
            sys.exit(1)
        return self.get_search_results(rawUnconstrainedUsers), attrs

    def getUnconstrainedComputers(self, attrs=''):
        if not attrs:
            attrs = ['dn', 'dNSHostName']
        objectFilter = "(&(objectCategory=computer)(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
        base_dn = self.domainBase
        try:
            rawUnconstrainedComputers = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving unconstrained computers")
            print("[!] {}".format(e))
            sys.exit(1)
        return self.get_search_results(rawUnconstrainedComputers), attrs

    def getGPOs(self, attrs=''):
        if not attrs:
            attrs = ['displayName', 'gPCFileSysPath']
        objectFilter = "objectClass=groupPolicyContainer"
        base_dn = self.domainBase
        try:
            rawGPOs = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving GPOs")
            print("[!] {}".format(e))
            sys.exit(1)
        return self.get_search_results(rawGPOs), attrs

    def doCustomFilterSearch(self, customFilter, attrs=''):
        if not attrs:
            attrs = ['dn']
        objectFilter = customFilter
        base_dn = self.domainBase
        try:
            rawResults = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving results with custom filter")
            print("[!] {}".format(e))
            sys.exit(1)
        return self.get_search_results(rawResults), attrs


def prettyPrintResults(results, showDN=False):
    for result in results:
        if showDN:
            print(result.dn)
        result.pretty_print()
        print("")


def prettyPrintDictionary(results, attrs=None, separator=","):
    # helper function to pretty print(a dictionary of dictionaries, like the one returned in getComputerDict
    keys = set()
    common_attrs = ['cn', 'IP', 'dNSHostName', 'userPrincipalName', 'operatingSystem', 'operatingSystemVersion',
                    'operatingSystemServicePack']
    attrs = []

    for dn, computer in results.iteritems():
        for key in computer:
            keys.add(key)

    for attr in common_attrs:
        if attr in keys:
            attrs.append(attr)
            keys.remove(attr)
    for attr in keys:
        attrs.append(attr)
    print(", ".join(attrs))

    for dn, computer in results.items():
        line = []
        for attr in attrs:
            if attr in computer:
                line.append(computer[attr])
            else:
                line.append(' ')
        print(separator.join(line))


def writeResults(results, attrs, filename):
    with open(filename, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file, delimiter="\t")
        writer.writerow(attrs)
        writer.writerows((result.getCSVLine() for result in results))
    print("[*] {} written".format(filename))


def printFunctionalityLevels(levels):
    for name, level in levels.items():
        print("[+]\t {}: {}".format(name, FUNCTIONALITYLEVELS[level[0]]))


def run(args):
    startTime = datetime.now().strftime("%Y%m%d-%H:%M:%S")
    if not args.username:
        username = ''
        password = ''
        print("[+] No username provided. Will try anonymous bind.")
    else:
        username = args.username

    if args.username and not args.password:
        password = getpass.getpass("Password for {}: ".format(args.username))
    elif args.password:
        password = args.password

    if not args.dc_ip:
        print("[+] No DC IP provided. Will try to discover via DNS lookup.")

    ldapSession = LDAPSession(dc_ip=args.dc_ip, username=username, password=password, domain=args.domain)

    print("[+] Using Domain Controller at: {}".format(ldapSession.dc_ip))

    print("[+] Getting defaultNamingContext from Root DSE")
    print("[+]\tFound: {}".format(ldapSession.getDefaultNamingContext()))
    if args.functionality:
        levels = ldapSession.getFunctionalityLevel()
        print("[+] Functionality Levels:")
        printFunctionalityLevels(levels)

    print("[+] Attempting bind")
    ldapSession.do_bind()

    if ldapSession.is_binded:
        print("[+]\t...success! Binded as: ")
        print("[+]\t {}".format(ldapSession.whoami()))

    attrs = ''

    if args.full:
        attrs = ['*']
    elif args.attrs:
        attrs = args.attrs.split(',')

    if args.groups:
        print("\n[+] Enumerating all AD groups")
        allGroups, searchAttrs = ldapSession.getAllGroups(attrs=attrs)
        if not allGroups:
            bye(ldapSession)
        print("[+]\tFound {} groups: \n".format(len(allGroups)))
        prettyPrintResults(allGroups)
        if args.output_dir:
            filename = "{}/{}-groups.tsv".format(args.output_dir, startTime)
            writeResults(allGroups, searchAttrs, filename)

    if args.users:
        print("\n[+] Enumerating all AD users")
        allUsers, searchAttrs = ldapSession.getAllUsers(attrs=attrs)
        if not allUsers:
            bye(ldapSession)
        print("[+]\tFound {} users: \n".format(len(allUsers)))
        prettyPrintResults(allUsers)
        if args.output_dir:
            filename = "{}/{}-users.tsv".format(args.output_dir, startTime)
            writeResults(allUsers, searchAttrs, filename)

    if args.privileged_users:
        print("[+] Attempting to enumerate all AD privileged users")
        for group in BUILTIN_PRIVILEGED_GROUPS:
            daDN = "CN={},CN=Users,{}".format(group, ldapSession.domainBase)
            print("[+] Using DN: {}".format(daDN))
            domainAdminResults, searchAttrs = ldapSession.getNestedGroupMemberships(daDN, attrs=attrs)
            print("[+]\tFound {} nested users for group {}:\n".format(len(domainAdminResults), group))
            prettyPrintResults(domainAdminResults)
            if args.output_dir:
                filename = "{}/{}-{}-users.tsv".format(args.output_dir, startTime, group.replace(" ", "_"))
                writeResults(domainAdminResults, searchAttrs, filename)

    if args.computers:
        print("\n[+] Enumerating all AD computers")
        allComputers, searchAttrs = ldapSession.getAllComputers(attrs=attrs)
        if not allComputers:
            bye(ldapSession)
        print("[+]\tFound {} computers: \n".format(len(allComputers)))
        if not args.resolve:
            prettyPrintResults(allComputers)
        else:
            allComputersDict = ldapSession.getComputerDict(allComputers, ipLookup=True)
            prettyPrintDictionary(allComputersDict, attrs=searchAttrs)
        if args.output_dir:
            filename = "{}/{}-computers.tsv".format(args.output_dir, startTime)
            writeResults(allComputers, searchAttrs, filename)

    if args.group_name:
        if not isValidDN(args.group_name):
            print("[+] Attempting to enumerate full DN for group: {}".format(args.group_name))
            searchResults = ldapSession.doFuzzySearch(args.group_name)
            if not searchResults:
                print("[!] Couldn't find any DNs matching {}".format(args.group_name))
                bye(ldapSession)
            elif len(searchResults) == 1:
                groupDN = searchResults[0].dn
                print("[+]\t Using DN: {}\n".format(groupDN))
            elif len(searchResults) > 1:
                groupDN = selectResult(searchResults).dn
        else:
            groupDN = args.group_name
            print("[+]\t Using DN: {}\n".format(groupDN))

        groupMembers = ldapSession.queryGroupMembership(groupDN)
        if not groupMembers:
            print("[!] Found 0 results")
        else:
            print("[+]\t Found {} members:\n".format(len(groupMembers)))
            for member in groupMembers:
                print(member)

    if args.da:
        print("[+] Attempting to enumerate all Domain Admins")
        for da_group in DOMAIN_ADMIN_GROUPS:
            daDN = "CN={},CN=Users,{}".format(da_group, ldapSession.domainBase)
            domainAdminResults, searchAttrs = ldapSession.getNestedGroupMemberships(daDN, attrs=attrs)
            if len(domainAdminResults) > 0:
                print("[+] Using DN: CN={},CN=Users.{}".format(da_group, daDN))
                print("[+]\tFound {} Domain Admins:\n".format(len(domainAdminResults)))
                prettyPrintResults(domainAdminResults)
                if args.output_dir:
                    filename = "{}/{}-domainadmins.tsv".format(args.output_dir, startTime)
                    writeResults(domainAdminResults, searchAttrs, filename)

    if args.admin_objects:
        print("[+] Attempting to enumerate all admin (protected) objects")
        adminResults, searchAttrs = ldapSession.getAdminObjects(attrs=attrs)
        print("[+]\tFound {} Admin Objects:\n".format(len(adminResults)))
        prettyPrintResults(adminResults, showDN=True)
        if args.output_dir:
            filename = "{}/{}-adminobjects.tsv".format(args.output_dir, startTime)
            writeResults(adminResults, searchAttrs, filename)

    if args.spns:
        print("[+] Attempting to enumerate all User objects with SPNs")
        spnResults, searchAttrs = ldapSession.getSPNs(attrs=attrs)
        print("[+]\tFound {} Users with SPNs:\n".format(len(spnResults)))
        prettyPrintResults(spnResults, showDN=True)
        if args.output_dir:
            filename = "{}/{}-spns.tsv".format(args.output_dir, startTime)
            writeResults(spnResults, searchAttrs, filename)

    if args.unconstrained_users:
        print("[+] Attempting to enumerate all user objects with unconstrained delegation")
        unconstrainedUserResults, searchAttrs = ldapSession.getUnconstrainedUsers(attrs=attrs)
        print("[+]\tFound {} Users with unconstrained delegation:\n".format(len(unconstrainedUserResults)))
        prettyPrintResults(unconstrainedUserResults, showDN=True)
        if args.output_dir:
            filename = "{}/{}-unconstrained-users.tsv".format(args.output_dir, startTime)
            writeResults(unconstrainedUserResults, searchAttrs, filename)

    if args.unconstrained_computers:
        print("[+] Attempting to enumerate all computer objects with unconstrained delegation")
        unconstrainedComputerResults, searchAttrs = ldapSession.getUnconstrainedComputers(attrs=attrs)
        print("[+]\tFound {} computers with unconstrained delegation:\n".format(len(unconstrainedComputerResults)))
        prettyPrintResults(unconstrainedComputerResults, showDN=True)
        if args.output_dir:
            filename = "{}/{}-unconstrained-computers.tsv".format(args.output_dir, startTime)
            writeResults(unconstrainedComputerResults, searchAttrs, filename)

    if args.gpos:
        print("[+] Attempting to enumerate all group policy objects")
        gpoResults, searchAttrs = ldapSession.getGPOs(attrs=attrs)
        print("[+]\tFound {} GPOs:\n".format(len(gpoResults)))
        prettyPrintResults(gpoResults)
        if args.output_dir:
            filename = "{}/{}-gpos.tsv".format(args.output_dir, startTime)
            writeResults(gpoResults, searchAttrs, filename)

    if args.custom_filter:
        print("[+] Performing custom lookup with filter: \"{}\"".format(args.custom_filter))
        customResults, searchAttrs = ldapSession.doCustomFilterSearch(args.custom_filter, attrs=attrs)
        print("[+]\tFound {} results:\n".format(len(customResults)))
        prettyPrintResults(customResults, showDN=True)
        if args.output_dir:
            filename = "{}/{}-custom.tsv".format(args.output_dir, startTime)
            writeResults(customResults, searchAttrs, filename)

    if args.search_term:
        print("[+] Doing fuzzy search for: \"{}\"".format(args.search_term))
        searchResults = ldapSession.doFuzzySearch(args.search_term)
        print("[+]\tFound {} results:\n".format(len(searchResults)))
        for result in searchResults:
            print(result.dn)

    if args.lookup:
        if not isValidDN(args.lookup):
            print("[+] Searching for matching DNs for term: \"{}\"".format(args.lookup))
            searchResults = ldapSession.doFuzzySearch(args.lookup)
            if not searchResults:
                print("[!] Couldn't find any DNs matching: \"{}\"".format(args.lookup))
                bye(ldapSession)
            elif len(searchResults) == 1:
                lookupDN = searchResults[0].dn
                print("[+]\t Using DN: {}\n".format(lookupDN))
            elif len(searchResults) > 1:
                lookupDN = selectResult(searchResults).dn
        else:
            lookupDN = args.lookup
            print("[+]\t Using DN: {}\n".format(lookupDN))
        if not attrs:
            attrs = ['*']
        lookupResults = ldapSession.doCustomSearch(lookupDN, objectFilter="(cn=*)", attrs=attrs)
        prettyPrintResults(lookupResults)
        if args.output_dir:
            filename = "{}/{}-lookup.tsv".format(args.output_dir, startTime)
            writeResults(lookupResults, searchAttrs, filename)

    bye(ldapSession)


def isValidDN(testdn):
    # super lazy regex way to see if what they entered is a DN
    dnRegex = re.compile('(DC=[^,"]+)+')
    return dnRegex.search(testdn)


def selectResult(results):
    print("[+] Found {} results:\n".format(len(results)))
    for number, result in enumerate(results):
        print("{}: {}".format(number, result.dn))
    print("")
    response = input("Which DN do you want to use? : ")
    return results[int(response)]


def bye(ldapSession):
    ldapSession.unbind()
    print("\n[*] Bye!")
    sys.exit(1)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(add_help=True,
                                     description="Script to perform Windows domain enumeration through LDAP queries to a Domain Controller")
    dgroup = parser.add_argument_group("Domain Options")
    dgroup.add_argument("-d", "--domain", metavar="DOMAIN", dest='domain', type=str,
                        help="The FQDN of the domain (e.g. 'lab.example.com'). Only needed if DC-IP not provided")
    dgroup.add_argument("--dc-ip", metavar="DC_IP", dest='dc_ip', type=str,
                        help="The IP address of a domain controller")

    bgroup = parser.add_argument_group("Bind Options",
                                       "Specify bind account. If not specified, anonymous bind will be attempted")
    bgroup.add_argument("-u", "--user", metavar="USER", dest="username", type=str,
                        help="The full username with domain to bind with (e.g. 'ropnop@lab.example.com' or 'LAB\\ropnop'")
    bgroup.add_argument("-p", "--password", metavar="PASSWORD", dest="password", type=str,
                        help="Password to use. If not specified, will be prompted for")

    egroup = parser.add_argument_group("Enumeration Options", "Data to enumerate from LDAP")
    egroup.add_argument("--functionality", action="store_true",
                        help="Enumerate Domain Functionality level. Possible through anonymous bind")
    egroup.add_argument("-G", "--groups", action="store_true", help="Enumerate all AD Groups")
    egroup.add_argument("-U", "--users", action="store_true", help="Enumerate all AD Users")
    egroup.add_argument("-PU", "--privileged-users", dest="privileged_users", action="store_true",
                        help="Enumerate All privileged AD Users. Performs recursive lookups for nested members.")
    egroup.add_argument("-C", "--computers", action="store_true", help="Enumerate all AD Computers")
    egroup.add_argument("-m", "--members", metavar="GROUP_NAME", dest="group_name", type=str,
                        help="Enumerate all members of a group")
    egroup.add_argument("--da", action="store_true",
                        help="Shortcut for enumerate all members of group 'Domain Admins'. Performs recursive lookups for nested members.")
    egroup.add_argument("--admin-objects", dest="admin_objects", action="store_true",
                        help="Enumerate all objects with protected ACLs (i.e. admins)")
    egroup.add_argument("--user-spns", dest="spns", action="store_true",
                        help="Enumerate all users objects with Service Principal Names (for kerberoasting)")
    egroup.add_argument("--unconstrained-users", dest="unconstrained_users", action="store_true",
                        help="Enumerate all user objects with unconstrained delegation")
    egroup.add_argument("--unconstrained-computers", dest="unconstrained_computers", action="store_true",
                        help="Enumerate all computer objects with unconstrained delegation")
    egroup.add_argument("--gpos", action="store_true", help="Enumerate Group Policy Objects")
    egroup.add_argument("-s", "--search", metavar="SEARCH_TERM", dest="search_term", type=str,
                        help="Fuzzy search for all matching LDAP entries")
    egroup.add_argument("-l", "--lookup", metavar="DN", dest="lookup", type=str,
                        help="Search through LDAP and lookup entry. Works with fuzzy search. Defaults to printing all attributes, but honors '--attrs'")
    egroup.add_argument("--custom", dest="custom_filter",
                        help="Perform a search with a custom object filter. Must be valid LDAP filter syntax")

    ogroup = parser.add_argument_group("Output Options", "Display and output options for results")
    ogroup.add_argument("-r", "--resolve", action="store_true",
                        help="Resolve IP addresses for enumerated computer names. Will make DNS queries against system NS")
    ogroup.add_argument("--attrs", metavar="ATTRS", dest="attrs", type=str,
                        help="Comma separated custom atrribute names to search for (e.g. 'badPwdCount,lastLogon')")
    ogroup.add_argument("--full", action="store_true", help="Dump all atrributes from LDAP.")
    ogroup.add_argument("-o", "--output", metavar="output_dir", dest="output_dir", type=str,
                        help="Save results to TSV files in <OUTPUT_DIR>")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if not (args.domain or args.dc_ip):
        print("[!] You must specify either a domain or the IP address of a domain controller")
        sys.exit(1)

    run(args)
