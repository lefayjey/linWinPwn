### Interactive Mode Menus

Main menu
```
1) Run DNS Enumeration using netexec
2) Active Directory Enumeration Menu
3) ADCS Enumeration Menu
4) SCCM Enumeration Menu
5) GPO Enumeration Menu
6) Brute Force Attacks Menu
7) Kerberos Attacks Menu
8) SMB shares Enumeration Menu
9) Vulnerability Checks Menu
10) MSSQL Enumeration Menu
11) Password Dump Menu
12) AD Objects or Attributes Modification Menu
13) Command Execution Menu
14) Network Scan Menu
A) Authentication Menu
C) Configuration Menu
exit) Exit
```

AD Enum menu
```
1) BloodHound Enumeration using all collection methods (Noisy!)
2) BloodHound Enumeration using DCOnly
1ce) BloodHoundCE Enumeration using all collection methods (Noisy!)
2ce) BloodHoundCE Enumeration using DCOnly
3) ldapdomaindump LDAP Enumeration
4) enum4linux-ng LDAP-MS-RPC Enumeration
5) MS-RPC Users Enumeration using netexec
6) Password policy Enumeration using netexec
7) LDAP Users Enumeration using netexec
8) LDAP Enumeration using netexec (passnotreq, userdesc, maq, subnets, passpol)
9) Delegation Enumeration using findDelegation and netexec
10) bloodyAD All Enumeration
11) bloodyAD write rights Enumeration
12) bloodyAD write rights Enumeration (details)
13) bloodyAD query DNS server
14) bloodyAD enumerate object
15) SilentHound LDAP Enumeration
16) ldeep LDAP Enumeration
17) windapsearch LDAP Enumeration
18) LDAP Wordlist Harvester
19) LDAP Enumeration using LDAPPER
20) Adalanche Enumeration
21) Enumeration of RDWA servers
22) Open p0dalirius' LDAP Console
23) Open p0dalirius' LDAP Monitor
24) Open garrettfoster13's ACED console
25) Open LDAPPER custom options
26) Run godap console
27) Run ADCheck enumerations
28) Run soapy enumerations
29) Soaphound Enumeration using all collection methods (Noisy!)
30) Soaphound Enumeration using ADWSOnly
31) Run DACLSearch dump and cli
32) ADWS Domain Dump Enumeration
33) PyADRecon LDAP Enumeration
34) PyADRecon ADWS Enumeration
35) Run ADPulse Checks
36) Open PowerView.py Console
37) Scan for GhostSPN
38) Check DNS zones allowing nonsecure dynamic updates using netexec
```

ADCS menu
```
1) ADCS Enumeration using netexec
2) certi.py ADCS Enumeration
3) Certipy ADCS Enumeration
4) Certifried check
5) Certipy LDAP shell via Schannel (using Certificate Authentication)
6) Certipy extract CA and forge Golden Certificate (requires admin rights on PKI server)
7) Dump LSASS using masky
8) Dump NTDS using certsync
```

SCCM menu
```
1) SCCM Enumeration using netexec
2) SCCM Enumeration using sccmhunter
3) SCCM NAA credentials dump using sccmhunter
4) SCCM Policies/NAA credentials dump using SCCMSecrets
```

GPO Menu
```
1) GPP Enumeration using netexec
2) GPO Enumeration using GPOwned
3) GPOParser Enumeration
4) GroupPolicyBackdoor Enumeration
5) GPP Privilege Enumeration using netexec
```

BruteForce menu
```
1) RID Brute Force (Null session) using netexec
2) User Enumeration using kerbrute (Null session)
3) User=Pass check using kerbrute (Noisy!)
4) User=Pass check using netexec (Noisy!)
5) Identify Pre-Created Computer Accounts using netexec (Noisy!)
6) Pre2k computers authentication check (Noisy!)
7) User Enumeration using ldapnomnom (Null session)
8) Password spraying using kerbrute (Noisy!)
9) Password spraying using netexec - ldap (Noisy!)
10) Timeroast attack against NTP
11) MSSQL RID Brute Force (Null session) using netexec
12) Open SpearSpray console
13) Run rbcdbrute attack (Requires RBCD already set up) (Noisy!)
```

Kerberos Attacks menu
```
1) AS REP Roasting Attack using GetNPUsers
2) Kerberoast Attack using GetUserSPNs
3) Cracking AS REP Roast hashes using john the ripper
4) Cracking Kerberoast hashes using john the ripper
5) NoPac check using netexec (only on DC)
6) MS14-068 check (only on DC)
7) CVE-2022-33679 exploit / AS-REP with RC4 session key (Null session)
8) AP-REQ hijack with DNS unsecure updates abuse using krbjack
9) Run custom Kerberoast attack using Orpheus
10) Request TGS for current user (requires: authenticated)
11) Generate Golden Ticket (requires: hash of krbtgt or DCSync rights)
12) Generate Silver Ticket (requires: hash of SPN service account or DCSync rights)
13) Request ticket for another user using S4U2self (OPSEC alternative to Silver Ticket) (requires: authenticated session of SPN service account, for example 'svc')
14) Generate Diamond Ticket (requires: hash of krbtgt or DCSync rights)
15) Generate Sapphire Ticket (requires: hash of krbtgt or DCSync rights)
16) Privilege escalation from Child Domain to Parent Domain using raiseChild (requires: DA rights on child domain)
17) Request impersonated ticket using Constrained Delegation rights (requires: authenticated session of account allowed for delegation, for example 'gmsa')
18) Request impersonated ticket using Resource-Based Constrained Delegation rights (requires: authenticated session of SPN account allowed for RBCD)
19) Request TGS impersonated ticket using dMSA to exploit BadSuccessor (requires: authenticated session of account with BadSuccessor privileges)
```

SMB Shares menu
```
1) SMB shares Scan using smbmap
2) SMB shares Enumeration using netexec
3) SMB shares Spidering using netexec
4) SMB shares Scan using FindUncommonShares
5) List all servers and run SMB shares Scan using FindUncommonShares
6) SMB shares Scan using manspider
7) SMB shares Scan using ShareHound
8) SMB shares Scan using ShareHound (on all subnets)"
9) Open smbclient.py console on target
10) Open p0dalirius's smbclientng console on target
11) Search for LogonScript misconfigurations using ScriptScout
12) Mount SMB share (requires sudo)
```

Vuln Checks menu
```
1) zerologon check using netexec (only on DC)
2) MS17-010 check using netexec
3) Print Spooler and Printnightmare checks using netexec
4) WebDAV check using netexec
5) coerce check using netexec
6) Run coerce attack using netexec
7) SMB signing check using netexec
8) ntlmv1, smbghost and remove-mic checks using netexec
9) RPC Dump and check for interesting protocols
10) Coercer RPC scan
11) PushSubscription abuse using PrivExchange
12) RunFinger scan
13) Run LDAPNightmare check
14) Run sessions enumeration using netexec (reg-sessions)
15) Check for unusual sessions
16) Check for BadSuccessor vuln using netexec and impacket
17) RelayKing coerce scan
18) Drop LNK, Library-MS and SC (on writeable share)
19) onelogon check using netexec (only on DC)
20) Enumerate common (useful) CVEs using netexec
```

MSSQL Enumeration menu
```
1) MSSQL Enumeration using netexec
2) MSSQL Relay check
3) Open mssqlclient.py console on target
4) Open mssqlpwner in interactive mode
5) Enumeration Domain objects using RID bruteforce
```

Password Dump menu
```
1) LAPS Dump using netexec
2) gMSA Dump using netexec
3) DCSync using secretsdump (only on DC)
4) Dump SAM and LSA using secretsdump
5) Dump SAM and SYSTEM using reg
6) Dump SAM and SYSTEM using regsecrets
7) Dump NTDS using netexec
8) Dump SAM and LSA secrets using netexec
9) Dump LSA secrets using netexec
10) Dump SAM and LSA secrets using netexec without touching disk (regdump)
11) Dump LSASS using lsassy
12) Dump LSASS using handlekatz
13) Dump LSASS using procdump
14) Dump LSASS using nanodump
15) Dump dpapi secrets using netexec
16) Dump secrets using DonPAPI
17) Dump secrets using DonPAPI (Disable Remote Ops operations)
18) Dump secrets using hekatomb (only on DC)
19) Search for juicy information using netexec
20) Dump Veeam credentials (only from Veeam server)
21) Dump Msol password (only from Azure AD-Connect server)
22) Extract Bitlocker Keys
23) Dump SAM and LSA secrets using winrm with netexec
```

Modification menu
```
1) Change user or computer password (Requires: ForceChangePassword)
2) Add user to group (Requires: AddMember on group)
3) Remove user from group (Requires: AddMember on group)
4) Add new computer (Requires: MAQ > 0)
4ou) Add new computer to a custom OU location (Requires: MAQ > 0 and GenericWrite on OU)
5) Add new DNS entry (Requires: Modification of DNS)
6) Remove DNS entry (Requires: Modification of DNS)
7) Enable account (Requires: GenericWrite)
8) Disable account (Requires: GenericWrite)
9) Change Owner of target (Requires: WriteOwner permission)
10) Grant FullControl rights on target using dacledit (Requires: WriteDACL)
11) Add GenericAll rights on target (Requires: Owner of object)
12) Delete user or computer (Requires: GenericWrite)
13) Restore deleted user or computer (Requires: GenericWrite on OU of deleted object)
14) Targeted Kerberoast Attack (Noisy!) (Requires: WriteSPN)
15) SPN-jacking attack using krbrelayx's addspn (Requires: WriteSPN)
16) Enable AS-REP roasting - uac: DONT_REQ_PREAUTH (Requires: GenericWrite on userAccountControl)
17) Force RC4 tickets - set msDS-SupportedEncryptionTypes=4 (Requires: GenericWrite on user/computer)
18) Perform RBCD attack (Requires: AllowedToAct on computer)
19) Perform RBCD attack on SPN-less user (Requires: AllowedToAct on computer & MAQ=0)
20) Perform ShadowCredentials attack (Requires: AddKeyCredentialLink)
21) Remove added ShadowCredentials (Requires: AddKeyCredentialLink)
22) Abuse GPO to execute command (Requires: GenericWrite on GPO)
23) Add Unconstrained Delegation rights - uac: TRUSTED_FOR_DELEGATION (Requires: SeEnableDelegationPrivilege rights)
24) Add DCSync rights (Requires: GenericWrite)
25) Add CIFS and HTTP SPNs entries to computer with Unconstrained Deleg rights - ServicePrincipalName & msDS-AdditionalDnsHostName (Requires: Owner of computer)
26) Add userPrincipalName to perform Kerberos impersonation of another user (Targeting Linux machines) (Requires: GenericWrite on user)
27) Modify userPrincipalName to perform Certificate impersonation (ESC10) (Requires: GenericWrite on user)
28) Add Constrained Delegation rights - uac: TRUSTED_TO_AUTH_FOR_DELEGATION (Requires: SeEnableDelegationPrivilege rights)
29) Add HOST and LDAP SPN entries of DC to computer with Constrained Deleg rights - msDS-AllowedToDelegateTo (Requires: Owner of computer)
30) Add dMSA to exploit BadSuccessor on Server 2025 (Requires: GenericWrite on OU)
31) Remove dMSA to clean after exploiting BadSuccessor (Requires: GenericWrite on OU)
32) Modify custom attribute using bloodyad (Requires: GenericWrite)
```

Command Execution menu
```
1) Open CMD console using smbexec on target
2) Open CMD console using wmiexec on target
3) Open CMD console using psexec on target
4) Open PowerShell console using evil-winrm on target
5) Open PowerShell console using evil-winrm-py on target
```

Network Scan menu
```
1) Identify hosts with accessible SMB port using netexec
2) Identify hosts with accessible RDP port using netexec
3) Identify hosts with accessible WinRM port using netexec
4) Identify hosts with accessible SSH port using netexec
5) Identify hosts with accessible FTP port using netexec
6) Identify hosts with accessible VNC port using netexec
7) Identify hosts with accessible MSSQL port using netexec
8) Basic scan of domain machines using NetworkHound
9) Full scan of domain and Shadow IT machines using NetworkHound
```

Auth menu
```
1) Generate NTLM hash of current user - Pass the hash
2) Crack NTLM hash of current user
3) Generate AES Key using aesKrbKeyGen
4) Generate TGT for current user (requires: password, NTLM hash or AES key) - Pass the key/Overpass the hash
5) Request certificate (requires: authentication)
6) Extract NTLM hash from Certificate using PKINIT (requires: pfx certificate)
```

Config menu
```
1) Check installation of tools and dependencies
2) Synchronize time with Domain Controller (requires root)
3) Add Domain Controller's IP and Domain to /etc/hosts (requires root)
4) Update resolv.conf to define Domain Controller as DNS server (requires root)
5) Update krb5.conf to define realm and KDC for Kerberos (requires root)
6) Download default username and password wordlists (non-kali machines)
7) Change users wordlist file
8) Change passwords wordlist file
9) Change attacker's IP
10) Switch between LDAP (port 389) and LDAPS (port 636)
11) Show session information
```
