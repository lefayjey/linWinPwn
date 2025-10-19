# linWinPwn - Swiss-Army knife for Active Directory Pentesting using Linux

## Description

linWinPwn is a bash script that wraps a number of Active Directory tools for enumeration (LDAP, RPC, ADCS, MSSQL, Kerberos, SCCM), vulnerability checks (noPac, ZeroLogon, MS17-010, MS14-068), object modifications (password change, add user to group, RBCD, Shadow Credentials) and password dumping (secretsdump, lsassy, nanodump, DonPAPI). The script streamlines the use of a large number of tools: impacket, bloodhound, netexec, enum4linux-ng, ldapdomaindump, lsassy, smbmap, kerbrute, adidnsdump, certipy, silenthound, bloodyAD, DonPAPI and many others.

## Setup

Git clone the repository and install requirements using the `install.sh` script
```bash
git clone https://github.com/lefayjey/linWinPwn
cd linWinPwn
chmod +x install.sh
./install.sh
```

Alternatively, build a Docker image and run the Docker container
```bash
docker build -t "linwinpwn:latest" .
docker run --rm -it linwinpwn:latest
```

## Usage

### Mode
The linWinPwn script can be executed in interactive mode (default), or in automated mode (enumeration only).

**1. Interactive Mode (Default)** - Open interactive menu to run checks separately

```bash
linWinPwn -t <Domain_Controller_IP> [-d <AD_domain> -u <AD_user> -p <AD_password> -H <hash[LM:NT]> -K <kerbticket[./krb5cc_ticket]> -A <AES_key> -C <cert[./cert.pfx]> -o <output_dir>]
```

**2. Automated Mode** - Using the `--auto` parameter, run enumeration tools (no exploitation, modifications or password dumping)

When using the automated mode, different checks are performed based on the authentication method.

- Unauthenticated (no credentials provided)
    - Anonymous enumeration using netexec, enum4linux-ng, ldapdomaindump, ldeep
    - RID bruteforce using netexec
    - kerbrute user spray
    - Pre2k authentication check on collected list of computers
    - ASREPRoast using collected list of users (and cracking hashes using john-the-ripper and the rockyou wordlist)
    - Blind Kerberoast
    - CVE-2022-33679 exploit
    - Check for DNS unsecure updates for AS-REQ abuse using krbjack
    - SMB shares anonymous enumeration on identified servers
    - Enumeration for WebDav, dfscoerce, shadowcoerce and Spooler services on identified servers
    - Check for ms17-010, zerologon, petitpotam, nopac, smb-sigining, ntlmv1, runasppl weaknesses
```bash
linWinPwn -t <Domain_Controller_IP> --auto [-o <output_dir>]
```

- Authenticated (using password, NTLM hash, Kerberos ticket, AES key or pfx Certificate)
    - DNS extraction using adidnsdump
    - BloodHound data collection
    - Enumeration using netexec, enum4linux-ng, ldapdomaindump, bloodyAD, sccmhunter, rdwatool, sccmhunter, GPOParser
    - Generate wordlist for password cracking
    - netexec find accounts with user=pass
    - Pre2k authentication check on domain computers
    - Extract ADCS information using certipy and certi.py
    - kerbrute find accounts with user=pass
    - ASREPRoasting (and cracking hashes using john-the-ripper and the rockyou wordlist)
    - Kerberoasting (and cracking hashes using john-the-ripper and the rockyou wordlist)
    - Targeted Kerberoasting (and cracking hashes using john-the-ripper and the rockyou wordlist)
    - SMB shares enumeration on all domain servers using smbmap, FindUncommonShares and cme's spider_plus
    - Enumeration for WebDav, dfscoerce, shadowcoerce and Spooler services on all domain servers (using cme, Coercer and RPC Dump)
    - Check for ms17-010, ms14-068, zerologon, petitpotam, nopac, smb-signing, ntlmv1, runasppl, certifried weaknesses, ldapnightmare, badsuccessor
    - Check mssql privilege escalation paths
    - Check mssql relay possibilities
```bash
linWinPwn -t <Domain_Controller_IP>  -d <AD_domain> -u <AD_user> [-p <AD_password> -H <hash[LM:NT]> -K <kerbticket[./krb5cc_ticket]> -A <AES_key> -C <cert[./cert.pfx]>] [-o <output_dir>] --auto
```

### Parameters

**Auto config** - Run NTP sync with target DC and add entry to /etc/hosts before running the modules

```bash
linWinPwn -t <Domain_Controller_IP> --auto-config
```

**LDAPS** - Use LDAPS instead of LDAP (port 636)

```bash
linWinPwn -t <Domain_Controller_IP> --ldaps
```

**Force Kerberos Auth** - Force using Kerberos authentication instead of NTLM (when possible)

```bash
linWinPwn -t <Domain_Controller_IP> --force-kerb
```

**Verbose** - Enable all verbose and debug outputs

```bash
linWinPwn -t <Domain_Controller_IP> --verbose
```

**Interface** - Choose attacker's network interface

```bash
linWinPwn -t <Domain_Controller_IP> -I tun0
linWinPwn -t <Domain_Controller_IP> --interface eth0
```

**Targets** - Choose targets to be scanned (DC, All, IP=IP_or_hostname, File=./path_to_file)

```bash
linWinPwn -t <Domain_Controller_IP> --targets All
linWinPwn -t <Domain_Controller_IP> --targets DC
linWinPwn -t <Domain_Controller_IP> -T IP=192.168.0.1
linWinPwn -t <Domain_Controller_IP> -T File=./list_servers.txt
```

**Custom wordlists** - Choose custom user and password wordlists

```bash
linWinPwn -t <Domain_Controller_IP> -U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
linWinPwn -t <Domain_Controller_IP> -P /usr/share/seclists/Passwords/xato-net-10-million-passwords.txt
```

### Tunneling

linWinPwn can be particularly useful when you have access to an Active Directory environment for a limited time only, and you wish to be more efficient in the enumeration process and in the collection of evidence.
In addition, linWinPwn can replace the use of enumeration tools on Windows in the aim of reducing the number of created artifacts (e.g., PowerShell commands, Windows Events, created files on disk), and bypassing certain Anti-Virus or EDRs. This can be achieved by performing remote dynamic port forwarding through the creation of an SSH tunnel from the Windows host (e.g., VDI machine or workstation or laptop) to a remote Linux machine (e.g., Pentest laptop or VPS), and running linWinPwn with proxychains.

On the Windows host, run using PowerShell:
```powershell
ssh.exe kali@<linux_machine> -R 1080 -NCqf
```
On the Linux machine, first update `/etc/proxychains4.conf` to include `socks5 127.0.0.1 1080`, then run:
```bash
linWinPwn_proxychains -t <Domain_Controller_IP>  -d <AD_domain> -u <AD_user> [-p <AD_password> -H <hash[LM:NT]> -K <kerbticket[./krb5cc_ticket]> -A <AES_key> -C <cert[./cert.pfx]>] [-o <output_dir>] [--auto]
```

### Current supported authentications

| Tool                    | Null Session | Password | NTLM Hash  | Kerberos Ticket| AES Key     | Certificate |
|-------------------------|--------------|----------|------------|----------------|-------------|-------------|
| `netexec`               | ✅           | ✅       | ✅        | ✅             | ✅         | ✅         |
| `Impacket`              | ✅           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `adidnsdump`            | ✅           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `bloodhound-python`     | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `ldapdomaindump`        | ✅           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `enum4linux-ng`         | ✅           | ✅       | ✅        | ✅             | ❌         | ❌         |
| `bloodyAD`              | ❌           | ✅       | ✅        | ✅             | ❌         | ✅         |
| `SilentHound`           | ✅           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `ldeep`                 | ✅           | ✅       | ✅        | ✅             | ❌         | ✅         |
| `windapsearch`          | ✅           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `LDAPWordlistHarvester` | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `LDAPConsole`           | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `pyLDAPmonitor`         | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `sccmhunter`            | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `ldapper`               | ❌           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `Adalanche`             | ❌           | ✅       | ✅        | ✅             | ❌         | ❌         |
| `GPOwned`               | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `ACED`                  | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `breads`                | ✅           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `godap`                 | ✅           | ✅       | ✅        | ✅             | ❌         | ❌         |
| `adcheck`               | ❌           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `certi.py`              | ❌           | ✅       | ✅        | ✅             | ✅         | ✅         |
| `Certipy`               | ❌           | ✅       | ✅        | ✅             | ✅         | ✅         |
| `certsync`              | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `pre2k`                 | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `orpheus`               | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `smbmap`                | ✅           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `FindUncommonShares`    | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `smbclient-ng`          | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `manspider`             | ✅           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `coercer`               | ✅           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `privexchange`          | ✅           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `RunFinger.py`          | ✅           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `mssqlrelay`            | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `targetedKerberoast`    | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `pygpoabuse`            | ❌           | ✅       | ✅        | ✅             | ❌         | ❌         |
| `DonPAPI`               | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `hekatomb`              | ❌           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `ExtractBitlockerKeys`  | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `evilwinrm`             | ❌           | ✅       | ✅        | ✅             | ✅         | ✅         |
| `mssqlpwner`            | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `SoaPy`                 | ❌           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `SCCMSecrets`           | ✅           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `Soaphound`             | ❌           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `gpoParser`             | ❌           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `spearspray`            | ❌           | ✅       | ❌        | ❌             | ❌         | ❌         |
| `GroupPolicyBackdoor`   | ✅           | ✅       | ✅        | ✅             | ❌         | ❌         |
| `NetworkHound`          | ❌           | ✅       | ✅        | ✅             | ❌         | ❌         |

#### LDAP Channel Binding support
ldap3: netexec, ldapdomaindump (NTLM), Certipy, pre2k, bloodhound, ldeep, GroupPolicyBackdoor



msldap: bloodyAD

#### LDAP Custom port support
netexec, ldapdomaindump, ldeep, windapsearch, godap, pre2k, ldapnomnom

### Interactive Mode Menus

Main menu
```
1) Run DNS Enumeration using adidnsdump
2) Active Directory Enumeration Menu
3) ADCS Enumeration Menu
4) Brute Force Attacks Menu
5) Kerberos Attacks Menu
6) SMB shares Enumeration Menu
7) Vulnerability Checks Menu
8) MSSQL Enumeration Menu
9) Password Dump Menu
10) AD Objects or Attributes Modification Menu
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
12) bloodyAD query DNS server
13) bloodyAD enumerate object
14) SilentHound LDAP Enumeration
15) ldeep LDAP Enumeration
16) windapsearch LDAP Enumeration
17) LDAP Wordlist Harvester
18) LDAP Enumeration using LDAPPER
19) Adalanche Enumeration
20) Enumeration of RDWA servers
21) Open p0dalirius' LDAP Console
22) Open p0dalirius' LDAP Monitor
23) Open garrettfoster13's ACED console
24) Open LDAPPER custom options
25) Run godap console
26) Run ADCheck enumerations
27) Run soapy enumerations
28) Soaphound Enumeration using all collection methods (Noisy!)
29) Soaphound Enumeration using ADWSOnly
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
```

SMB Shares menu
```
1) SMB shares Scan using smbmap
2) SMB shares Enumeration using netexec
3) SMB shares Spidering using netexec
4) SMB shares Scan using FindUncommonShares
5) List all servers and run SMB shares Scan using FindUncommonShares
6) SMB shares Scan using manspider
7) Open smbclient.py console on target
8) Open p0dalirius's smbclientng console on target
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
16) Check for BadSuccessor vuln using netexec
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
6) Dump NTDS using netexec
7) Dump SAM and LSA secrets using netexec
8) Dump SAM and LSA secrets using netexec without touching disk (regdump)
9) Dump LSASS using lsassy
10) Dump LSASS using handlekatz
11) Dump LSASS using procdump
12) Dump LSASS using nanodump
13) Dump dpapi secrets using netexec
14) Dump secrets using DonPAPI
15) Dump secrets using DonPAPI (Disable Remote Ops operations)
16) Dump secrets using hekatomb (only on DC)
17) Search for juicy information using netexec
18) Dump Veeam credentials (only from Veeam server)
19) Dump Msol password (only from Azure AD-Connect server)
20) Extract Bitlocker Keys
21) Dump SAM and LSA secrets using winrm with netexec
```

Modification menu
```
1) Change user or computer password (Requires: ForceChangePassword)
2) Add user to group (Requires: AddMember on group)
3) Remove user from group (Requires: AddMember on group)
4) Add new computer (Requires: MAQ > 0)
5) Add new DNS entry (Requires: Modification of DNS)
6) Enable account (Requires: GenericWrite)
7) Disable account (Requires: GenericWrite)
8) Change Owner of target (Requires: WriteOwner permission)
9) Add GenericAll rights on target (Requires: Owner of object)
10) Delete user or computer (Requires: GenericWrite)
11) Restore deleted user or computer (Requires: GenericWrite on OU of deleted object)
12) Targeted Kerberoast Attack (Noisy!) (Requires: WriteSPN)
13) Perform RBCD attack (Requires: AllowedToAct on computer)
14) Perform RBCD attack on SPN-less user (Requires: AllowedToAct on computer & MAQ=0)
15) Perform ShadowCredentials attack (Requires: AddKeyCredentialLink)
16) Remove added ShadowCredentials (Requires: AddKeyCredentialLink)
17) Abuse GPO to execute command (Requires: GenericWrite on GPO)
18) Add Unconstrained Delegation rights - uac: TRUSTED_FOR_DELEGATION (Requires: SeEnableDelegationPrivilege rights)
19) Add CIFS and HTTP SPNs entries to computer with Unconstrained Deleg rights - ServicePrincipalName & msDS-AdditionalDnsHostName (Requires: Owner of computer)
20) Add userPrincipalName to perform Kerberos impersonation of another user (Requires: GenericWrite on user)
21) Modify userPrincipalName to perform Certificate impersonation (UPN Spoofing - ESC10) (Requires: GenericWrite on user)
22) Add Constrained Delegation rights - uac: TRUSTED_TO_AUTH_FOR_DELEGATION (Requires: SeEnableDelegationPrivilege rights)
23) Add HOST and LDAP SPN entries of DC to computer with Constrained Deleg rights - msDS-AllowedToDelegateTo (Requires: Owner of computer)
```
Command Execution menu
```
1) Open CMD console using smbexec on target
2) Open CMD console using wmiexec on target
3) Open CMD console using psexec on target
4) Open PowerShell console using evil-winrm on target
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
1) Generate and use NTLM hash of current user (requires: password) - Pass the hash
2) Crack NTLM hash of current user and use password (requires: NTLM hash)
3) Generate and use TGT for current user (requires: password, NTLM hash or AES key) - Pass the key/Overpass the hash
4) Extract NTLM hash from Certificate using PKINIT (requires: pfx certificate)
5) Request and use certificate (requires: authentication)
6) Generate AES Key using aesKrbKeyGen (requires: password)
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

## Demos
- HackTheBox Forest

Interactive Mode:
[![asciicast](https://asciinema.org/a/499893.svg)](https://asciinema.org/a/499893)

Automated Mode:
[![asciicast](https://asciinema.org/a/464904.svg)](https://asciinema.org/a/464904)

- TryHackme AttacktiveDirectory

[![asciicast](https://asciinema.org/a/464901.svg)](https://asciinema.org/a/464901)

## TO DO

- Add more enumeration and exploitation tools...

## Credits

- Inspiration: [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t) - WinPwn
- Tools:
    - [fortra](https://github.com/fortra) - impacket
    - [NeffIsBack, Marshall-Hallenbeck, zblurx, mpgn, byt3bl33d3r and all contributors](https://github.com/Pennyw0rth/NetExec) - crackmapexec/netexec
    - [Fox-IT](https://github.com/fox-it) - bloodhound-python
    - [dirkjanm](https://github.com/dirkjanm/) - ldapdomaindump, adidnsdump, privexchange
    - [zer1t0](https://github.com/zer1t0) - certi.py
    - [ly4k](https://github.com/ly4k) - Certipy
    - [ShawnDEvans](https://github.com/ShawnDEvans) - smbmap
    - [ropnop](https://github.com/ropnop) - windapsearch, kerbrute
    - [login-securite](https://github.com/login-securite) - DonPAPI
    - [Processus-Thief](https://github.com/Processus-Thief) - HEKATOMB
    - [layer8secure](https://github.com/layer8secure) - SilentHound
    - [ShutdownRepo](https://github.com/ShutdownRepo) - TargetedKerberoast
    - [franc-pentest](https://github.com/franc-pentest) - ldeep
    - [garrettfoster13](https://github.com/garrettfoster13/) - pre2k, aced, sccmhunter
    - [zblurx](https://github.com/zblurx/) - certsync
    - [p0dalirius](https://github.com/p0dalirius) - Coercer, FindUncommonShares, ExtractBitlockerKeys, LDAPWordlistHarvester, ldapconsole, pyLDAPmonitor, RDWAtool, smbclient-ng, FindUnusualSessions
    - [blacklanternsecurity](https://github.com/blacklanternsecurity/) - MANSPIDER
    - [CravateRouge](https://github.com/CravateRouge) - bloodyAD
    - [shellster](https://github.com/shellster) - LDAPPER
    - [TrustedSec](https://github.com/trustedsec) - orpheus
    - [lkarlslund](https://github.com/lkarlslund) - Adalanche
    - [X-C3LL](https://github.com/X-C3LL) - GPOwned
    - [Hackndo](https://github.com/Hackndo) - pyGPOAbuse
    - [CompassSecurity](https://github.com/CompassSecurity) - mssqlrelay
    - [lgandx](https://github.com/lgandx) - Responder
    - [CobblePot59](https://github.com/CobblePot59) - ADcheck
    - [lkarlslund](https://github.com/lkarlslund) - ldapnomnom
    - [Macmod](https://github.com/Macmod) - godap
    - [ScorpionesLabs](https://github.com/ScorpionesLabs) - MSSqlPwner
    - [barcrange](https://github.com/barcrange) - CVE-2024-49113-Checker
    - [logangoins](https://github.com/logangoins/) - SoaPy
    - [synacktiv](https://github.com/synacktiv/) - SCCMSecrets, gpoParser, GroupPolicyBackdoor
    - [j4s0nmo0n](https://github.com/j4s0nmo0n/) - Soaphound
    - [sikumy](https://github.com/sikumy/) - spearspray
    - [MorDavid](https://github.com/MorDavid/) - NetworkHound

- References:
    -  https://orange-cyberdefense.github.io/ocd-mindmaps/
    -  https://github.com/swisskyrepo/PayloadsAllTheThings
    -  https://book.hacktricks.xyz/
    -  https://adsecurity.org/
    -  https://casvancooten.com/
    -  https://www.thehacker.recipes/
    -  https://www.ired.team/
    -  https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
    -  https://hideandsec.sh/

## Legal Disclamer

Usage of linWinPwn for attacking targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
