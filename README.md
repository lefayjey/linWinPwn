# linWinPwn - Active Directory Vulnerability Scanner

## Description

linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks. The script uses a number of tools and serves as wrapper of them. Tools include: impacket, bloodhound, netexec, enum4linux-ng, ldapdomaindump, lsassy, smbmap, kerbrute, adidnsdump, certipy, silenthound, and others. 

linWinPwn is particularly useful when you have access to an Active Directory environment for a limited time only, and you wish to automate the enumeration process and collect evidence efficiently.
In addition, linWinPwn can replace the use of enumeration tools on Windows in the aim of reducing the number of created artifacts (e.g., PowerShell commands, Windows Events, created files on disk), and bypassing certain Anti-Virus or EDRs. This can be achieved by performing remote dynamic port forwarding through the creation of an SSH tunnel from the Windows host (e.g., VDI machine or workstation or laptop) to a remote Linux machine (e.g., Pentest laptop or VPS), and running linWinPwn with proxychains.

On the Windows host, run using PowerShell:
```
ssh kali@<linux_machine> -R 1080 -NCqf
```
On the Linux machine, first update `/etc/proxychains4.conf` to include `socks5 127.0.0.1 1080`, then run:
```
proxychains ./linWinPwn.sh -t <Domain_Controller_IP>
```

## Setup

Git clone the repository and make the script executable

```bash
git clone https://github.com/lefayjey/linWinPwn
cd linWinPwn; chmod +x linWinPwn.sh
```

Install requirements using the `install.sh` script (using standard account)
```bash
chmod +x install.sh
./install.sh
```

## Usage


### Modules
The linWinPwn script contains 6 modules that can be used either separately or simultaneously.

**Default: interactive** - Open interactive menu to run checks separately  

```bash
./linWinPwn.sh -t <Domain_Controller_IP> [-d <AD_domain> -u <AD_user> -p <AD_password> -H <hash[LM:NT]> -K <kerbticket[./krb5cc_ticket]> -A <AES_key> -o <output_dir>]
```

**User modules: ad_enum,kerberos,scan_shares,vuln_checks,mssql_enum**

```bash
./linWinPwn.sh -t <Domain_Controller_IP> -M user -d <AD_domain> -u <AD_user> -p <AD_password>
```

**All modules: ad_enum,kerberos,scan_shares,vuln_checks,mssql_enum,pwd_dump**

```bash
./linWinPwn.sh -t <Domain_Controller_IP> -M all -d <AD_domain> -u <AD_user> -p <AD_password>
```

**Module ad_enum:** Active Directory Enumeration

```bash
./linWinPwn.sh -t <Domain_Controller_IP> -M ad_enum -d <AD_domain> -u <AD_user> -p <AD_password>
```

**Module kerberos:** Kerberos Based Attacks

```bash
./linWinPwn.sh -t <Domain_Controller_IP> -M kerberos -d <AD_domain> -u <AD_user> -p <AD_password>
```

**Module scan_shares:** Network Shares Scan

```bash
./linWinPwn.sh -t <Domain_Controller_IP> -M scan_shares -d <AD_domain> -u <AD_user> -p <AD_password>
```

**Module vuln_checks:** Vulnerability Checks

```bash
./linWinPwn.sh -t <Domain_Controller_IP> -M vuln_checks -d <AD_domain> -u <AD_user> -p <AD_password>
```

**Module mssql_enum:** MSSQL Enumeration

```bash
./linWinPwn.sh -t <Domain_Controller_IP> -M mssql_enum -d <AD_domain> -u <AD_user> -p <AD_password>
```

**Module pwd_dump:** Password Dump

```bash
./linWinPwn.sh -t <Domain_Controller_IP> -M pwd_dump -d <AD_domain> -u <AD_user> -p <AD_password>
```

### Parameters

**Auto config** - Run NTP sync with target DC and add entry to /etc/hosts before running the modules

```bash
./linWinPwn.sh -t <Domain_Controller_IP> --auto-config
```

**LDAPS** - Use LDAPS instead of LDAP (port 636)

```bash
./linWinPwn.sh -t <Domain_Controller_IP> --ldaps
```

**Force Kerberos Auth** - Force using Kerberos authentication instead of NTLM (when possible)

```bash
./linWinPwn.sh -t <Domain_Controller_IP> --force-kerb
```

**Verbose** - Enable all verbose and debug outputs

```bash
./linWinPwn.sh -t <Domain_Controller_IP> --verbose
```

**Interface** - Choose attacker's network interface

```bash
./linWinPwn.sh -t <Domain_Controller_IP> -I tun0
./linWinPwn.sh -t <Domain_Controller_IP> --interface eth0
```

**Targets** - Choose targets to be scanned (DC, All, IP=IP_or_hostname, File=./path_to_file)

```bash
./linWinPwn.sh -t <Domain_Controller_IP> -T All
./linWinPwn.sh -t <Domain_Controller_IP> --targets DC
./linWinPwn.sh -t <Domain_Controller_IP> -T IP=192.168.0.1
./linWinPwn.sh -t <Domain_Controller_IP> -T File=./list_servers.txt
```

## Demos
- HackTheBox Forest

Interactive Mode:
[![asciicast](https://asciinema.org/a/499893.svg)](https://asciinema.org/a/499893)

Automated Mode:
[![asciicast](https://asciinema.org/a/464904.svg)](https://asciinema.org/a/464904)

- TryHackme AttacktiveDirectory

[![asciicast](https://asciinema.org/a/464901.svg)](https://asciinema.org/a/464901)

## Use cases

For each of the cases described, the linWinPwn script performs different checks as shown below.

**Case 1: Unauthenticated**
- Module ad_enum
    - RID bruteforce using netexec
    - Anonymous enumeration using netexec, enum4linux-ng, ldapdomaindump, ldeep
    - Pre2k authentication check on collected list of computers
- Module kerberos
    - kerbrute user spray
    - ASREPRoast using collected list of users (and cracking hashes using john-the-ripper and the rockyou wordlist)
    - Blind Kerberoast
    - CVE-2022-33679 exploit
    - Check for DNS unsecure updates for AS-REQ abuse using krbjack
- Module scan_shares
    - SMB shares anonymous enumeration on identified servers
- Module vuln_checks
    - Enumeration for WebDav, dfscoerce, shadowcoerce and Spooler services on identified servers
    - Check for ms17-010, zerologon, petitpotam, nopac, smb-sigining, ntlmv1, runasppl weaknesses

```bash
./linWinPwn.sh -t <Domain_Controller_IP_or_Target_Domain> -M user
```

**Case 2: Standard Account (using password, NTLM hash or Kerberos ticket)**
- DNS extraction using adidnsdump
- Module ad_enum
    - BloodHound data collection
    - Enumeration using netexec, enum4linux-ng, ldapdomaindump, windapsearch, SilentHound, ldeep, bloodyAD, sccmhunter, ldapper
        - Users
        - MachineAccountQuota
        - Password Policy
        - Users' descriptions containing "pass"
        - ADCS
        - Subnets
        - GPP Passwords
        - Check if ldap signing is enforced, check for LDAP Relay
        - Delegation information
        - RDWA and SCCM servivces
    - Generate wordlist for password cracking
    - netexec find accounts with user=pass 
    - Pre2k authentication check on domain computers
    - Extract ADCS information using certipy and certi.py
 
- Module kerberos
    - kerbrute find accounts with user=pas
    - ASREPRoasting (and cracking hashes using john-the-ripper and the rockyou wordlist)
    - Kerberoasting (and cracking hashes using john-the-ripper and the rockyou wordlist)
    - Targeted Kerberoasting (and cracking hashes using john-the-ripper and the rockyou wordlist)
- Module scan_shares
    - SMB shares enumeration on all domain servers using smbmap FindUncommonShares, manspider and cme's spider_plus
    - KeePass files and processes discovery on all domain servers
- Module vuln_checks
    - Enumeration for WebDav, dfscoerce, shadowcoerce and Spooler services on all domain servers (using cme, Coercer and RPC Dump)
    - Check for ms17-010, ms14-068, zerologon, petitpotam, nopac, smb-signing, ntlmv1, runasppl, certifried weaknesses
- Module mssql_enum
    - Check mssql privilege escalation paths

```bash
./linWinPwn.sh -t <Domain_Controller_IP_or_Target_Domain> -d <AD_domain> -u <AD_user> -p <AD_password> -H <hash[LM:NT]> -K <kerbticket[./krb5cc_ticket]> -A <AES_key> -C <cert[./cert.pfx]> -M user
```

**Case 3: Administrator Account (using password, NTLM hash or Kerberos ticket)**
- All of the "Standard User" checks
- Module pwd_dump
    - LAPS and gMSA dump
    - SAM SYSTEM extraction
    - secretsdump on all domain servers
    - NTDS dump using impacket, netexec and certsync
    - Dump lsass on all domain servers using: procdump, lsassy, nanodump, handlekatz, masky
    - Extract backup keys using DonPAPI, HEKATOMB
    - Extract bitlocker keys

```bash
./linWinPwn.sh -t <Domain_Controller_IP_or_Target_Domain> -d <AD_domain> -u <AD_user> -p <AD_password> -H <hash[LM:NT]> -K <kerbticket[./krb5cc_ticket]> -A <AES_key> -C <cert[./cert.pfx]> -M all
```

## TO DO

- Add more enumeration and exploitation tools...
- Add Kerberos delegation attacks

## Credits

- Inspiration: [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t) - WinPwn
- Tools: 
    - [fortra](https://github.com/fortra) - impacket
    - [NeffIsBack, Marshall-Hallenbeck, zblurx, mpgn, byt3bl33d3r and all contributors](https://github.com/Pennyw0rth/NetExec) - crackmapexec/netexec
    - [Fox-IT](https://github.com/fox-it) - bloodhound-python
    - [dirkjanm](https://github.com/dirkjanm/) - ldapdomaindump, adidnsdump
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
    - [p0dalirius](https://github.com/p0dalirius) - Coercer, FindUncommonShares, ExtractBitlockerKeys, LDAPWordlistHarvester, ldapconsole, pyLDAPmonitor, RDWAtool
    - [blacklanternsecurity](https://github.com/blacklanternsecurity/) - MANSPIDER
    - [CravateRouge](https://github.com/CravateRouge) - bloodyAD
    - [shellster](https://github.com/shellster) - LDAPPER

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
