# linWinPwn

## Description

linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks. The script leverages and is dependent of a number of tools including: impacket, bloodhound, crackmapexec, ldapdomaindump, lsassy, smbmap, kerbrute, adidnsdump. 

## Setup

Git clone the repository and make the script executable

```bash
git clone https://github.com/lefayjey/linWinPwn
cd linWinPwn; chmod +x linWinPwn.sh
```

Install Linux and Python packages

```bash
sudo apt update
sudo apt install python3 python3-dev python3-pip python3-venv nmap smbmap john libsasl2-dev libldap2-dev ntpdate -y
sudo pip install -r requirements.txt
wget -q "https://raw.githubusercontent.com/micahvandeusen/gMSADumper/main/gMSADumper.py" -O ./Scripts/gMSADumper.py
wget -q "https://raw.githubusercontent.com/zyn3rgy/LdapRelayScan/main/LdapRelayScan.py" -O ./Scripts/LdapRelayScan.py
wget -q "https://raw.githubusercontent.com/ropnop/windapsearch/master/windapsearch.py" -O ./Scripts/windapsearch.py
```

On non-Kali machines, uncomment the lines under `#Non-Kali variables` and run the following commands
```bash
sudo pip install impacket crackmapexec
mkdir -p wordlists && wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz -O ./wordlists/rockyou.txt.tar.gz && gunzip ./wordlists/rockyou.txt.tar.gz && tar xf ./wordlists/rockyou.txt.tar -C ./wordlists/ && chmod 644 ./wordlists/rockyou.txt && rm ./wordlists/rockyou.txt.tar && wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/cirt-default-usernames.txt -O ./wordlists/cirt-default-usernames.txt
```

If you're having DNS issues, run the `update_dns` script
*WARNING: The script will update /etc/resolv.conf, make sure to backup it before running the script*
```bash
chmod +x update_dns.sh
sudo ./update_dns.sh <DC_IP>
```

## Usage

### Modules
The linWinPwn script contains 4 modules that can be used either separately or simultaneously.

**Default (fastest): ad_enum,kerberos** with OPSEC safe checks using `-O` 

```bash
./linWinPwn.sh -O -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP> -o <output_dir>
```

**User modules: ad_enum,kerberos,scan_shares,vuln_checks,mssql_enum**

```bash
./linWinPwn.sh -M user -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP> -o <output_dir>
```

**All modules: ad_enum,kerberos,scan_shares,vuln_checks,mssql_enum,pwd_dump**

```bash
./linWinPwn.sh -M all -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP> -o <output_dir>
```

**Module ad_enum:** Active Directory Enumeration

```bash
./linWinPwn.sh -M ad_enum -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP_or_Target_Domain> -o <output_dir>
```

**Module kerberos:** Kerberos Based Attacks

```bash
./linWinPwn.sh -M kerberos -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP_or_Target_Domain> -o <output_dir>
```

**Module scan_shares:** Network Shares Scan

```bash
./linWinPwn.sh -M scan_shares -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]>  -t <Domain_Controller_IP_or_Target_Domain> -o <output_dir>
```

**Module vuln_checks:** Vulnerability Checks

```bash
./linWinPwn.sh -M vuln_checks -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]>  -t <Domain_Controller_IP_or_Target_Domain> -o <output_dir>
```

**Module mssql_enum:** MSSQL Enumeration

```bash
./linWinPwn.sh -M mssql_enum -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]>  -t <Domain_Controller_IP_or_Target_Domain> -o <output_dir>
```

**Module pwd_dump:** Password Dump

```bash
./linWinPwn.sh -M pwd_dump -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]>  -t <Domain_Controller_IP_or_Target_Domain> -S <domain_servers_list> -o <output_dir>
```

## Demos
- HackTheBox Forest

[![asciicast](https://asciinema.org/a/464904.svg)](https://asciinema.org/a/464904)

- TryHackme AttacktiveDirectory

[![asciicast](https://asciinema.org/a/464901.svg)](https://asciinema.org/a/464901)

## Use cases

For each of the cases described, the linWinPwn script performs different checks as shown below.

**Case 1: Unauthenticated**
- Module ad_enum
    - rid bruteforce
    - user enumeration
    - ldapdomaindump anonymous enumeration
    - Check if ldap-signing is enforced, check for LDAP Relay
- Module kerberos
    - kerbrute user spray
    - ASREPRoast using collected list of users (and cracking hashes using john-the-ripper and the rockyou wordlist)
- Module scan_shares
    - SMB shares anonymous enumeration on identified servers
- Module vuln_checks
    - Enumeration for WebDav and Spooler services on identified servers
    - Check for zerologon, petitpotam, nopac weaknesses

```bash
./linWinPwn.sh -M user -t <Domain_Controller_IP_or_Target_Domain>
```

**Case 2: Standard Account (using password, NTLM hash or Kerberos ticket)**
- DNS extraction using adidnsdump
- Module ad_enum
    - BloodHound data collection
    - ldapdomaindump enumeration
    - Delegation information extraction
    - GPP Passwords extraction
    - Extract ADCS information using certipy
    - Check if ldap-signing is enforced, check for LDAP Relay
    - Extraction of MachineAccountQuota of user, Password Policy and users' descriptions containing "pass"
    - LAPS and gMSA dump
- Module kerberos
    - kerbrute user=pass enumeration
    - ASREPRoasting (and cracking hashes using john-the-ripper and the rockyou wordlist)
    - Kerberoasting (and cracking hashes using john-the-ripper and the rockyou wordlist)
- Module scan_shares
    - SMB shares enumeration on all domain servers
- Module vuln_checks
    - Enumeration for WebDav and Spooler services on all domain servers
    - Check for zerologon, petitpotam, nopac weaknesses
- Module mssql_enum
    - Check mssql privilege escalation paths

```bash
./linWinPwn.sh -M user -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP_or_Target_Domain>
```

**Case 3: Administrator Account (using password, NTLM hash or Kerberos ticket)**
- All of the "Standard User" checks
- Module pwd_dump
    - secretsdump on all domain servers or on provided list of servers with `-S`
    - lsassy on on all domain servers or on provided list of servers with `-S`

```bash
./linWinPwn.sh -M all -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP_or_Target_Domain> -S <domain_servers_list>
```

## To Do
Improve kerberos authentication support

## Credits

- [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t) - WinPwn
- [SecureAuth](https://github.com/SecureAuthCorp) - impacket
- [byt3bl33d3r, mpgn, Porchetta Industries](https://porchetta.industries/) - crackmapexec
- [Fox-IT](https://github.com/fox-it) - bloodhound-python
- [dirkjanm](https://github.com/dirkjanm/) - ldapdomaindump, adidnsdump
- [Hackndo](https://github.com/Hackndo) - lsassy
- [TarlogicSecurity](https://github.com/TarlogicSecurity) - kerbrute
- [zer1t0](https://github.com/zer1t0) - certi.py
- [ly4k](https://github.com/ly4k) - Certipy
- [micahvandeusen](https://github.com/micahvandeusen) - gMSADumper
- [n00py](https://github.com/n00py/) - LAPSDumper
- [zyn3rgy](https://github.com/zyn3rgy) - LdapRelayScan
- [ShawnDEvans](https://github.com/ShawnDEvans) - smbmap
- [ropnop](https://github.com/ropnop) - windapsearch

## Legal Disclamer

Usage of linWinPwn for attacking targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.