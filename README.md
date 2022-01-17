# pentestAD

## Description

pentestAD is a script that automates a large number of Active Directory Enumeration and Exploitation steps. The script leverages and is dependent of a number of tools including: impacket, bloodhound, crackmapexec, ldapdomaindump, lsassy, smbmap, rpcclient. 

## Preparation and setup

Git clone the repository and run the setup script

```bash
git clone https://github.com/lefayjey/pentestAD
cd pentestAD; chmod +x setup.sh; chmod +x pentestAD.sh
sudo ./setup.sh
```

## Functionalities

### Modules
The pentestAD script contains 4 modules that can be used either separately or simultaneously.

**Module 1: Active Directory Enumeration**

```bash
./pentestAD.sh -M ad_enum -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP> -o <output_dir>
```

**Module 2: Kerberos Based Attacks**

```bash
./pentestAD.sh -M kerberos -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP> -o <output_dir>
```

**Module 3: SMB Shares Enumeration**

```bash
./pentestAD.sh -M scan_shares -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]>  -t <Domain_Controller_IP> -o <output_dir>
```

**Module 4: Password Dump (secretsdump and lsassy)**

```bash
./pentestAD.sh -M pwd_dump -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]>  -t <Domain_Controller_IP> -S <domain_servers_list> -o <output_dir>
```

Notes:
- Use `-U` to override default username list
- Use `-P` to override default password list
- Use `-L` with pwd_dump to skip execution of lsassy

**Run all modules**

```bash
./pentestAD.sh -M ad_enum,kerberos,scan_shares,pwd_dump -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP> -o <output_dir>
```

## Demos
- HackTheBox Forest

[![asciicast](https://asciinema.org/a/O7YnFOqvU3Ssd2lntzlEIuQIa.svg)](https://asciinema.org/a/O7YnFOqvU3Ssd2lntzlEIuQIa)

- TryHackme AttacktiveDirectory

[![asciicast](https://asciinema.org/a/e5KyoRJyigiQM6nRqLF3nomrZ.svg)](https://asciinema.org/a/e5KyoRJyigiQM6nRqLF3nomrZ)

### Use cases

For each of the cases described, the pentestAD script performs different checks as shown below.

**Case 1: Unauthenticated**
- Module ad_enum
    - rid bruteforce
    - rpcclient user enumeration
    - ldapdomaindump anonymous enumeration
- Module kerberos
    - kerbrute user spray
    - ASREPRoast using collected list of users (and cracking hashes using john-the-ripper and the rockyou wordlist)
- Module scan_shares
    - SMB shares anonymous enumeration on domain controller

```bash
./pentestAD.sh -M ad_enum,kerberos,scan_shares -d <AD_domain> -t <Domain_Controller_IP> -o <output_dir>
```

**Case 2: Standard Account (using password, NTLM hash or Kerberos ticket)**
- DNS extraction using adidnsdump
- Module ad_enum
    - BloodHound data collection
    - ldapdomaindump enumeration
    - Extraction of MachineAccountQuota of user, and all users' descriptions 
    - Delegation information extraction
    - GPP Passwords extraction
    - Enumeration for interesting services (WebDav, Spooler, etc.)
    - LAPS and gMSA dump
- Module kerberos
    - ASREPRoasting (and cracking hashes using john-the-ripper and the rockyou wordlist)
    - Kerberoasting (and cracking hashes using john-the-ripper and the rockyou wordlist)
- Module scan_shares
    - SMB shares enumeration on all domain servers

```bash
./pentestAD.sh -M ad_enum,kerberos,scan_shares -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP> -o <output_dir>
```

**Case 3: Administrator Account (using password, NTLM hash or Kerberos ticket)**
- All of the "Standard User" checks
- Module pwd_dump
    - secretsdump on provided list of domain servers 
    - lsassy on on provided list of domain servers

```bash
./pentestAD.sh -M ad_enum,kerberos,scan_shares,pwd_dump -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP> -S <domain_servers_list> -o <output_dir>
```

### TO DO
- Add MSSQL checks
- ...
