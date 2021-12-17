# pentestAD

## Description

pentestAD is a script that automates a large number of Active Directory Enumeration and Exploitation steps. The script leverages and is dependent of a number of tools including: impacket, bloodhound, crackmapexec, ldapdomaindump, lsassy, smbmap, rpcclient. 

## Preparation and setup

Git clone the repository and run the setup script

`git clone https://github.com/lefayjey/pentestAD`

`cd pentestAD; chmod +x setup.sh; chmod +x pentestAD.sh`

`sudo ./setup.sh`

## Functionalities

### Modules
The pentestAD script contains 4 modules that can be used either separately or simultaneously.

**Module 1: Active Directory Enumeration**

`./pentestAD.sh -M ad_enum -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP> -o <output_dir>`

**Module 2: Kerberos Based Attacks**

`./pentestAD.sh -M kerberos -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP> -o <output_dir>`

**Module 3: SMB Shares Enumeration**

`./pentestAD.sh -M scan_shares -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]>  -t <Domain_Controller_IP> -o <output_dir>`

**Module 4: Password Dump (secretsdump and lsassy)**

`./pentestAD.sh -M pwd_dump -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]>  -t <Domain_Controller_IP> -S <domain_servers_list> -o <output_dir>`

Notes:
- Use "-L" with pwd_dump to skip execution of lsassy
- If the list of target servers' IPs was not provided, the pwd_dump module will use the list of all domain servers with SMB port open that were identified using the scan_shares module

**Run all modules**

`./pentestAD.sh -M ad_enum,kerberos,scan_shares,pwd_dump -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP> -o <output_dir>`

### Use cases

For each of the cases described, the pentestAD script performs different checks as shown below.

**Case 1: Unauthenticated**
- [Module ad_enum] rid bruteforce
- [Module ad_enum] rpcclient user enumeration
- [Module ad_enum] ldapdomaindump anonymous enumeration
- [Module kerberos] kerbrute user spray
- [Module kerberos] ASREPRoast using collected list of users (and cracking hashes using john-the-ripper and the rockyou wordlist)
- [Module scan_shares] SMB shares anonymous enumeration on all domain servers

`./pentestAD.sh -M ad_enum,kerberos,scan_shares -d <AD_domain> -t <Domain_Controller_IP> -o <output_dir>`

**Case 2: Standard Account (using password, NTLM hash or Kerberos ticket)**
- [Module ad_enum] BloodHound data collection
- [Module ad_enum] ldapdomaindump enumeration
- [Module ad_enum] Delegation information extraction
- [Module ad_enum] GPP Passwords extraction
- [Module ad_enum] RPC enumeration for interesting protocols
- [Module ad_enum] LAPS and gMSA dump
- [Module kerberos] ASREPRoasting (and cracking hashes using john-the-ripper and the rockyou wordlist)
- [Module kerberos] Kerberoasting (and cracking hashes using john-the-ripper and the rockyou wordlist)
- [Module scan_shares] SMB shares enumeration on all domain servers

`./pentestAD.sh -M ad_enum,kerberos,scan_shares -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP> -o <output_dir>`

**Case 3: Administrator Account (using password, NTLM hash or Kerberos ticket)**
- All of the "Standard User" checks
- [Module pwd_dump] secretsdump on provided list of domain servers 
- [Module pwd_dump] lsassy on on provided list of domain servers

`sudo ./pentestAD.sh -M ad_enum,kerberos,scan_shares,pwd_dump -d <AD_domain> -u <AD_user> -p <AD_password_or_hash[LM:NT]_or_kerbticket[./krb5cc_ticket]> -t <Domain_Controller_IP> -S <domain_servers_list> -o <output_dir>`

### TO DO
- Add AD CS checks
- Add zerologon check
- ...
