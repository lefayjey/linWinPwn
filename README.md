# linWinPwn - Swiss-Army knife for Active Directory Pentesting using Linux

## Description

linWinPwn is a bash script that wraps a number of Active Directory tools for enumeration (LDAP, RPC, ADCS, MSSQL, Kerberos, SCCM), vulnerability checks (noPac, ZeroLogon, MS17-010, MS14-068), object modifications (password change, add user to group, RBCD, Shadow Credentials) and password dumping (secretsdump, lsassy, nanodump, DonPAPI). The script streamlines the use of a large number of tools: impacket, bloodhound, netexec, enum4linux-ng, ldapdomaindump, lsassy, smbmap, kerbrute, certipy, silenthound, bloodyAD, DonPAPI and many others.

## Setup

Git clone the repository and install requirements using the `install.sh` script
```bash
git clone https://github.com/lefayjey/linWinPwn
cd linWinPwn
chmod +x install.sh
./install.sh
```

Alternatively, use the pre-built Docker image from Docker Hub
```bash
docker pull lefayjey/linwinpwn:latest

# Add linWinPwn_docker to PATH
echo -e "docker run --rm --init -it --net=host -v \$(pwd):/opt/lwp-output lefayjey/linwinpwn:latest \$@" | sudo tee "/usr/local/sbin/linWinPwn_docker"
sudo chmod 755 /usr/local/sbin/linWinPwn_docker
# Run linWinPwn_docker (output to host's current directory)
linWinPwn_docker -t <DC_IP>
linWinPwn_docker -t <DC_IP> -d <domain> -u <user> -p <password> --auto
```

Or build from source
```bash
docker build -t linwinpwn .
docker run --rm --init -it --net=host -v $(pwd):/opt/lwp-output linwinpwn -t <DC_IP>
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
    - DNS extraction using netexec
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
| `ShareHound`            | ✅           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `DACLSearch`            | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `ScriptScout`           | ❌           | ✅       | ❌        | ❌             | ❌         | ❌         |
| `relayking`             | ✅           | ✅       | ✅        | ✅             | ✅         | ❌         |
| `ADWS Domain Dump`      | ❌           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `PyADRecon`             | ❌           | ✅       | ❌        | ✅             | ❌         | ❌         |
| `PyADRecon-ADWS`        | ❌           | ✅       | ❌        | ✅             | ❌         | ❌         |
| `ADPulse`               | ❌           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `PowerView.py`          | ✅           | ✅       | ✅        | ✅             | ✅         | ✅         |
| `evil-winrm-py`         | ❌           | ✅       | ✅        | ❌             | ❌         | ✅         |
| `GhostSPN`              | ✅           | ✅       | ✅        | ❌             | ❌         | ❌         |
| `rbcdbrute`             | ❌           | ✅       | ✅        | ✅             | ✅         | ❌         |

#### LDAP Channel Binding support
ldap3: netexec, ldapdomaindump (NTLM), Certipy, pre2k, bloodhound, ldeep, GroupPolicyBackdoor, relayking

msldap: bloodyAD

#### LDAP Custom port support
netexec, ldapdomaindump, ldeep, windapsearch, godap, pre2k, ldapnomnom

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
    - [dirkjanm](https://github.com/dirkjanm/) - ldapdomaindump, privexchange
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
    - [p0dalirius](https://github.com/p0dalirius) - Coercer, FindUncommonShares, ExtractBitlockerKeys, LDAPWordlistHarvester, ldapconsole, pyLDAPmonitor, RDWAtool, smbclient-ng, FindUnusualSessions, ShareHound, GhostSPN
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
    - [cogiceo](https://github.com/cogiceo/) - DACLSearch
    - [MarcoZufferli](https://github.com/MarcoZufferli) - ScriptScout
    - [depthsecurity](https://github.com/depthsecurity) - relayking
    - [mverschu](https://github.com/mverschu) - ADWS Domain Dump
    - [l4rm4nd](https://github.com/l4rm4nd) - PyADRecon, PyADRecon-ADWS
    - [dievus](https://github.com/dievus) - ADPulse
    - [aniqfakhrul](https://github.com/aniqfakhrul) - PowerView.py
    - [adityatelange](https://github.com/adityatelange) - evil-winrm-py
    - [nnnino](https://github.com/nnnnino) - rbcdbrute

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

## For Developers

### Tool Integrator

`lwp_tool_integrator.py` automates the integration of new tools. It patches `linWinPwn.sh`, `install.sh`, and `README.md` in one step:
- Adds tool variable definition and wrapper function
- Patches `authenticate()` with appropriate flags
- Adds the tool to the interactive menu
- Updates `install.sh` for automatic installation
- Adds reference and auth table row to `README.md`

Usage:
```bash
python3 lwp_tool_integrator.py <tool_config.json>
```
See `lwp_tool_template.json` for a configuration example.

## Legal Disclaimer

Usage of linWinPwn for attacking targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
