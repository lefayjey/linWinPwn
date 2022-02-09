#!/bin/bash
#
# Author: lefayjey
#

RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]
    then echo -e "\n${RED}[Error]${NC} Please run with sudo or as root"
    exit
fi

install_tools() {
    apt install python3 python3-dev python3-pip python3-venv nmap smbmap john git seclists libsasl2-dev libldap2-dev -y
    
    python3 -m pip install --upgrade pip
    
    pip3 install impacket bloodhound crackmapexec ldapdomaindump lsassy kerbrute python-ldap \
    git+https://github.com/dirkjanm/adidnsdump#egg=adidnsdump git+https://github.com/zer1t0/certi.git \
    git+https://github.com/ly4k/Certipy.git --upgrade
    
    gunzip /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz 2>/dev/null
    tar xf /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar -C /usr/share/seclists/Passwords/Leaked-Databases/ 2>/dev/null
    chmod 644 /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt 2>/dev/null

	echo -e "\tgMSADumper"
	wget -q "https://raw.githubusercontent.com/micahvandeusen/gMSADumper/main/gMSADumper.py" -O ./Scripts/gMSADumper.py
	echo -e "\tLdapRelayScan"
	wget -q "https://raw.githubusercontent.com/zyn3rgy/LdapRelayScan/main/LdapRelayScan.py" -O ./Scripts/LdapRelayScan.py
	echo -e "\twindapsearch"
	wget -q "https://raw.githubusercontent.com/ropnop/windapsearch/master/windapsearch.py" -O ./Scripts/windapsearch.py
}

install_tools || { echo -e "\n${RED}[Failure]${NC} Intalling tools failed.. exiting script!\n"; exit 1; }

echo -e "\n${GREEN}[Success]${NC} Setup completed successfully!\n"