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
    apt update
    apt install python3 python3-dev python3-pip python3-venv nmap smbmap john libsasl2-dev libldap2-dev ntpdate -y
    pip install impacket crackmapexec
    pip install -r requirements.txt

    mkdir -p wordlists
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz" -O ./wordlists/rockyou.txt.tar.gz
    gunzip ./wordlists/rockyou.txt.tar.gz
    tar xf ./wordlists/rockyou.txt.tar -C ./wordlists/
    chmod 644 ./wordlists/rockyou.txt
    rm ./wordlists/rockyou.txt.tar
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/cirt-default-usernames.txt" -O ./wordlists/cirt-default-usernames.txt
	
	wget -q "https://raw.githubusercontent.com/micahvandeusen/gMSADumper/main/gMSADumper.py" -O ./Scripts/gMSADumper.py
	wget -q "https://raw.githubusercontent.com/zyn3rgy/LdapRelayScan/main/LdapRelayScan.py" -O ./Scripts/LdapRelayScan.py
	wget -q "https://raw.githubusercontent.com/ropnop/windapsearch/master/windapsearch.py" -O ./Scripts/windapsearch.py

    sed -i '/Non-Kali-variables/s/^#//g' ./linWinPwn.sh
}

install_tools || { echo -e "\n${RED}[Failure]${NC} Intalling tools failed.. exiting script!\n"; exit 1; }

echo -e "\n${GREEN}[Success]${NC} Setup completed successfully!\n"