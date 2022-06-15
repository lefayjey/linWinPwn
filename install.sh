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
    pip install -r requirements.txt

	wget -q "https://raw.githubusercontent.com/micahvandeusen/gMSADumper/main/gMSADumper.py" -O ./Scripts/gMSADumper.py
	wget -q "https://raw.githubusercontent.com/zyn3rgy/LdapRelayScan/main/LdapRelayScan.py" -O ./Scripts/LdapRelayScan.py
	wget -q "https://raw.githubusercontent.com/ropnop/windapsearch/master/windapsearch.py" -O ./Scripts/windapsearch.py
	wget -q "https://raw.githubusercontent.com/cddmp/enum4linux-ng/master/enum4linux-ng.py" -O ./Scripts/enum4linux-ng.py
    wget -q "https://github.com/login-securite/DonPAPI/archive/master.zip" -O /opt/DonPAPI.zip
    unzip -o  /opt/DonPAPI.zip -d /opt/
}

install_tools || { echo -e "\n${RED}[Failure]${NC} Intalling tools failed.. exiting script!\n"; exit 1; }

echo -e "\n${GREEN}[Success]${NC} Setup completed successfully!\n"