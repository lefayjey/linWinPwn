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

scripts_dir="/opt/lwp-scripts"
mkdir -p ${scripts_dir}

install_tools() {
    apt update
    apt install python3 python3-dev python3-pip python3-venv nmap smbmap john libsasl2-dev libldap2-dev ntpdate -y
    pip install --user pipx "PyYAML>=5.1" LnkParse3
    pipx ensurepath
    pipx install git+https://github.com/dirkjanm/ldapdomaindump.git
    pipx install git+https://github.com/Porchetta-Industries/CrackMapExec.git
    pipx install git+https://github.com/ThePorgs/impacket.git
    pipx install git+https://github.com/dirkjanm/adidnsdump.git
    pipx install git+https://github.com/zer1t0/certi.git
    pipx install git+https://github.com/ly4k/Certipy.git
    pipx install git+https://github.com/fox-it/BloodHound.py.git

    wget -q "https://github.com/ropnop/go-windapsearch/releases/latest/download/windapsearch-linux-amd64" -O "$scripts_dir/windapsearch"
    wget -q "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64" -O "$scripts_dir/kerbrute"
    wget -q "https://raw.githubusercontent.com/cddmp/enum4linux-ng/master/enum4linux-ng.py" -O "$scripts_dir/enum4linux-ng.py"
    wget -q "https://raw.githubusercontent.com/Bdenneu/CVE-2022-33679/main/CVE-2022-33679.py" -O "$scripts_dir/CVE-2022-33679.py"
    wget -q "https://raw.githubusercontent.com/layer8secure/SilentHound/main/silenthound.py" -O "$scripts_dir/silenthound.py"
    wget -q "https://github.com/login-securite/DonPAPI/archive/master.zip" -O "$scripts_dir/DonPAPI.zip"
    chmod +x "$scripts_dir/windapsearch"
    chmod +x "$scripts_dir/kerbrute"
    unzip -o "$scripts_dir/DonPAPI.zip" -d $scripts_dir
}

install_tools || { echo -e "\n${RED}[Failure]${NC} Installing tools failed.. exiting script!\n"; exit 1; }

echo -e "\n${GREEN}[Success]${NC} Setup completed successfully!\n"