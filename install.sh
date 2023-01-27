#!/bin/bash
#
# Author: lefayjey
#

RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
NC='\033[0m'

scripts_dir="/opt/lwp-scripts"
sudo mkdir -p ${scripts_dir}

install_tools() {
    sudo apt update
    sudo apt install python3 python3-dev python3-pip python3-venv nmap smbmap john libsasl2-dev libldap2-dev ntpdate -y
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    sudo pip3 install --user pipx PyYAML LnkParse3 alive_progress --upgrade
    pipx ensurepath
    pipx install git+https://github.com/dirkjanm/ldapdomaindump.git --force
    pipx install git+https://github.com/Porchetta-Industries/CrackMapExec.git --force
    pipx install git+https://github.com/ThePorgs/impacket.git --force
    pipx install git+https://github.com/dirkjanm/adidnsdump.git --force
    pipx install git+https://github.com/zer1t0/certi.git --force
    pipx install git+https://github.com/ly4k/Certipy.git --force
    pipx install git+https://github.com/fox-it/BloodHound.py.git --force
    pipx install git+https://github.com/franc-pentest/ldeep.git --force

    sudo wget -q "https://github.com/ropnop/go-windapsearch/releases/latest/download/windapsearch-linux-amd64" -O "$scripts_dir/windapsearch"
    sudo wget -q "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64" -O "$scripts_dir/kerbrute"
    sudo wget -q "https://raw.githubusercontent.com/cddmp/enum4linux-ng/master/enum4linux-ng.py" -O "$scripts_dir/enum4linux-ng.py"
    sudo wget -q "https://raw.githubusercontent.com/Bdenneu/CVE-2022-33679/main/CVE-2022-33679.py" -O "$scripts_dir/CVE-2022-33679.py"
    sudo wget -q "https://raw.githubusercontent.com/layer8secure/SilentHound/main/silenthound.py" -O "$scripts_dir/silenthound.py"
    sudo wget -q "https://raw.githubusercontent.com/ShutdownRepo/targetedKerberoast/main/targetedKerberoast.py" -O "$scripts_dir/targetedKerberoast.py"
    sudo wget -q "https://github.com/login-securite/DonPAPI/archive/master.zip" -O "$scripts_dir/DonPAPI.zip"
    sudo chmod +x "$scripts_dir/windapsearch"
    sudo chmod +x "$scripts_dir/kerbrute"
    sudo chmod +x "$scripts_dir/enum4linux-ng.py"
    sudo chmod +x "$scripts_dir/CVE-2022-33679.py"
    sudo chmod +x "$scripts_dir/silenthound.py"
    sudo chmod +x "$scripts_dir/targetedKerberoast.py"
    sudo unzip -o "$scripts_dir/DonPAPI.zip" -d $scripts_dir
    sudo chmod +x "$scripts_dir/DonPAPI-main/DonPAPI.py"
    sudo chown -R $(whoami) ${scripts_dir}
}

install_tools || { echo -e "\n${RED}[Failure]${NC} Installing tools failed.. exiting script!\n"; exit 1; }

echo -e "\n${GREEN}[Success]${NC} Setup completed successfully!\n"