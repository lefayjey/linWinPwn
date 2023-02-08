#!/bin/bash
#
# Author: lefayjey
#

RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
NC='\033[0m'

scripts_dir="/opt/lwp-scripts"

install_tools() {
    sudo apt update
    sudo apt install python3 python3-dev python3-pip python3-venv nmap smbmap john libsasl2-dev libldap2-dev ntpdate wget zip unzip systemd-timesyncd pipx -y
    sudo mkdir -p ${scripts_dir}
    sudo chown -R $(whoami):$(whoami) ${scripts_dir}
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    pip3 install --user pipx PyYAML LnkParse3 alive_progress --upgrade
    pipx ensurepath
    pipx install git+https://github.com/dirkjanm/ldapdomaindump.git --force
    pipx install git+https://github.com/Porchetta-Industries/CrackMapExec.git --force
    pipx install git+https://github.com/ThePorgs/impacket.git --force
    pipx install git+https://github.com/dirkjanm/adidnsdump.git --force
    pipx install git+https://github.com/zer1t0/certi.git --force
    pipx install git+https://github.com/ly4k/Certipy.git --force
    pipx install git+https://github.com/fox-it/BloodHound.py.git --force
    pipx install git+https://github.com/franc-pentest/ldeep.git --force
    pipx install git+https://github.com/garrettfoster13/pre2k.git --force
    pipx install git+https://github.com/zblurx/certsync.git --force
    wget -q "https://github.com/ropnop/go-windapsearch/releases/latest/download/windapsearch-linux-amd64" -O "$scripts_dir/windapsearch"
    wget -q "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64" -O "$scripts_dir/kerbrute"
    wget -q "https://raw.githubusercontent.com/cddmp/enum4linux-ng/master/enum4linux-ng.py" -O "$scripts_dir/enum4linux-ng.py"
    wget -q "https://raw.githubusercontent.com/Bdenneu/CVE-2022-33679/main/CVE-2022-33679.py" -O "$scripts_dir/CVE-2022-33679.py"
    wget -q "https://raw.githubusercontent.com/layer8secure/SilentHound/main/silenthound.py" -O "$scripts_dir/silenthound.py"
    wget -q "https://raw.githubusercontent.com/ShutdownRepo/targetedKerberoast/main/targetedKerberoast.py" -O "$scripts_dir/targetedKerberoast.py"
    wget -q "https://github.com/login-securite/DonPAPI/archive/master.zip" -O "$scripts_dir/DonPAPI.zip"
    chmod +x "$scripts_dir/windapsearch"
    chmod +x "$scripts_dir/kerbrute"
    chmod +x "$scripts_dir/enum4linux-ng.py"
    chmod +x "$scripts_dir/CVE-2022-33679.py"
    chmod +x "$scripts_dir/silenthound.py"
    chmod +x "$scripts_dir/targetedKerberoast.py"
    unzip -o "$scripts_dir/DonPAPI.zip" -d $scripts_dir
    chmod +x "$scripts_dir/DonPAPI-main/DonPAPI.py"
}

install_tools || { echo -e "\n${RED}[Failure]${NC} Installing tools failed.. exiting script!\n"; exit 1; }

echo -e "\n${GREEN}[Success]${NC} Setup completed successfully!\n"