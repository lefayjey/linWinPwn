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
wordlists_dir="/opt/lwp-wordlists"
mkdir -p ${scripts_dir}
mkdir -p ${wordlists_dir}

install_tools() {
    apt update
    apt install python3 python3-dev python3-pip python3-venv nmap smbmap john libsasl2-dev libldap2-dev ntpdate -y
    pip install impacket crackmapexec
    pip install -r requirements.txt

    mkdir -p wordlists
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz" -O "$wordlists_dir/rockyou.txt.tar.gz"
    gunzip "$wordlists_dir/rockyou.txt.tar.gz"
    tar xf "$wordlists_dir/rockyou.txt.tar" -C "$wordlists_dir/"
    chmod 644 "$wordlists_dir/rockyou.txt"
    rm "$wordlists_dir/rockyou.txt.tar"
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/cirt-default-usernames.txt" -O "$wordlists_dir/cirt-default-usernames.txt"
    wget -q "https://github.com/ropnop/go-windapsearch/releases/latest/download/windapsearch-linux-amd64" -O "$scripts_dir/windapsearch"
    wget -q "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64" -O "$scripts_dir/kerbrute"
    wget -q "https://raw.githubusercontent.com/cddmp/enum4linux-ng/master/enum4linux-ng.py" -O "$scripts_dir/enum4linux-ng.py"
    wget -q "https://github.com/login-securite/DonPAPI/archive/master.zip" -O "$scripts_dir/DonPAPI.zip"
    chmod +x "$scripts_dir/windapsearch"
    chmod +x "$scripts_dir/kerbrute"
    unzip -o "$scripts_dir/DonPAPI.zip" -d $scripts_dir
    sed -i '/Non-Kali-variables/s/^#//g' ./linWinPwn.sh
}

install_tools || { echo -e "\n${RED}[Failure]${NC} Intalling tools failed.. exiting script!\n"; exit 1; }

echo -e "\n${GREEN}[Success]${NC} Setup completed successfully!\n"