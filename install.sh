#!/bin/bash
#
# Author: lefayjey
# GNU/Linux Distro and Rust detection: ReK2, Hispagatos
#

RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
NC='\033[0m'

scripts_dir="/opt/lwp-scripts"

# Detect Linux Distribution
if command -v apt-get >/dev/null; then
    PKG_MANAGER="apt-get"
    PACKAGES="python3 python3-dev python3-pip python3-venv python3.11 python3.11-venv python3.11-dev nmap smbmap john libsasl2-dev libldap2-dev libkrb5-dev ntpdate wget zip unzip systemd-timesyncd pipx swig curl jq openssl rlwrap"
elif command -v pacman >/dev/null; then
    PKG_MANAGER="pacman"
    PACKAGES="python python-pip python-virtualenv nmap smbmap john libsasl openldap krb5 ntp wget zip unzip systemd python-pipx swig curl jq openssl"
else
    echo -e "${RED}[Error]${NC} Unsupported Linux distribution"
    exit 1
fi

install_tools() {
    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        echo -e "${BLUE}Installing tools using apt...${NC}"
        sudo apt-get update && sudo apt-get install -y $PACKAGES
    elif [[ "$PKG_MANAGER" == "pacman" ]]; then
        echo -e "${BLUE}Installing tools using pacman...${NC}"
        sudo pacman -Sy --needed --noconfirm $PACKAGES
    fi

    echo -e ""
    # Check if Rust is installed, and install if it's missing
    if ! command -v rustc >/dev/null; then
        echo -e "${BLUE}Rust not found, installing Rust...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source ~/.cargo/env
        echo -e "${GREEN}Rust installed successfully.${NC}"
    else
        echo -e "${GREEN}Rust is already installed.${NC}"
    fi 

    echo -e ""
    echo -e "${BLUE}Installing python tools using pip and pipx...${NC}"
    pipx ensurepath
    #pipx install git+https://github.com/deadjakk/ldapdomaindump --force #LDAP Channel Binding
    #/home/$(whoami)/.local/share/pipx/venvs/ldapdomaindump/bin/python3 -m pip install git+https://github.com/ly4k/ldap3 #LDAP Channel Binding
    pipx install git+https://github.com/dirkjanm/ldapdomaindump.git --force
    pipx install git+https://github.com/Pennyw0rth/NetExec.git --force
    pipx install git+https://github.com/fortra/impacket.git --force
    pipx install git+https://github.com/dirkjanm/adidnsdump.git --force
    pipx install git+https://github.com/zer1t0/certi.git --force
    pipx install git+https://github.com/ly4k/Certipy.git --force
    #pipx install git+https://github.com/zimedev/certipy-merged --force #Certipy with more features
    #/home/$(whoami)/.local/share/pipx/venvs/certipy-ad/bin/python3 -m pip install git+https://github.com/ly4k/ldap3 #LDAP Channel Binding
    #pipx install git+https://github.com/deadjakk/BloodHound.py --force #LDAP Channel Binding
    #/home/$(whoami)/.local/share/pipx/venvs/bloodhound/bin/python3 -m pip install git+https://github.com/ly4k/ldap3 #LDAP Channel Binding
    pipx install git+https://github.com/dirkjanm/Bloodhound.py --force
    pipx install "git+https://github.com/dirkjanm/BloodHound.py@bloodhound-ce" --force --suffix '_ce'
    pipx install git+https://github.com/franc-pentest/ldeep.git --force
    pipx install git+https://github.com/garrettfoster13/pre2k.git --force
    pipx install git+https://github.com/zblurx/certsync.git --force
    pipx install hekatomb --force
    pipx install git+https://github.com/blacklanternsecurity/MANSPIDER --force
    pipx install git+https://github.com/p0dalirius/Coercer --force
    pipx install git+https://github.com/CravateRouge/bloodyAD --force
    pipx install git+https://github.com/login-securite/DonPAPI --force
    pipx install git+https://github.com/p0dalirius/RDWAtool --force
    pipx install git+https://github.com/almandin/krbjack --force
    pipx install git+https://github.com/CompassSecurity/mssqlrelay.git --force
    pipx install git+https://github.com/CobblePot59/ADcheck.git --force
    pipx install --force --pip-args="--use-deprecated=legacy-resolver" "git+https://github.com/ajm4n/adPEAS#egg=adPEAS"
    pipx install git+https://github.com/oppsec/breads.git --force
    pipx install git+https://github.com/p0dalirius/smbclient-ng --force
    pipx install --python python3.11 git+https://github.com/ScorpionesLabs/MSSqlPwner.git --force
    pipx install --python python3.11 git+https://github.com/xforcered/SoaPy --force
    echo -e ""
    echo -e "${BLUE}Downloading tools and scripts using wget and unzipping...${NC}"
    sudo mkdir -p ${scripts_dir}
    sudo mkdir -p ${scripts_dir}/ldapper
    sudo mkdir -p ${scripts_dir}/Responder
    sudo chown -R "$(whoami)":"$(whoami)" ${scripts_dir}
    python3 -m venv "${scripts_dir}/.venv"
    source "${scripts_dir}/.venv/bin/activate"
    pip3 install PyYAML alive-progress xlsxwriter sectools typer colorama impacket tabulate arc4 msldap pandas requests requests_ntlm requests_toolbelt cmd2 pycryptodome --upgrade
    deactivate
    
    wget -q "https://github.com/ropnop/go-windapsearch/releases/latest/download/windapsearch-linux-amd64" -O "$scripts_dir/windapsearch"
    wget -q "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64" -O "$scripts_dir/kerbrute"
    wget -q "https://raw.githubusercontent.com/cddmp/enum4linux-ng/master/enum4linux-ng.py" -O "$scripts_dir/enum4linux-ng.py"
    wget -q "https://raw.githubusercontent.com/Bdenneu/CVE-2022-33679/main/CVE-2022-33679.py" -O "$scripts_dir/CVE-2022-33679.py"
    wget -q "https://raw.githubusercontent.com/layer8secure/SilentHound/main/silenthound.py" -O "$scripts_dir/silenthound.py"
    wget -q "https://raw.githubusercontent.com/ShutdownRepo/targetedKerberoast/main/targetedKerberoast.py" -O "$scripts_dir/targetedKerberoast.py"
    wget -q "https://raw.githubusercontent.com/p0dalirius/FindUncommonShares/main/FindUncommonShares.py" -O "$scripts_dir/FindUncommonShares.py"
    wget -q "https://raw.githubusercontent.com/p0dalirius/ExtractBitlockerKeys/refs/heads/main/python/ExtractBitlockerKeys.py" -O "$scripts_dir/ExtractBitlockerKeys.py"
    wget -q "https://raw.githubusercontent.com/p0dalirius/ldapconsole/master/ldapconsole.py" -O "$scripts_dir/ldapconsole.py"
    wget -q "https://raw.githubusercontent.com/p0dalirius/LDAPmonitor/master/python/pyLDAPmonitor.py" -O "$scripts_dir/pyLDAPmonitor.py"
    wget -q "https://raw.githubusercontent.com/p0dalirius/LDAPWordlistHarvester/main/LDAPWordlistHarvester.py" -O "$scripts_dir/LDAPWordlistHarvester.py"
    wget -q "https://github.com/garrettfoster13/aced/archive/refs/heads/main.zip" -O "$scripts_dir/aced.zip"
    wget -q "https://github.com/garrettfoster13/sccmhunter/archive/refs/heads/main.zip" -O "$scripts_dir/sccmhunter.zip"
    wget -q "https://raw.githubusercontent.com/shellster/LDAPPER/master/ldapper.py" -O "$scripts_dir/ldapper/ldapper.py"
    wget -q "https://raw.githubusercontent.com/shellster/LDAPPER/master/utilities.py" -O "$scripts_dir/ldapper/utilities.py"
    wget -q "https://raw.githubusercontent.com/shellster/LDAPPER/master/queries.py" -O "$scripts_dir/ldapper/queries.py"
    wget -q "https://raw.githubusercontent.com/shellster/LDAPPER/master/ldap_connector.py" -O "$scripts_dir/ldapper/ldap_connector.py"
    wget -q "https://github.com/trustedsec/orpheus/archive/refs/heads/main.zip" -O "$scripts_dir/orpheus.zip"
    wget -q "https://github.com/lkarlslund/Adalanche/releases/latest/download/adalanche-linux-x64-v2024.1.11" -O "$scripts_dir/adalanche"
    wget -q "https://github.com/Hackndo/pyGPOAbuse/archive/refs/heads/master.zip" -O "$scripts_dir/pyGPOAbuse.zip"
    wget -q "https://raw.githubusercontent.com/X-C3LL/GPOwned/main/GPOwned.py" -O "$scripts_dir/GPOwned.py"
    wget -q "https://raw.githubusercontent.com/dirkjanm/PrivExchange/master/privexchange.py" -O "$scripts_dir/privexchange.py"
    wget -q "https://raw.githubusercontent.com/lgandx/Responder/master/tools/RunFinger.py" -O "$scripts_dir/Responder/RunFinger.py"
    wget -q "https://raw.githubusercontent.com/lgandx/Responder/master/tools/odict.py" -O "$scripts_dir/Responder/odict.py"
    wget -q "https://raw.githubusercontent.com/lgandx/Responder/master/tools/RunFingerPackets.py" -O "$scripts_dir/Responder/RunFingerPackets.py"
    wget -q "https://github.com/lkarlslund/ldapnomnom/releases/latest/download/ldapnomnom-linux-x64" -O "$scripts_dir/ldapnomnom"
    wget -q "https://github.com/Macmod/godap/releases/download/v2.8.0/godap-v2.8.0-linux-amd64.tar.gz" -O "$scripts_dir/godap-v2.8.0-linux-amd64.tar.gz"
    wget -q "https://raw.githubusercontent.com/Tw1sm/aesKrbKeyGen/refs/heads/master/aesKrbKeyGen.py" -O "$scripts_dir/aesKrbKeyGen.py"
    wget -q "https://raw.githubusercontent.com/barcrange/CVE-2024-49113-Checker/refs/heads/main/CVE-2024-49113-checker.py" -O "$scripts_dir/CVE-2024-49113-checker.py"

    unzip -o "$scripts_dir/aced.zip" -d "$scripts_dir"
    unzip -o "$scripts_dir/sccmhunter.zip" -d "$scripts_dir"
    unzip -o "$scripts_dir/orpheus.zip" -d "$scripts_dir"
    unzip -o "$scripts_dir/pyGPOAbuse.zip" -d "$scripts_dir"
    tar -C $scripts_dir -xf "$scripts_dir/godap-v2.8.0-linux-amd64.tar.gz" godap

    chmod +x "$scripts_dir/aced-main/aced.py"
    chmod +x "$scripts_dir/sccmhunter-main/sccmhunter.py"
    chmod +x "$scripts_dir/windapsearch"
    chmod +x "$scripts_dir/kerbrute"
    chmod +x "$scripts_dir/enum4linux-ng.py"
    chmod +x "$scripts_dir/CVE-2022-33679.py"
    chmod +x "$scripts_dir/silenthound.py"
    chmod +x "$scripts_dir/targetedKerberoast.py"
    chmod +x "$scripts_dir/FindUncommonShares.py"
    chmod +x "$scripts_dir/ExtractBitlockerKeys.py"
    chmod +x "$scripts_dir/ldapconsole.py"
    chmod +x "$scripts_dir/pyLDAPmonitor.py"
    chmod +x "$scripts_dir/LDAPWordlistHarvester.py"
    chmod +x "$scripts_dir/ldapper/ldapper.py"
    chmod +x "$scripts_dir/orpheus-main/orpheus.py"
    chmod +x "$scripts_dir/orpheus-main/GetUserSPNs.py"
    chmod +x "$scripts_dir/adalanche"
    chmod +x "$scripts_dir/pyGPOAbuse-master/pygpoabuse.py"
    chmod +x "$scripts_dir/GPOwned.py"
    chmod +x "$scripts_dir/privexchange.py"
    chmod +x "$scripts_dir/Responder/RunFinger.py"
    chmod +x "$scripts_dir/Responder/odict.py"
    chmod +x "$scripts_dir/Responder/RunFingerPackets.py"
    chmod +x "$scripts_dir/ldapnomnom"
    chmod +x "$scripts_dir/godap"
    chmod +x "$scripts_dir/aesKrbKeyGen.py"
    chmod +x "$scripts_dir/CVE-2024-49113-checker.py"
}

install_tools || { echo -e "\n${RED}[Failure]${NC} Installing tools failed.. exiting script!\n"; exit 1; }

echo -e "\n${GREEN}[Success]${NC} Setup completed successfully! Open a new terminal to load the shell's configuration ... \n"
