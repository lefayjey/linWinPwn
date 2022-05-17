#!/bin/bash
#
# Author: lefayjey
#
# Run if you're having DNS issues or time sync issues while connecting to the target Domain Controller
#

#Colors
RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
PURPLE='\033[1;35m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[-] Please run as root... ${NC}"
  exit
fi

help_conflWP () {
  echo -e "${BLUE}Usage:${NC}"
  echo -e "-t <DC IP>"
  echo -e "-d | Modify DNS server in /etc/resolv.conf (${RED}WARNING:${NC} Please backup resolv.conf before execution)"
  echo -e "-n | Sync system time with the target's (important for Kerberos)"
}

dns=false
ntp=false

while getopts "t:dnh" opt; do
  case $opt in
    t) dc_ip="${OPTARG}";; #mandatory
    d) dns=true;;
    n) ntp=true;;
    h) help_conflWP; exit;;
    \?) echo -e "Unknown option: -${OPTARG}" >&2; exit 1;;
  esac
done

if [ -z "$dc_ip" ] ; then
  echo -e "${RED}[-] Missing target... ${NC}"
  help_conflWP
  exit 1
fi

if [ "$dns" == false ] && [ "$ntp" == false ]; then
  echo -e "${RED}[-] Please specify either DNS update or NTP sync ... ${NC}"
  help_conflWP
  exit 1
fi

if [ "$dns" == true ] ; then
  echo -e "${BLUE}[*] DNS update${NC}"
  echo -e "Content of /etc/resolv.conf before update:"
  echo -e "------------------------------------------"
  cat /etc/resolv.conf
  sed -i '/^#/! s/^/#/g' /etc/resolv.conf
  echo -e "nameserver ${dc_ip}" >> /etc/resolv.conf
  echo -e ""
fi

if [ "$ntp" == true ] ; then
  echo -e "${BLUE}[*] ntp sync${NC}"
  ntpdate ${dc_ip}
fi