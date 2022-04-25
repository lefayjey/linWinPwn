#!/bin/bash
#
# Author: lefayjey
#
# Run if you're having DNS issues or time sync issues while connecting to target Domain Controller
#
# WARNING:
# This will update /etc/resolv.conf and could cause internet connectivity issues
# Please backup /etc/resolv.conf before execution and then revert it in case of issues

if [ -z "$1" ]; then
  echo "IP of Domain Controller/DNS server not supplied"
  echo "Usage: $0 <IP>"
  exit
fi

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi
echo "[*] DNS update"
echo "Current content of /etc/resolv.conf is shown below. Please save the content and restore the /etc/resolv.conf later"
echo "------------------------------------------------------------------------------------------------------------------"
cat /etc/resolv.conf
sed -i '/^#/! s/^/#/g' /etc/resolv.conf
echo -e "nameserver $1" >> /etc/resolv.conf

echo "[*] Proxychains DNS update"
sed -i "s/^DNS_SERVER.*/DNS_SERVER=\${PROXYRESOLV_DNS:-$1}/g" /usr/lib/proxychains3/proxyresolv

echo "[*] ntp sync update"
ntpdate $1