#!/bin/bash
# Run if you're having DNS issues while connecting to target Domain Controller
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

sed -i '/^#/! s/^/#/g' /etc/resolv.conf
echo -e "nameserver $1" >> /etc/resolv.conf

sed -i "s/^DNS_SERVER.*/DNS_SERVER=\${PROXYRESOLV_DNS:-$1}/g" /usr/lib/proxychains3/proxyresolv
