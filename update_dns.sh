#!/bin/bash

if [ -z "$1" ]
  then
    echo "IP of Domain Controller/DNS server not supplied"
    echo "Usage: $0 <IP>"
fi

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

sed -i '/^#/! s/^/#/g' /etc/resolv.conf
echo -e "nameserver $1" >> /etc/resolv.conf

sed -i "s/^DNS_SERVER.*/DNS_SERVER=\${PROXYRESOLV_DNS:-$1}/g" /usr/lib/proxychains3/proxyresolv
