#!/bin/bash
#simple ping sweeps

#network scan to find live hosts

if [[ $1 -eq 0 ]];then
    printf "please provide CIDR range like so 192.168.178.0/24\n"
    exit 0
fi

printf "scanning using fping...\n"
fping -a -g $1 2>/dev/null 


printf "scanning using nmap...\n"
nmap -sn $1


