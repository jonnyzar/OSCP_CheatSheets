#!/bin/bash
#simple OS fingerprinting


if [[ $1 -eq 0 ]];then
    printf "please provide CIDR range like so 192.168.178.0/24\n"
    exit 0
fi

printf "scanning using nmap...\n"
nmap -Pn -n -O --osscan-guess $1
