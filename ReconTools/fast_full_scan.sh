#!/bin/bash

TARGET=$1

masscan -p0-65535 $TARGET  --rate=1000 --open-only -oG $PWD/recon/ports_$TARGET.log

PORTS=$(cat $PWD/recon/ports_$TARGET.log | grep -v '^#' | cut -d " " -f 5 | grep -oE '^[0-9]+' | tr '\n' ',' | sed s/,$//) 


nmap -p$PORTS -A -Pn -sS -sV -sC -vv --min-rate=1000 -oN $PWD/recon/services_$TARGET.log $TARGET
