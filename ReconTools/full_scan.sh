#!/bin/bash

TARGET=$1
PORTS=$(nmap -p- -vv -Pn --min-rate=1000 $TARGET | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 

echo "Port scan results"
echo $PORTS
echo $PORTS > $PWD/ports_$TARGET.log

nmap -p$PORTS -A -Pn -sV -sC -vv --min-rate=1000 -oN $PWD/result_$TARGET.log $TARGET
