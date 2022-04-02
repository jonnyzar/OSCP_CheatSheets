#!/bin/bash

PORTS=$(nmap -p- -vv --min-rate=1000 $1 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

echo $PORTS > $PWD/ports_$TARGET.log
