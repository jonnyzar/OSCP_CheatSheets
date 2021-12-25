#!/bin/bash

TARGET=$1
PORTS=$(cat $2)

nmap -p$PORTS -sV -sC -vv --min-rate=1000 -oN $PWD/result_$TARGET.log $TARGET
