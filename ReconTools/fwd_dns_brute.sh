#! /bin/bash

for ip in  $(cat host_list.txt);
do 
host $ip.$1;
done
