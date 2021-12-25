#! /bin/bash

for ip in  $(seq $1 $2);
do 
host 10.211.55.$ip | grep -v "not found";
done
