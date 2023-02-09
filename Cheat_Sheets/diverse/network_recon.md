# Network Recon

Not a replacement for official docs but a rapid reference

## Find online hosts

### Ping scan

#### nmap

```bash

nmap -sn -T4 -n -vvv -oA ping_hosts -iL range.txt
grep Up ping_hosts.gnmap | cut -d ' ' -f 2 > hosts.txt

#get ips as a result
```

Wont work if ICMP ping requests are blocked.

### SYN-scan