# Pentesting DNS

## Discovery

* DNS runs on TCP and UDP ports 53

```bash

nmap -p53 --open -sC 123.132.34.23

```

* Banner grabbing

`dig version.bind CHAOS TXT @DNS`

* Return all info

`dig any victim.com @<DNS_IP>`

## Lookup

* direct

`dig google.com`

* reverse

`dig -x 192.168.0.2 @<DNS_IP>`

### nslookup

```powershell

nslookup -type=TXT info.domain.com 192.168.xxx.xxx

```

## Records

* DNS server may have following records

```text

NS - Nameserver records 
A - contains the IP address of hostname 
MX - Mail Exchange records with mail
PTR - Pointer Records are used in reverse lookup zones and are used to find the records associated with an IP address.
CNAME - Canonical Name Records are used to create aliases for other host records like Subdomains
TXT - Text records can contain any arbitrary data like SPF records

```

* Get txt record

`dig -t txt dns.google.com`

## DNS Zone Transfer

This misconfiguration may reveal hiffen domains and hosts behind firewalls and other defences.

```bash
# taken from https://book.hacktricks.xyz/

dig axfr @<DNS_IP> #Try zone transfer without domain
dig axfr @<DNS_IP> <DOMAIN> #Try zone transfer guessing the domain

```

## Using nslookup

Alternative way especially for windows

```bash
nslookup
> SERVER <IP_DNS> #Select dns server
> 127.0.0.1 #Reverse lookup of 127.0.0.1, maybe...
> <IP_MACHINE> #Reverse lookup of a machine, maybe...
```

## Easy way

`dnsrecon -d target.com -t axfr`