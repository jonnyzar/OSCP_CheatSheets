# SNP Pentesting Cheatsheet

Or `security not my problem`?

https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp

https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp/snmp-rce

### What is it

* SNMP contains Management Information Base (MIB) 
* It is realated to network management
* This tree contains endpoints with values that can be accessed and probed
* google for stuff like `1.3.6.1.2.1.25.1.6.0	System Processes`

### Manual

* scan UDP port 161

`sudo nmap -sU --open -p 161 10.10.1.1-254 -oG snmp.log`

### Onesixtyone

`onesixtyone -c community_list -i ip_list`

where 

```bash
cat community_list 

public
private
other
```

```bash
cat ip_list 

10.11.2.34
10.34.21.1
```