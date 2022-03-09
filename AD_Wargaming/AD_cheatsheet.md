# Intro: Please Read!
* Sources for this cheat sheet: [zer1t0](https://zer1t0.gitlab.io/posts/attacking_ad/)
* If not stated otherwise, all commands are to be executed in Powershell
* 

# Reconaissance

Understanding the target AD environment is key to further exploitation.

* **AD infos**:  

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

## Domain Controller Discovery

* **DNS query**: `nslookup -q=srv _ldap._tcp.dc._msdcs.contoso.local`
* **Using nltest**: `nltest /dclist:domain.local`
