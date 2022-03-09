== If not stated otherwise, all command are executed in Powershell .==

# Reconaissance

Understanding the target AD environment is key to further exploitation.
* AD Domain infos:  <code> Get-ADDomain </code>
* Get current active domain for the user
** <code> (Get-WmiObject Win32_ComputerSystem).Domain </code>
* Domain can be also identified using [SID](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers)
** <code> Get-ADDomain | select DNSRoot, NetBIOSName, DomainSID </code>
