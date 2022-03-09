# Intro: Please Read!
* Sources for this cheat sheet: [zer1t0](https://zer1t0.gitlab.io/posts/attacking_ad/)
* If not stated otherwise, all commands are to be executed in Powershell
* 

# Reconaissance

Understanding the target AD environment is key to further exploitation.
* AD infos:  

Get Domain infos: <code> Get-ADDomain </code>

Get Forest infos: <code> Get-ADForest</code>

Check trusted domains: <code> nltest /domain_trusts </code>

* Get current active domain for the user:

<code> (Get-WmiObject Win32_ComputerSystem).Domain </code>

* Domain can be also identified using [SID](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers):

<code> Get-ADDomain | select DNSRoot, NetBIOSName, DomainSID </code>
