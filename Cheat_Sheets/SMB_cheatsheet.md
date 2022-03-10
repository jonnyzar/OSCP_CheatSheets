# Intro
Following Ressources contain information about SMB protocol and its vulnerabilities:
* MS info: https://docs.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview
* Pentesting SMB: https://book.hacktricks.xyz/pentesting/pentesting-smb

# Reconnaisance

## **CrackMapExec**: used for basic SMB enumeration

* Null Session:
```
crackmapexec smb ip_addr -u '' -p ''
```
