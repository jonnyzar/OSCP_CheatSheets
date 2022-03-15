* The bind/reverse shell is not always fully interactive
* Python trick can be used to make it such

<code> python -c 'import pty; pty.spawn("/bin/bash")' </code><br>
<code> python3 -c 'import pty;pty.spawn("/bin/bash")' </code>

* Using script
'script /dev/null -c bash'
