* The bind/reverse shell is not always fully interactive
* Python trick can be used to make it such
* Attention> try either python or python3 

<code> python -c 'import pty; pty.spawn("/bin/bash")' </code><br>
<code> python3 -c 'import pty;pty.spawn("/bin/bash")' </code>
