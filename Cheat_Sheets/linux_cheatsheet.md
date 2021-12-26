# Shadow file generation and alteration

Generate shadow files ([stackoverflow](https://unix.stackexchange.com/questions/81240/manually-generate-password-for-etc-shadow)):

<code> openssl passwd -6 -salt xyz  yourpass </code>

Note: passing -1 will generate an MD5 password, -5 a SHA256 and -6 SHA512 (recommended)

To understand which hash you need, check what is $X$:

username:$X$salt$pass....

* $1$ is MD5
* $2a$ is Blowfish
* $2y$ is Blowfish
* $5$ is SHA-256
* $6$ is SHA-512

AND dont forget salt!

# Process Management

* Supress messages from background process

<code>  bg_proc > /dev/null 2>&1 &   </code>


