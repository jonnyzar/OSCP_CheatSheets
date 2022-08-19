# Intro

This is a cheat sheet for exploitation of OWASP Top 10.

It is the followed by more refined attacks. 

# OWASP Top 10

## Command Injection

If Backend has an insecure function that passes user input directly to shell, it can be exploited.

Try injecting the following:
```
# Linux

whoami
id
ifconfig/ip addr
uname -a
ps -ef


# Windows

whoami
ver
ipconfig
tasklist
netstat -an
```

For bypassing WAF and more advanced injections your best friend is as always: Payload all the thins.

## Broken Authentication

If an attacker is able to find flaws in an authentication mechanism, they would then successfully gain access to other users’ accounts.

1. Try manipulating session cookies to see if they are predictable
2. Manipulate GET requests containing IDs or usernames
3. Register as user with similar name: add space " admin" or numbers

## Sensitive Data Exposure

1. Search web source code
2. Dirbust for hidden files
3. Dork with Google or Github
4. Try downloading db files with command injection

# Advanced Web Attacks

## API

## JWT