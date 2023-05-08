# How to crack Linux passwords


## john way

copy  /etc/passwd and /etc/shadow

then unshadow 

`unshadow passwd shadow passwds.txt`

launch john

`john --sordlist=/usr/share/rock.txt passwds.txt`