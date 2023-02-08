# Start local Mail server

To start SMTP server on default port 25, you need sudo privileges, because 25 is reserved port in <0, 1024> range. Running following command will start SMTP process under nobody user.

sudo python -m smtpd -c DebuggingServer localhost:25

## enumerate users

* user script `../eMail/vrfy.py`

## POP3 access

```bash
nc 10.11.1.72 -nvC 110 
(UNKNOWN) [10.11.1.72] 110 (pop3) open
+OK beta POP3 server (JAMES POP3 Server 2.3.2) ready 
USER tester
+OK
PASS password1111
+OK Welcome tester
LIST
+OK 2 1807
1 7434
2 11221
.
RETR 1 # to get the fist mail
```