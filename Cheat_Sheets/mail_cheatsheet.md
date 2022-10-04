# Start local Mail server

To start SMTP server on default port 25, you need sudo privileges, because 25 is reserved port in <0, 1024> range. Running following command will start SMTP process under nobody user.

sudo python -m smtpd -c DebuggingServer localhost:25

# enumerate users

* user script `../eMail/vrfy.py`

