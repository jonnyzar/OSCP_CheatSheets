#!/usr/bin/env python3

import smtplib

from_addr = "someone@somemail.com"
to_addr = "xy@gmail.com"

msg = "some msg"

server = smtplib.SMTP('localhost')
server.set_debuglevel(1)
server.sendmail(from_addr,to_addr,msg)
server.quit()
