#!/usr/bin/python
import socket
import sys

if len(sys.argv) != 3:
    print ("Usage: vrfy.py <usernames_file> <ip>")
    sys.exit(0)

user_file = open(sys.argv[1],'r')

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#timeout
#s.settimeout(2)
# Connect to the Server
connect = s.connect((sys.argv[2],25))
# Receive the banner
banner = s.recv(1024)
print (banner)

lines = user_file.readlines()

for line in lines:    

    # VRFY a user
    s.send(bytes('VRFY ' + line.strip() + '\r\n', 'ascii'))
    result = s.recv(1024)
    print (result)
    # Close the

user_file.close()