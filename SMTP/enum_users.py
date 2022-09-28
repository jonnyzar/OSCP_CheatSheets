#!/usr/bin/python

import socket
import sys


def get_users(user_filename):
    user_file = open(user_filename,'r')
    users=user_file.readlines()
    user_file.close()

    return users



if len(sys.argv) !=3:
    print ("Usage: <file with host list> <file with usernames>")
    sys.exit(0)


#open hosts file

with open(sys.argv[1],'r') as hosts_file:
    hosts = hosts_file.readlines()

    for host in hosts:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2) 

            try:
                s.connect((host.strip("\n\r "),25))
            except OSError as msg:
                print('could not open socket for ' + host)
                print(msg)
                continue

            banner = s.recv(1024)
                
            #open file with users
            users = get_users(sys.argv[2])

            #iterate through users
            for user in users:
                s.send(b'VRFY ' + bytearray(user,encoding='UTF-8') + b' \\r\\n\\')
                print(s.recv(1024))

            


