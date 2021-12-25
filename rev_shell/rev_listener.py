#!/usr/bin/env python
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
#
#  AUTHOR IS NOT RESPONSIBLE FOR ANY CONSEQUENCES CAUSED BY USE
#  OF THIS PROGRAM
"""
listener
"""

import socket        



def main():
    LADDR = '0.0.0.0'
    LPORT = 8890
    LHOST = (LADDR, LPORT)
    
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind(LHOST)
    s.listen(5)


    try:
        client, addr = s.accept()      
        
        while True:                    
            cmd = str(input('> '))
            client.send(cmd.encode())
            if cmd == 'exit':
                break
            fb = client.recv(1024).decode()
            print(fb)
    except KeyboardInterrupt:
        client.close()
        s.close()  
    finally: 
        client.close()
        s.close()      
 
     
    return 0

if __name__ == '__main__':
    main()

