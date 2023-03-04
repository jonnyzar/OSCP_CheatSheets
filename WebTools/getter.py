# getter is a tool for arbitrary GET requests
#
# Copyright (C) 2023 https://github.com/jonnyzar. All rights reserved.
#
# This software is provided under MIT LICENCE.
#
#
# Author:
#   Yan Zaripov (@jonnyzar)
#



import requests
import re
#import base64
import sys

#import requests.utils.quote as url_enc

URL = sys.argv[1]
PAYLOAD_FILE = sys.argv[2]
#PASS_FILE = sys.argv[3]
#INIT_TOKEN = sys.argv[4]
#INIT_COOKIE = sys.argv[5]

def forge_get(url):

    session = requests.Session()

    resp = session.get(url)

    if resp.status_code == 404:
        print("[-] ", resp.status_code, ' ', resp.url)
    else:
        print("[+] ", resp.status_code, ' ', resp.url)

###########################################   MAIN   #############################################

def main():

#add asyncio

    with open(PAYLOAD_FILE,"r") as pf:

        for payload_raw in pf.readlines():
            payload = payload_raw.rstrip("\n")

            forge_get(URL + payload)
            
    return 0

######################################################################################

if __name__ == "__main__":
    main()
