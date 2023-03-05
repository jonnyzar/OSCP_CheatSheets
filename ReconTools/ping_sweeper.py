#write a short script to perform a ping sweep of a target IP address range

'''
Do not use non-standard libraries

You DO NOT need to do any error checking 
'''

from pythonping import ping
from sys import argv


def main():

    #require thpython3 -m pip install --upgrade pip setuptools wheelree arguments:
    # the first three octets of the IP address
    # the starting value of the last octet
    # the ending value of the last octet 

    if len(argv) < 4:
        print("Usage: ping_sweeper.py 3_octets last_octet_start last_octet_end")
        exit(1)
    
    #print(str(argv))

    #print the IP addresses of any valid responses (one IP address per line)

    ip_base = argv[1] + '.'
    oct_first = int(argv[2])
    oct_last = int(argv[3])

    for i in range(oct_first,oct_last+1):
        ip = ip_base + str(i)
        response = ping(ip, count=1)
        for r in response:
            if r.success:
                print(ip)



if __name__=="__main__":
    main()